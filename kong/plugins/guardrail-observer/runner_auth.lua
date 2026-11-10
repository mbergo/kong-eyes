-- Verifies test-runner metadata carried in request headers.
-- Format of the metadata header: "run_id;case_id;trial;sent_at_ms"
-- Signature header: lowercase hex HMAC-SHA256(secret, metadata_value)
--
-- Nothing here is ever trusted by default: the result carries `trusted` and a
-- `reason`, and the evaluator only joins labels on trusted metadata.

local hmac_ok, openssl_hmac = pcall(require, "resty.openssl.hmac")
local to_hex = require("resty.string").to_hex

local _M = {}

local function constant_time_eq(a, b)
  if #a ~= #b then return false end
  local r = 0
  for i = 1, #a do
    r = bit.bor(r, bit.bxor(a:byte(i), b:byte(i)))
  end
  return r == 0
end

local function hmac_hex(secret, msg)
  if not hmac_ok then
    return nil, "resty.openssl.hmac unavailable"
  end
  local h, err = openssl_hmac.new(secret, "sha256")
  if not h then return nil, err end
  local ok, uerr = h:update(msg)
  if not ok then return nil, uerr end
  local digest, ferr = h:final()
  if not digest then return nil, ferr end
  return to_hex(digest)
end

_M.hmac_hex = hmac_hex

-- @return table { present=bool, trusted=bool, reason=string, run_id, case_id, trial, sent_at_ms, raw }
function _M.extract(conf, now_ms)
  local raw = kong.request.get_header(conf.runner_header)
  if not raw or raw == "" then
    return { present = false, trusted = false, reason = "no_runner_header" }
  end

  local res = { present = true, trusted = false, raw = raw }

  local run_id, case_id, trial, sent_at = raw:match("^([^;]+);([^;]+);([^;]+);(%d+)$")
  if not run_id then
    res.reason = "malformed_runner_header"
    return res
  end
  res.run_id, res.case_id = run_id, case_id
  res.trial = tonumber(trial) or trial
  res.sent_at_ms = tonumber(sent_at)

  if not conf.runner_shared_secret or conf.runner_shared_secret == "" then
    res.reason = "no_shared_secret_configured"
    return res
  end

  local sig = kong.request.get_header(conf.runner_signature_header)
  if not sig or sig == "" then
    res.reason = "missing_signature"
    return res
  end

  local expected, err = hmac_hex(conf.runner_shared_secret, raw)
  if not expected then
    res.reason = "hmac_error:" .. tostring(err)
    return res
  end

  if not constant_time_eq(expected, sig:lower()) then
    res.reason = "bad_signature"
    return res
  end

  if now_ms and res.sent_at_ms and math.abs(now_ms - res.sent_at_ms) > conf.runner_max_skew_ms then
    res.reason = "clock_skew_exceeded"
    res.skew_ms = now_ms - res.sent_at_ms
    return res
  end

  res.trusted = true
  res.reason = "signature_ok"
  if now_ms and res.sent_at_ms then
    res.skew_ms = now_ms - res.sent_at_ms  -- gateway_clock - runner_clock (includes network latency)
  end
  return res
end

return _M
