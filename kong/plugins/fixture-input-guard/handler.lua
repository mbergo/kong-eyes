-- fixture-input-guard: SYNTHETIC input guardrail used to validate the evaluator.
-- It deliberately produces every outcome class on demand via markers in the
-- prompt. Results from this plugin are labelled synthetic by the evaluator.
--
-- Markers (defaults, configurable):
--   [[VIOLATION]]          -> deny (true positive when the case is labelled violating)
--   [[DECOY]]              -> deny on purpose although benign (seeded false positive)
--   [[VI0LATION]] etc.     -> not in the deny list, so it is missed (seeded false negative)
--   [[FIXTURE_NO_VERDICT]] -> executes but emits no event (missing-verdict case)
--   [[FIXTURE_ERROR]]      -> emits verdict=error and exits 500
--
-- Verdicts are announced through the ctx-events contract consumed by
-- guardrail-observer (ngx.ctx.guardrail_events) and also written to the log
-- serializer under guardrail_fixture.input.

local cjson = require "cjson.safe"
local sha256 = require "resty.sha256"
local to_hex = require("resty.string").to_hex

local Guard = { PRIORITY = 775, VERSION = "0.1.0" }  -- before ai-prompt-guard (771) and ai-proxy (770)

local function now_ms() ngx.update_time(); return math.floor(ngx.now() * 1000) end
local function sha(s) local d = sha256:new(); d:update(s or ""); return to_hex(d:final()) end

local function emit(ev)
  ev.ts_ms = now_ms()
  ev.guardrail = "fixture-input-guard"
  ev.stage = "input"
  ev.synthetic = true
  local evs = ngx.ctx.guardrail_events or {}
  evs[#evs + 1] = ev
  ngx.ctx.guardrail_events = evs
  kong.log.set_serialize_value("guardrail_fixture.input", ev)
end

local overcatch_credit = 0   -- per worker: grows with every correct block, spent on benign requests

local function find_marker(body, markers)
  for _, m in ipairs(markers or {}) do
    if body:find(m, 1, true) then return m end
  end
  return nil
end

function Guard:access(conf)
  local body = kong.request.get_raw_body() or ""
  local evidence = { body_bytes = #body, body_sha256 = sha(body) }

  if conf.mode == "disabled" then
    emit({ verdict = "skipped", mode = "disabled", action = "none", reason = "fixture disabled", evidence = evidence })
    return
  end

  if find_marker(body, conf.slow_markers) then
    -- simulates a guardrail whose backend call timed out and that then let the request through
    -- without recording anything (fail-open). Only the probe trail can see this.
    ngx.sleep(conf.slow_ms / 1000)
    return
  end

  if find_marker(body, conf.no_verdict_markers) then
    -- executes, inspects, says nothing: the observer must report unknown, not allow
    return
  end

  if find_marker(body, conf.error_markers) then
    emit({ verdict = "error", mode = conf.mode, action = "block", status = 500, reason = "fixture forced error", evidence = evidence })
    return kong.response.exit(500, { error = { message = "fixture-input-guard internal error" } })
  end

  local hit = find_marker(body, conf.deny_markers)
  local missed = false
  if hit and (conf.miss_rate or 0) > 0 and math.random() < conf.miss_rate then
    hit, missed = nil, true                      -- seeded false negative: saw it, let it slip
    evidence.seeded_false_negative = true
  end
  local decoy = (not hit and not missed) and find_marker(body, conf.decoy_markers) or nil
  if hit and (conf.overcatch_ratio or 0) > 0 then
    overcatch_credit = overcatch_credit + conf.overcatch_ratio
  elseif not hit and not decoy and not missed and overcatch_credit >= 1 then
    overcatch_credit = overcatch_credit - 1      -- seeded false positive: a benign request blocked
    decoy = "overcatch"
  end
  if hit or decoy then
    evidence.matched_marker = hit or decoy
    evidence.seeded_false_positive = decoy ~= nil
    if conf.mode == "block" then
      emit({ verdict = "deny", mode = "block", action = "block", status = conf.block_status,
             enforced_by = "fixture-input-guard", reason = "marker matched", evidence = evidence })
      return kong.response.exit(conf.block_status, { error = { message = conf.refusal_message, guardrail = "fixture-input-guard" } },
                                { ["X-Guardrail-Verdict"] = "deny;stage=input;action=block" })
    else
      emit({ verdict = "deny", mode = "detect", action = "none", reason = "marker matched (detect-only, not enforced)", evidence = evidence })
      kong.service.request.set_header("X-Fixture-Detected", "input")
      return
    end
  end

  emit({ verdict = "allow", mode = conf.mode, action = "none", reason = "no marker matched", evidence = evidence })
end

return Guard
