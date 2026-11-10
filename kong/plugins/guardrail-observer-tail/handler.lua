-- guardrail-observer-tail: second, tiny capture point that runs AFTER the AI
-- proxy and output guardrails in header_filter/body_filter (priority 5), so
-- the evaluator can compare the pre-transform snapshot (observer, 790) with the
-- last plugin-visible snapshot. It has no `log` handler on purpose: values are
-- set from body_filter so they are serialized by any logger regardless of
-- logger priority. Still NOT proof of client-visible bytes; the runner is.

local sha256 = require "resty.sha256"
local to_hex = require("resty.string").to_hex

local Tail = { PRIORITY = 5, VERSION = "0.1.0" }

local function now_ms()
  ngx.update_time()
  return math.floor(ngx.now() * 1000)
end

function Tail:header_filter(conf)
  local gro = ngx.ctx.gro
  local t = now_ms()
  ngx.ctx.gro_tail = {
    status = kong.response.get_status(),
    content_type = kong.response.get_header("content-type"),
    content_length = tonumber(kong.response.get_header("content-length")),
    headers_at_ms = t,
    chunks = 0, bytes = 0, timeline = {}, truncated = false,
    started_at_ms = gro and gro.started_at_ms or t,
    _hash = sha256:new(),
    _parts = conf.capture_body_mode == "bounded" and {} or nil,
    _captured = 0,
  }
end

function Tail:body_filter(conf)
  local s = ngx.ctx.gro_tail
  if not s then return end
  local chunk, eof = ngx.arg[1], ngx.arg[2]
  local t = now_ms()
  if chunk and #chunk > 0 then
    s.chunks = s.chunks + 1
    s.bytes = s.bytes + #chunk
    if s.chunks == 1 then s.first_chunk_at_ms = t end
    if #s.timeline < conf.max_chunks_recorded then
      s.timeline[#s.timeline + 1] = { t = t - s.started_at_ms, n = #chunk }
    else
      s.truncated = true
    end
    if conf.capture_body_mode ~= "none" then s._hash:update(chunk) end
    if s._parts and s._captured < conf.max_capture_bytes then
      local room = conf.max_capture_bytes - s._captured
      s._parts[#s._parts + 1] = chunk:sub(1, room)
      s._captured = s._captured + math.min(room, #chunk)
    end
  end
  if eof then
    s.eof_at_ms = t
    if conf.capture_body_mode ~= "none" and s.chunks > 0 then s.sha256 = to_hex(s._hash:final()) end
    if s._parts then
      local prefix = table.concat(s._parts)
      local enc = kong.response.get_header("content-encoding")
      local ct = (s.content_type or ""):lower()
      local texty = (not enc or enc == "identity") and (ct:find("json", 1, true) or ct:find("text/", 1, true) or ct:find("event-stream", 1, true))
      if texty and ngx.re.find(prefix, [[^(?:[\x09\x0A\x0D\x20-\x7E]|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}|\xED[\x80-\x9F][\x80-\xBF]|\xF0[\x90-\xBF][\x80-\xBF]{2}|[\xF1-\xF3][\x80-\xBF]{3}|\xF4[\x80-\x8F][\x80-\xBF]{2})*$]], "jo") then
        s.body_prefix = prefix
      else
        s.body_prefix_b64 = ngx.encode_base64(prefix)
      end
      s.content_encoding = enc
      s.body_truncated = s.bytes > conf.max_capture_bytes
    end
    s.observed_at = "plugin-priority-5 (after ai-proxy and output guardrails; last plugin-visible snapshot)"
    s._hash, s._parts, s._captured = nil, nil, nil
    kong.log.set_serialize_value(conf.log_namespace .. ".tail", s)
  end
end

return Tail
