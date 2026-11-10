-- fixture-output-guard: SYNTHETIC output guardrail used to validate the evaluator.
-- Runs after ai-proxy (priority 760 < 770) so it sees the normalized response.
--
--   non-streaming: inspects the full body; block mode replaces it with a refusal.
--   streaming:     inspects each chunk; on detection it emits verdict=deny and,
--                  in block mode, aborts the stream `enforce_delay_chunks` chunks
--                  later. delay=0 => the offending chunk never leaves (correct block);
--                  delay>0 => violating bytes already left (enforcement failure).
--   detect mode:   emits the verdict, changes nothing.
--
-- Every event carries pre-enforcement evidence (hash/bytes of what was seen,
-- which chunk, how much leaked) so the evaluator never has to judge the
-- output decision from the replacement refusal alone.

local cjson = require "cjson.safe"
local gzip = require "kong.tools.gzip"
local sha256 = require "resty.sha256"
local to_hex = require("resty.string").to_hex

local Guard = { PRIORITY = 760, VERSION = "0.1.0" }

local function now_ms() ngx.update_time(); return math.floor(ngx.now() * 1000) end
local function sha(s) local d = sha256:new(); d:update(s or ""); return to_hex(d:final()) end

local function emit(ev)
  ev.ts_ms = now_ms()
  ev.guardrail = "fixture-output-guard"
  ev.stage = "output"
  ev.synthetic = true
  local evs = ngx.ctx.guardrail_events or {}
  evs[#evs + 1] = ev
  ngx.ctx.guardrail_events = evs
  kong.log.set_serialize_value("guardrail_fixture.output", ev)
end

local function find_marker(body, markers)
  for _, m in ipairs(markers or {}) do
    if body:find(m, 1, true) then return m end
  end
end

local function is_stream()
  local ct = kong.response.get_header("content-type") or ""
  return ct:find("text/event-stream", 1, true) ~= nil
end

local function refusal_json(conf)
  return cjson.encode({
    id = "fixture-refusal", object = "chat.completion",
    choices = { { index = 0, finish_reason = "content_filter",
                  message = { role = "assistant", content = conf.refusal_message } } },
    guardrail = "fixture-output-guard",
  })
end

local function refusal_sse(conf)
  local ev = cjson.encode({
    id = "fixture-refusal", object = "chat.completion.chunk",
    choices = { { index = 0, finish_reason = "content_filter",
                  delta = { role = "assistant", content = conf.refusal_message } } },
    guardrail = "fixture-output-guard",
  })
  return "data: " .. ev .. "\n\ndata: [DONE]\n\n"
end

function Guard:header_filter(conf)
  if conf.mode == "disabled" then return end
  local st = { stream = is_stream(), chunks = 0, bytes = 0, buf = {}, buf_bytes = 0,
               gzip = (kong.response.get_header("content-encoding") or ""):lower() == "gzip" }
  ngx.ctx.fixture_output = st
  if conf.mode == "block" and not st.stream then
    kong.response.clear_header("Content-Length")  -- body may be replaced
    if st.gzip then
      -- ai-proxy (priority 770) already decided to gzip because the client accepts it; this guard runs
      -- after it, so it must inflate to inspect and will emit plaintext. A guard that skips this step
      -- inspects compressed bytes and silently allows everything (see edge-gzip-output).
      kong.response.clear_header("Content-Encoding")
    end
  end
  kong.response.set_header("X-Fixture-Output-Guard", conf.mode)
end

function Guard:body_filter(conf)
  local st = ngx.ctx.fixture_output
  if not st then
    if conf.mode == "disabled" and not ngx.ctx.fixture_output_skipped then
      ngx.ctx.fixture_output_skipped = true
      emit({ verdict = "skipped", mode = "disabled", action = "none", reason = "fixture disabled" })
    end
    return
  end
  local chunk, eof = ngx.arg[1], ngx.arg[2]
  if chunk and #chunk > 0 then
    st.chunks = st.chunks + 1
    st.bytes = st.bytes + #chunk
  end

  ------------------------------------------------------------------ streaming
  if st.stream then
    if st.aborted then
      ngx.arg[1] = ""  -- stream already terminated by us
      return
    end
    if chunk and #chunk > 0 then
      if not st.detected_chunk then
        local m = find_marker(chunk, conf.deny_markers)
        if m then
          st.detected_chunk = st.chunks
          st.marker = m
          st.leaked_bytes_before = st.bytes - #chunk
          if conf.mode == "detect" then
            emit({ verdict = "deny", mode = "detect", action = "none", reason = "marker in stream (detect-only)",
                   evidence = { matched_marker = m, detected_chunk = st.chunks, stream = true } })
          end
        end
      end
      if st.detected_chunk and conf.mode == "block" then
        local enforce_at = st.detected_chunk + conf.enforce_delay_chunks
        if st.chunks >= enforce_at then
          -- leaked = every chunk from the detected one up to (not including) this one
          local leaked_chunks = st.chunks - st.detected_chunk
          emit({ verdict = "deny", mode = "block", action = "abort_stream", enforced_by = "fixture-output-guard",
                 reason = leaked_chunks == 0 and "marker chunk replaced before delivery"
                                             or ("stream aborted " .. leaked_chunks .. " chunk(s) after detection"),
                 evidence = { matched_marker = st.marker, detected_chunk = st.detected_chunk, enforced_at_chunk = st.chunks,
                              leaked_chunks = leaked_chunks, stream = true,
                              violating_chunk_sha256 = leaked_chunks == 0 and sha(chunk) or nil } })
          ngx.arg[1] = refusal_sse(conf)
          ngx.arg[2] = true
          st.aborted = true
          return
        end
      end
    end
    if eof and not st.detected_chunk then
      emit({ verdict = "allow", mode = conf.mode, action = "none", reason = "no marker in stream",
             evidence = { chunks = st.chunks, bytes = st.bytes, stream = true } })
    elseif eof and st.detected_chunk and conf.mode == "block" and not st.aborted then
      -- stream ended before the delayed enforcement point: full leak, never enforced
      emit({ verdict = "deny", mode = "block", action = "none", enforced_by = nil,
             reason = "detected but stream finished before enforcement point",
             evidence = { matched_marker = st.marker, detected_chunk = st.detected_chunk, leaked_chunks = st.chunks - st.detected_chunk + 1, stream = true } })
    end
    return
  end

  -------------------------------------------------------------- non-streaming
  if chunk and #chunk > 0 then
    st.buf[#st.buf + 1] = chunk
    st.buf_bytes = st.buf_bytes + #chunk
  end
  if conf.mode == "block" then
    ngx.arg[1] = ""  -- hold everything until eof
  end
  if not eof then return end

  local body = table.concat(st.buf)
  local evidence = { body_bytes = st.bytes, body_sha256 = sha(body), content_encoding = st.gzip and "gzip" or nil }
  if st.gzip then
    local inflated, err = gzip.inflate_gzip(body)
    if inflated then body = inflated; evidence.inflated_bytes = #inflated else evidence.inflate_error = tostring(err) end
  end
  local inspect = body:sub(1, conf.max_inspect_bytes)
  evidence.inspected_bytes, evidence.truncated = #inspect, #body > #inspect
  local m = find_marker(inspect, conf.deny_markers)
  if m then
    evidence.matched_marker = m
    if conf.mode == "block" then
      emit({ verdict = "deny", mode = "block", action = "block", enforced_by = "fixture-output-guard",
             status = kong.response.get_status(), reason = "marker in response body, body replaced", evidence = evidence })
      ngx.arg[1] = refusal_json(conf)
    else
      emit({ verdict = "deny", mode = "detect", action = "none", reason = "marker in response body (detect-only)", evidence = evidence })
    end
  else
    emit({ verdict = "allow", mode = conf.mode, action = "none", reason = "no marker in response body", evidence = evidence })
    if conf.mode == "block" then ngx.arg[1] = body end
  end
end

return Guard
