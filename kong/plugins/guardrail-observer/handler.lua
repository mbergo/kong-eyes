-- guardrail-observer: evidence collector for AI guardrail evaluation.
--
-- Phases:
--   init_worker   probe version; optionally wrap kong.response.exit for exit attribution
--   access        correlation, trusted runner metadata, bounded request metadata (runs BEFORE the guardrails)
--   header_filter response status/source/headers, start of stream timeline
--   body_filter   per-chunk timeline + running hash, never touches ngx.arg
--   log           phase trace, adapters -> guardrail verdicts, kong.log.set_serialize_value(namespace, evidence)
--
-- No `response` handler on purpose: it would force buffered proxying and change streaming semantics.

local cjson = require "cjson.safe"
local sha256 = require "resty.sha256"
local to_hex = require("resty.string").to_hex
local trace = require "kong.plugins.guardrail-observer.trace"
local adapters = require "kong.plugins.guardrail-observer.adapters"
local runner_auth = require "kong.plugins.guardrail-observer.runner_auth"
local trail = require "kong.plugins.guardrail-observer.trail"

local ngx = ngx
local kong = kong

local Observer = {
  PRIORITY = 790,   -- > ai-request-transformer 777 > ai-prompt-guard 771 > ai-proxy 770 ; < auth plugins (>=1000)
  VERSION = "0.2.0",
}

local SCHEMA_VERSION = "1.1"

-- JSON-safe bounded capture: text stays as-is (cjson escapes it), anything else is base64.
local function is_texty(content_type, content_encoding)
  if content_encoding and content_encoding ~= "identity" then return false end
  local ct = (content_type or ""):lower()
  return ct:find("json", 1, true) or ct:find("text/", 1, true) or ct:find("xml", 1, true)
     or ct:find("event-stream", 1, true) or ct:find("x-www-form-urlencoded", 1, true)
end

local function safe_prefix(s, texty)
  if texty and ngx.re.find(s, [[^(?:[\x09\x0A\x0D\x20-\x7E]|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}|\xED[\x80-\x9F][\x80-\xBF]|\xF0[\x90-\xBF][\x80-\xBF]{2}|[\xF1-\xF3][\x80-\xBF]{3}|\xF4[\x80-\x8F][\x80-\xBF]{2})*$]], "jo") then
    return s, nil
  end
  return nil, ngx.encode_base64(s)
end

local function now_ms()
  ngx.update_time()
  return math.floor(ngx.now() * 1000)
end

local internal_supported, internal_reason = false, "not probed"

----------------------------------------------------------------------------
-- init_worker
----------------------------------------------------------------------------
function Observer:init_worker()
  internal_supported, internal_reason = trace.internal_ctx_supported()
  kong.log.notice("guardrail-observer ", Observer.VERSION, " on Kong ", tostring(trace.kong_version()),
                  "; internal-ctx adapters supported=", tostring(internal_supported), " (", internal_reason, ")")
  -- NOTE: no global wrapping of kong.response.exit. Verified on 3.10.0.19 that
  -- wrapping it (even as a pure pass-through) breaks the Admin API's content-phase
  -- exit handling. Exit attribution uses Kong's request-debug trace instead
  -- (X-Kong-Request-Debug: * + token, read from ngx.ctx.req_trace_ctx in log).
end

----------------------------------------------------------------------------
-- access
----------------------------------------------------------------------------
local function summarize_request_body(conf, gro)
  local req = gro.request
  local body = kong.request.get_raw_body()
  if body == nil then
    -- body larger than client_body_buffer_size: nginx spilled it to a temp file
    req.body_bytes = tonumber(kong.request.get_header("content-length"))
    req.body_in_file = true
    gro.gaps[#gro.gaps + 1] = "request_body_in_file"
    return
  end
  req.body_bytes = #body
  if conf.capture_body_mode ~= "none" then
    req.body_sha256 = trace.sha256_hex(body)
  end
  if conf.capture_body_mode == "bounded" then
    req.body_prefix, req.body_prefix_b64 = safe_prefix(body:sub(1, conf.max_capture_bytes), is_texty(req.content_type, kong.request.get_header("content-encoding")))
    req.body_truncated = #body > conf.max_capture_bytes
  end
  local ct = req.content_type or ""
  if ct:find("application/json", 1, true) and #body <= 1048576 then
    local t = cjson.decode(body)
    if type(t) == "table" then
      req.json_valid = true
      req.stream_requested = t.stream == true
      req.model = type(t.model) == "string" and t.model or nil
      if type(t.messages) == "table" then
        req.message_count = #t.messages
        local roles, chars = {}, 0
        for _, m in ipairs(t.messages) do
          if type(m) == "table" then
            roles[tostring(m.role)] = (roles[tostring(m.role)] or 0) + 1
            if type(m.content) == "string" then chars = chars + #m.content end
          end
        end
        req.roles = roles
        req.prompt_chars = chars
      elseif type(t.prompt) == "string" then
        req.prompt_chars = #t.prompt
      end
    else
      req.json_valid = false
    end
  end
end

function Observer:access(conf)
  local ctx = ngx.ctx
  local t0 = now_ms()
  local request_id = ngx.var.kong_request_id or ngx.var.request_id

  local route = kong.router.get_route()
  local service = kong.router.get_service()
  local consumer = kong.client.get_consumer()

  local gro = {
    schema_version = SCHEMA_VERSION,
    event_type = "kong_observation",
    observer_version = Observer.VERSION,
    kong_version = tostring(trace.kong_version()),
    environment = conf.environment,
    policy_version = conf.policy_version,
    request_id = request_id,
    started_at_ms = t0,
    phases = { access = { ts_ms = t0 } },
    gaps = {},
    route = route and { id = route.id, name = route.name, paths = route.paths } or nil,
    service = service and { id = service.id, name = service.name } or nil,
    consumer = consumer and { id = consumer.id, username = consumer.username } or nil,
    _route_id = route and route.id or nil,
    _service_id = service and service.id or nil,
    _consumer_id = consumer and consumer.id or nil,
  }
  ctx.gro = gro

  -- stable event id: request id + route is unique per Kong request; the
  -- evaluator deduplicates on it when http-log retries deliver twice.
  gro.event_id = trace.sha256_hex((request_id or "") .. "|" .. (route and route.id or "") .. "|" .. tostring(t0)):sub(1, 32)

  gro.runner = runner_auth.extract(conf, t0)

  if conf.capture_request_metadata then
    gro.request = {
      method = kong.request.get_method(),
      path = kong.request.get_path(),
      content_type = kong.request.get_header("content-type"),
      content_length = tonumber(kong.request.get_header("content-length")),
      accept = kong.request.get_header("accept"),
      accept_encoding = kong.request.get_header("accept-encoding"),
      scheme = kong.request.get_scheme(),
    }
    local ok, err = pcall(summarize_request_body, conf, gro)
    if not ok then
      gro.gaps[#gro.gaps + 1] = "request_summary_error:" .. tostring(err)
    end
  end

  -- probe trail: the head is position A. Middle probes (gro-probe-<priority>) append to this table;
  -- its presence is also what tells them the observer is active on this request.
  if conf.probe_trail then
    local e = { p = Observer.PRIORITY, t = t0 }
    if gro.request then
      e.n = gro.request.body_bytes
      e.h = gro.request.body_sha256 and gro.request.body_sha256:sub(1, 16) or nil
    end
    ctx.gro_trail = { e }
    if conf.trail_header then
      -- always overwrite: whatever the client sent under this name is discarded
      kong.service.request.set_header(conf.trail_header, ngx.md5("gro:" .. Observer.PRIORITY):sub(1, 4))
    end
  end
end

----------------------------------------------------------------------------
-- header_filter
----------------------------------------------------------------------------
function Observer:header_filter(conf)
  local gro = ngx.ctx.gro
  if not gro then return end
  local t = now_ms()
  gro.phases.header_filter = { ts_ms = t }
  gro.response = {
    status = kong.response.get_status(),
    source = kong.response.get_source(),          -- "service" | "exit" | "error"
    content_type = kong.response.get_header("content-type"),
    content_length = tonumber(kong.response.get_header("content-length")),
    transfer_encoding = kong.response.get_header("transfer-encoding"),
    content_encoding = kong.response.get_header("content-encoding"),
    headers_at_ms = t,
  }
  local vh = kong.response.get_header(conf.verdict_header)
  if vh then gro._verdict_header_value = vh end
  gro.stream = { chunks = 0, bytes = 0, timeline = {}, truncated = false }
  gro._hash = sha256:new()
  gro._captured = 0
  if conf.capture_body_mode == "bounded" then
    gro.stream.body_prefix_parts = {}
  end
end

----------------------------------------------------------------------------
-- body_filter (observe only)
----------------------------------------------------------------------------
function Observer:body_filter(conf)
  local gro = ngx.ctx.gro
  if not gro or not gro.stream then return end
  local chunk, eof = ngx.arg[1], ngx.arg[2]
  local s = gro.stream
  local t = now_ms()
  if chunk and #chunk > 0 then
    s.chunks = s.chunks + 1
    s.bytes = s.bytes + #chunk
    if s.chunks == 1 then s.first_chunk_at_ms = t end
    if #s.timeline < conf.max_chunks_recorded then
      s.timeline[#s.timeline + 1] = { t = t - gro.started_at_ms, n = #chunk }
    else
      s.truncated = true
    end
    if conf.capture_body_mode ~= "none" and gro._hash then
      gro._hash:update(chunk)
    end
    if s.body_prefix_parts and gro._captured < conf.max_capture_bytes then
      local room = conf.max_capture_bytes - gro._captured
      s.body_prefix_parts[#s.body_prefix_parts + 1] = chunk:sub(1, room)
      gro._captured = gro._captured + math.min(room, #chunk)
    end
  end
  if eof then
    s.eof_at_ms = t
    s.observed_at = "plugin-priority-790 (before ai-proxy/guardrail body filters; NOT the client-visible bytes)"
  end
end

----------------------------------------------------------------------------
-- log
----------------------------------------------------------------------------
function Observer:log(conf)
  local ctx = ngx.ctx
  local gro = ctx.gro
  if not gro then return end
  local t = now_ms()
  gro.phases.log = { ts_ms = t }
  gro.ended_at_ms = t
  gro.duration_ms = t - gro.started_at_ms

  -- response finalization (source may change after header_filter on errors)
  gro.response = gro.response or {}
  gro.response.status = kong.response.get_status()
  gro.response.source = kong.response.get_source()
  gro.response.proxied = ctx.KONG_PROXIED and true or false
  gro.response.upstream_status = ngx.var.upstream_status
  gro.response.kong_unexpected = ctx.KONG_UNEXPECTED and true or false

  if gro.stream then
    if gro._hash and conf.capture_body_mode ~= "none" and gro.stream.chunks > 0 then
      gro.stream.sha256 = to_hex(gro._hash:final())
    end
    if gro.stream.body_prefix_parts then
      gro.stream.body_prefix, gro.stream.body_prefix_b64 = safe_prefix(table.concat(gro.stream.body_prefix_parts),
        is_texty(gro.response.content_type, gro.response.content_encoding))
      gro.stream.body_prefix_parts = nil
      gro.stream.body_truncated = gro.stream.bytes > conf.max_capture_bytes
    end
    if gro.stream.chunks == 0 then
      gro.gaps[#gro.gaps + 1] = "no_body_chunks_observed"
    end
  else
    gro.gaps[#gro.gaps + 1] = "header_filter_not_run"
  end

  -- tail snapshot (guardrail-observer-tail stores it in ngx.ctx; our set_serialize_value below
  -- replaces the whole namespace, so merge it here instead of relying on its own write)
  if type(ctx.gro_tail) == "table" then
    local t = {}
    for k, v in pairs(ctx.gro_tail) do
      if type(k) == "string" and k:sub(1, 1) ~= "_" then t[k] = v end
    end
    gro.tail = t
  end

  -- phase trace (internal ctx)
  local configured
  if conf.configured_plugins then
    local ok, res = pcall(trace.configured_plugins, conf, gro._route_id, gro._service_id, gro._consumer_id)
    if ok then configured = res else gro.gaps[#gro.gaps + 1] = "configured_plugins_error:" .. tostring(res) end
  end
  if conf.phase_trace then
    local chain, err = trace.collected_chain(ctx)
    gro.plugin_chain = chain
    if not chain then gro.gaps[#gro.gaps + 1] = "plugin_chain:" .. tostring(err) end
    gro.ai = trace.ai_state(ctx)
    gro.attempts = trace.attempts(ctx)
    gro.phase_trace_provenance = { source = "kong-internal-ctx", supported = internal_supported, reason = internal_reason }
  end
  gro.configured_plugins = configured

  -- request-debug phase trace (present only when the request carried
  -- X-Kong-Request-Debug: * with a valid token; the runner does this)
  gro.request_debug = trace.request_debug(ctx)
  if gro.request_debug then
    gro.request_debug.supported = true
  elseif conf.attribute_exits then
    gro.gaps[#gro.gaps + 1] = "no_request_debug_trace"
  end

  -- exit attribution: who short-circuited this request?
  if gro.response.source == "exit" then
    gro.exit = trace.attribute_exit(ctx, gro, configured)
  end

  -- probe trail: per-gap timing, rewrites, and exit attribution that works on ordinary traffic
  if conf.probe_trail then
    local ok, tr = pcall(trail.build, ctx, gro, configured)
    if ok then
      gro.trail = tr
      local pt = tr and tr.exit
      if gro.exit and pt then
        -- copy, never share: kong.log.serialize() rejects a table that is referenced twice, and a
        -- rejected event takes every later log plugin on the request down with it
        local cands = {}
        for i, c in ipairs(pt.candidates or {}) do cands[i] = c end
        gro.exit.probe_trail = { plugin_name = pt.plugin_name, candidates = cands, confidence = pt.confidence, ms = pt.ms }
        if gro.exit.attribution ~= "request-debug-trace" then
          if pt.plugin_name then
            gro.exit.ai_filter_hint = gro.exit.plugin_name
            gro.exit.plugin_name, gro.exit.plugin_id, gro.exit.instance_name = pt.plugin_name, pt.plugin_id, pt.instance_name
            gro.exit.attribution, gro.exit.confidence, gro.exit.note = "probe-trail", "high", nil
          elseif gro.exit.plugin_name and pt.candidates then
            -- several plugins share the gap: accept the AI-filter hint only if it is one of them
            for _, c in ipairs(pt.candidates) do
              if c == gro.exit.plugin_name then
                gro.exit.attribution, gro.exit.confidence = "probe-trail+ai-filter-chain", "medium"
              end
            end
          end
        end
      end
    else
      gro.gaps[#gro.gaps + 1] = "probe_trail_error:" .. tostring(tr)
    end
    if conf.guardrail_timeouts then gro.thresholds = { guardrail_timeouts_ms = conf.guardrail_timeouts } end
  end
  if gro.exit and not gro.exit.plugin_name then
    gro.gaps[#gro.gaps + 1] = "exit_without_attribution"
  end

  -- guardrail verdicts
  local ok, verdicts = pcall(adapters.collect, conf, ctx, gro, configured, internal_supported)
  if ok then
    gro.guardrails = verdicts
  else
    gro.guardrails = {}
    gro.gaps[#gro.gaps + 1] = "adapter_error:" .. tostring(verdicts)
  end
  local guardrail_names = adapters.GUARDRAIL_NAMES
  if conf.guardrail_plugins and #conf.guardrail_plugins > 0 then
    guardrail_names = {}
    for k in pairs(adapters.GUARDRAIL_NAMES) do guardrail_names[k] = true end
    for _, n in ipairs(conf.guardrail_plugins) do guardrail_names[n] = true end
  end
  gro.policy_fingerprint = trace.policy_fingerprint(configured, guardrail_names)
  -- which of the known guardrail plugins are configured (and enabled) on this route: basis of the coverage check
  if configured and configured.plugins then
    local gc, seen = {}, {}
    for _, p in ipairs(configured.plugins) do
      if guardrail_names[p.name] and not seen[p.name] then
        seen[p.name] = true
        gc[#gc + 1] = { name = p.name, enabled = p.enabled, priority = trace.plugin_priority(p.name), config_sha256 = p.config_sha256 }
      end
    end
    gro.guardrails_configured = gc
  end

  -- upstream dispatch evidence: did an LLM call actually leave the gateway?
  -- ai-proxy performs the provider call inside its own filters (not via the
  -- nginx upstream), so KONG_PROXIED alone is not sufficient. We expose the
  -- facts separately and let the evaluator decide.
  gro.upstream = {
    kong_proxied = gro.response.proxied,
    upstream_status = gro.response.upstream_status,
    ai_proxy_request_normalized = gro.ai and gro.ai.executed_filters and (function()
      for _, f in ipairs(gro.ai.executed_filters) do if f == "normalize-request" then return true end end
      return false end)() or false,
    ai_response_body_present = gro.ai and gro.ai.response_body_bytes ~= nil or false,
    ai_response_body_source = gro.ai and gro.ai.response_body_source or nil,
    latencies_ms = {
      kong = ctx.KONG_PROXY_LATENCY or ctx.KONG_RESPONSE_LATENCY,
      proxy = ctx.KONG_WAITING_TIME,
      request = ctx.KONG_LOG_START and ctx.KONG_PROCESSING_START and (ctx.KONG_LOG_START - ctx.KONG_PROCESSING_START) or nil,
    },
  }

  gro.capture = {
    body_mode = conf.capture_body_mode,
    max_capture_bytes = conf.max_capture_bytes,
    max_chunks_recorded = conf.max_chunks_recorded,
    metadata_only = conf.capture_body_mode ~= "bounded",
  }

  -- strip private scratch fields
  gro._hash, gro._captured, gro._attribute_exits = nil, nil, nil
  gro._route_id, gro._service_id, gro._consumer_id, gro._verdict_header_value = nil, nil, nil, nil

  kong.log.set_serialize_value(conf.log_namespace, gro)
end

return Observer
