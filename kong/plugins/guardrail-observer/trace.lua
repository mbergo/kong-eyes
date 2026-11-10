-- Phase / plugin-chain tracing helpers.
--
-- IMPORTANT: part of this module reads Kong *internal* request state
-- (ngx.ctx.plugins, ngx.ctx.ai_executed_filters, ngx.ctx.ai_namespaced_ctx,
-- ngx.ctx.balancer_data). These are not public PDK APIs. They were verified
-- against the Kong 3.10.0 source tree (kong/runloop/plugins_iterator.lua,
-- kong/llm/plugin/base.lua, kong/llm/plugin/ctx.lua) and are probed at runtime
-- in init_worker; every field derived from them carries
-- provenance = "kong-internal-ctx" and a `supported` flag so the evaluator can
-- downgrade them to "unknown" on other versions instead of trusting them.

local cjson = require "cjson.safe"
local sha256 = require "resty.sha256"
local to_hex = require("resty.string").to_hex

local _M = {}

local SUPPORTED_MAJOR, SUPPORTED_MINOR = 3, 10

function _M.kong_version()
  local ok, meta = pcall(require, "kong.meta")
  if not ok then return nil end
  return meta.version, meta._VERSION_TABLE
end

-- true when the internal-ctx contracts we rely on are the ones we verified
function _M.internal_ctx_supported()
  local _, vt = _M.kong_version()
  if not vt then return false, "no kong.meta" end
  if vt.major ~= SUPPORTED_MAJOR or vt.minor ~= SUPPORTED_MINOR then
    return false, string.format("verified on %d.%d.x, running %s", SUPPORTED_MAJOR, SUPPORTED_MINOR, tostring(vt))
  end
  -- probe the AI plugin framework shape
  local ok_base = pcall(require, "kong.llm.plugin.base")
  local ok_ctx = pcall(require, "kong.llm.plugin.ctx")
  if not (ok_base and ok_ctx) then
    return false, "kong.llm.plugin framework not present"
  end
  return true, "ok"
end

function _M.sha256_hex(s)
  local d = sha256:new()
  d:update(s or "")
  return to_hex(d:final())
end

-- Plugins collected by the iterator for downstream phases during `access`.
-- ctx.plugins[phase] = { [0]=n, plugin1, cfg1, plugin2, cfg2, ... }
-- Only plugins implementing at least one downstream handler appear here;
-- access-only plugins (most auth plugins) do not. configured_plugins() fills that gap.
function _M.collected_chain(ctx)
  local plugins = ctx.plugins
  if type(plugins) ~= "table" then
    return nil, "ctx.plugins absent"
  end
  local by_id, order = {}, {}
  for _, phase in ipairs({ "response", "header_filter", "body_filter", "log" }) do
    local list = plugins[phase]
    if type(list) == "table" and type(list[0]) == "number" then
      for i = 1, list[0], 2 do
        local plugin, cfg = list[i], list[i + 1]
        if type(plugin) == "table" and plugin.name then
          local id = (type(cfg) == "table" and cfg.__plugin_id) or (plugin.name .. ":?")
          local rec = by_id[id]
          if not rec then
            rec = {
              name = plugin.name,
              plugin_id = type(cfg) == "table" and cfg.__plugin_id or nil,
              priority = plugin.handler and plugin.handler.PRIORITY or nil,
              version = plugin.handler and plugin.handler.VERSION or nil,
              phases = {},
            }
            by_id[id] = rec
            order[#order + 1] = rec
          end
          rec.phases[#rec.phases + 1] = phase
        end
      end
    end
  end
  table.sort(order, function(a, b) return (a.priority or 0) > (b.priority or 0) end)
  return order
end

-- AI plugin framework state (kong.llm.plugin.base / ctx)
function _M.ai_state(ctx)
  local executed = ctx.ai_executed_filters
  local ns = ctx.ai_namespaced_ctx
  if type(executed) ~= "table" and type(ns) ~= "table" then
    return nil
  end
  local out = { executed_filters = {}, namespaces = {} }
  if type(executed) == "table" then
    for name, v in pairs(executed) do
      if v then out.executed_filters[#out.executed_filters + 1] = name end
    end
    table.sort(out.executed_filters)
  end
  if type(ns) == "table" then
    for name, _ in pairs(ns) do
      out.namespaces[#out.namespaces + 1] = name
    end
    table.sort(out.namespaces)
    local g = ns._global
    if type(g) == "table" then
      out.stream_mode = g.stream_mode and true or false
      out.response_body_sent = g.response_body_sent and true or false
      out.response_body_bytes = type(g.response_body) == "string" and #g.response_body or nil
      out.response_body_sha256 = type(g.response_body) == "string" and _M.sha256_hex(g.response_body) or nil
      out.preserve_mode = g.preserve_mode and true or false
    end
    local src = ctx.ai_namespaced_ctx_global_source
    if type(src) == "table" then
      out.response_body_source = src.response_body
      out.response_body_sent_source = src.response_body_sent
    end
    local np = ns["normalize-request"]
    if type(np) == "table" and type(np.model) == "table" then
      out.model = { provider = np.model.provider, name = np.model.name }
    end
    local pr = ns["parse-request"]
    if (not out.model) and type(pr) == "table" and type(pr.request_model) == "table" then
      out.model = { provider = pr.request_model.provider, name = pr.request_model.name }
    end
    out.request_body_source = ctx.ai_request_body_table_source
  end
  if type(ctx.ai_llm_metrics) == "table" then
    out.metrics = {}
    for k, v in pairs(ctx.ai_llm_metrics) do
      if type(v) == "number" then out.metrics[k] = v end
    end
  end
  return out
end

-- Balancer attempts (retries / fallbacks). ctx.balancer_data.tries is the
-- same structure the native log serializer exposes as `tries`.
function _M.attempts(ctx)
  local bd = ctx.balancer_data
  if type(bd) ~= "table" or type(bd.tries) ~= "table" then
    return nil
  end
  local out = {}
  for i, t in ipairs(bd.tries) do
    out[i] = { ip = t.ip, port = t.port, code = t.code, state = t.state, balancer_latency = t.balancer_latency }
  end
  return out
end

-- Plugin instances configured for the current route/service/consumer/global.
-- Uses kong.db (LMDB in DB-less, Postgres otherwise) with kong.cache; costly
-- on cache miss for very large configs, so we cap the scan and flag truncation.
local MAX_SCAN = 2000

local SECRET_KEYS = { secret = true, password = true, header_value = true, key = true, token = true,
                      runner_shared_secret = true, client_secret = true, private_key = true }

local function scrub(t)
  if type(t) ~= "table" then return t end
  local out = {}
  for k, v in pairs(t) do
    if SECRET_KEYS[k] then
      out[k] = "<redacted>"
    elseif type(v) == "table" then
      out[k] = scrub(v)
    else
      out[k] = v
    end
  end
  return out
end

local function stable_encode(t)
  -- cjson key order is not stable; build a canonical form for hashing
  if type(t) ~= "table" then return cjson.encode(t) end
  local keys = {}
  for k in pairs(t) do keys[#keys + 1] = tostring(k) end
  table.sort(keys)
  local parts = {}
  for _, k in ipairs(keys) do
    local v = t[k]
    if v == nil then v = t[tonumber(k)] end
    parts[#parts + 1] = cjson.encode(k) .. ":" .. stable_encode(v)
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

local function load_configured(route_id, service_id, consumer_id)
  local out, n, truncated = {}, 0, false
  for plugin, err in kong.db.plugins:each(1000) do
    if err then
      return { error = tostring(err), plugins = out }
    end
    n = n + 1
    if n > MAX_SCAN then truncated = true break end
    local r = plugin.route and plugin.route.id
    local s = plugin.service and plugin.service.id
    local c = plugin.consumer and plugin.consumer.id
    -- applicable iff every scope the plugin is pinned to matches this request
    local matches = (r == nil or r == route_id)
      and (s == nil or s == service_id)
      and (c == nil or (consumer_id ~= nil and c == consumer_id))
    if matches then
      local scope = "global"
      if r then scope = "route" elseif s then scope = "service" elseif c then scope = "consumer" end
      out[#out + 1] = {
        name = plugin.name,
        id = plugin.id,
        instance_name = plugin.instance_name,
        scope = scope,
        enabled = plugin.enabled ~= false,
        protocols = plugin.protocols,
        updated_at = plugin.updated_at,
        config_sha256 = _M.sha256_hex(stable_encode(scrub(plugin.config or {}))),
      }
    end
  end
  table.sort(out, function(a, b) return a.name < b.name end)
  return { plugins = out, truncated = truncated, scanned = n }
end

function _M.configured_plugins(conf, route_id, service_id, consumer_id)
  if not route_id then return nil end
  local key = "guardrail-observer:plugins:" .. route_id .. ":" .. tostring(service_id) .. ":" .. tostring(consumer_id)
  local res, err = kong.cache:get(key, { ttl = conf.config_cache_ttl }, load_configured, route_id, service_id, consumer_id)
  if not res then
    return { error = tostring(err) }
  end
  return res
end

-- fingerprint of the guardrail-relevant plugin configs on this route
function _M.policy_fingerprint(configured, guardrail_names)
  if not configured or not configured.plugins then return nil end
  local parts = {}
  for _, p in ipairs(configured.plugins) do
    if guardrail_names[p.name] then
      parts[#parts + 1] = p.name .. "=" .. (p.config_sha256 or "?")
    end
  end
  if #parts == 0 then return nil end
  table.sort(parts)
  return _M.sha256_hex(table.concat(parts, ";")):sub(1, 16)
end

-- Kong request-debug trace (kong/timing). Present when the request carried
-- `X-Kong-Request-Debug: *` (+ `X-Kong-Request-Debug-Token` unless loopback).
-- Shape: root.child.<phase>.child.plugins.child.<plugin_name>.child.<plugin_id> = { total_time, child... }
-- Returns { phases = { access = { plugins = { {name, plugin_id, total_time_ms, priority} ... } } ... }, total_time_ms }
function _M.request_debug(ctx)
  local rt = ctx.req_trace_ctx
  if type(rt) ~= "table" or type(rt.root_context) ~= "table" then
    return nil
  end
  local root = rt.root_context
  local out = { phases = {}, total_time_ms = root.total_time, request_id = root.request_id }
  for phase, node in pairs(root.child or {}) do
    local ph = { total_time_ms = node.total_time, plugins = {} }
    local plugins = node.child and node.child.plugins
    if plugins and plugins.child then
      for name, pnode in pairs(plugins.child) do
        local ids = pnode.child or {}
        local any = false
        for id, inode in pairs(ids) do
          any = true
          ph.plugins[#ph.plugins + 1] = { name = name, plugin_id = id, total_time_ms = inode.total_time or pnode.total_time,
                                         priority = _M.plugin_priority(name) }
        end
        if not any then
          ph.plugins[#ph.plugins + 1] = { name = name, total_time_ms = pnode.total_time, priority = _M.plugin_priority(name) }
        end
      end
      -- execution order == descending priority
      table.sort(ph.plugins, function(a, b) return (a.priority or 0) > (b.priority or 0) end)
    end
    -- other children of the phase (router, dns, upstream...) kept as timings only
    for k, v in pairs(node.child or {}) do
      if k ~= "plugins" and type(v) == "table" then
        ph[k .. "_ms"] = v.total_time
      end
    end
    out.phases[phase] = ph
  end
  return out
end

local priority_cache = {}
function _M.plugin_priority(name)
  local p = priority_cache[name]
  if p ~= nil then return p or nil end
  local ok, handler = pcall(require, "kong.plugins." .. name .. ".handler")
  p = ok and type(handler) == "table" and handler.PRIORITY or false
  priority_cache[name] = p
  return p or nil
end

-- AI framework filter -> owning plugin (kong/plugins/<x>/handler.lua, 3.10)
local AI_FILTER_OWNER = {
  ["guard-prompt"] = "ai-prompt-guard",
  ["transform-request"] = "ai-request-transformer",
  ["transform-response"] = "ai-response-transformer",
  ["decorate-prompt"] = "ai-prompt-decorator",
  ["render-template"] = "ai-prompt-template",
  ["normalize-request"] = "ai-proxy", ["parse-request"] = "ai-*", ["enable-buffering"] = "ai-*",
}

-- Decide which plugin produced the short-circuit response.
-- 1. request-debug trace: the lowest-priority plugin whose access handler ran (nothing runs after an exit)
-- 2. AI framework: last AI filter executed maps to its plugin (medium confidence)
-- 3. none: unresolved
function _M.attribute_exit(ctx, gro, configured)
  local ex = { status = gro.response and gro.response.status, phase = "access" }
  local rd = gro.request_debug
  local acc = rd and rd.phases and rd.phases.access
  if acc and acc.plugins and #acc.plugins > 0 then
    local last = acc.plugins[#acc.plugins]
    ex.plugin_name, ex.plugin_id, ex.attribution, ex.confidence = last.name, last.plugin_id, "request-debug-trace", "high"
    ex.executed_access_plugins = {}
    for i, p in ipairs(acc.plugins) do ex.executed_access_plugins[i] = p.name end
    if configured and configured.plugins then
      for _, p in ipairs(configured.plugins) do
        if p.id == ex.plugin_id then ex.instance_name = p.instance_name end
      end
    end
    return ex
  end
  local executed = ctx.ai_executed_filters
  if type(executed) == "table" then
    local best, best_owner
    for f, v in pairs(executed) do
      if v and AI_FILTER_OWNER[f] and AI_FILTER_OWNER[f] ~= "ai-*" then
        local owner = AI_FILTER_OWNER[f]
        local pr = _M.plugin_priority(owner) or 0
        if not best or pr < best then best, best_owner = pr, owner end
      end
    end
    if best_owner then
      ex.plugin_name, ex.attribution, ex.confidence = best_owner, "ai-filter-chain", "medium"
      ex.note = "lowest-priority AI plugin whose filter executed; send X-Kong-Request-Debug for a definitive trace"
      return ex
    end
  end
  ex.attribution, ex.confidence = "unavailable", "none"
  ex.note = "no request-debug trace and no AI filter evidence; status alone is not used for attribution"
  return ex
end

return _M
