-- Verdict adapters. Each adapter returns zero or more guardrail records:
--
-- {
--   guardrail   = "ai-prompt-guard",        -- plugin / vendor name
--   adapter     = "ai-prompt-guard@1",      -- adapter contract + version
--   stage       = "input" | "output",
--   verdict     = "allow" | "deny" | "detect" | "not_run" | "skipped" | "error" | "unknown",
--   mode        = "block" | "detect" | "disabled" | nil,
--   action      = "block" | "redact" | "transform" | "abort_stream" | "none" | nil,
--   enforced_by = "<plugin name>" | nil,    -- component that produced the client-visible effect
--   status      = <http status if the guardrail produced the response>,
--   provenance  = "kong-internal-ctx" | "ctx-events" | "response-header",
--   supported   = true|false,                -- false => evaluator must treat as unknown
--   reason      = "...",                     -- why we concluded this
--   evidence    = {...}                      -- bounded raw facts
-- }
--
-- Rules: never infer a verdict from HTTP status alone; a guardrail that did
-- not execute is "not_run" (never a true negative); missing evidence is
-- "unknown" with a reason.

local trace = require "kong.plugins.guardrail-observer.trace"

local _M = {}

local function has_plugin(configured, name)
  if not configured or not configured.plugins then return nil end
  for _, p in ipairs(configured.plugins) do
    if p.name == name and p.enabled then return p end
  end
  return false
end

---------------------------------------------------------------------------
-- ai-prompt-guard (bundled, Kong 3.10): regex allow/deny on prompts.
-- Facts (kong/plugins/ai-prompt-guard/filters/guard-prompt.lua, 3.10.0):
--   * filter name "guard-prompt", STAGE REQ_TRANSFORMATION (access)
--   * on allow:  set_ctx("guarded", true)  -> ngx.ctx.ai_namespaced_ctx["guard-prompt"].guarded == true
--   * on deny:   kong.response.exit(400, {error={message="bad request"}})  (no ctx flag)
--   * on bad regex: kong.response.exit(500)
--   * executed-ness: ngx.ctx.ai_executed_filters["guard-prompt"] == true
-- The plugin writes nothing to the log serializer, so deny/allow is only
-- recoverable from this ctx state plus exit attribution.
---------------------------------------------------------------------------
function _M.ai_prompt_guard(ctx, gro, configured, supported)
  local present = has_plugin(configured, "ai-prompt-guard")
  -- filter name: "guard-prompt" (3.10) / "guard-request" (3.15, observed on Konnect serverless 3.15.0.6)
  local ex = ctx.ai_executed_filters or {}
  local nsall = ctx.ai_namespaced_ctx or {}
  local fname = (ex["guard-request"] ~= nil or nsall["guard-request"] ~= nil) and "guard-request" or "guard-prompt"
  local executed = ex[fname] or false
  local ns = nsall[fname]
  local guarded = type(ns) == "table" and ns.guarded == true

  if present == false and not executed and not guarded then
    return nil -- not configured on this route, nothing to say
  end

  local rec = {
    guardrail = "ai-prompt-guard",
    adapter = "ai-prompt-guard@1",
    stage = "input",
    mode = "block",            -- the plugin has no detect-only mode
    provenance = "kong-internal-ctx",
    supported = supported,
    plugin_id = present and present.id or nil,
    evidence = { executed = executed, guarded_flag = guarded, filter = fname },
  }

  if not supported then
    rec.verdict = "unknown"
    rec.reason = "internal ctx contract not verified on this Kong version"
    return rec
  end

  if not executed then
    rec.verdict = "not_run"
    rec.reason = (gro.exit and gro.exit.plugin_name ~= "ai-prompt-guard")
      and ("short-circuited earlier by " .. tostring(gro.exit.plugin_name))
      or "guard-prompt filter never executed"
    return rec
  end

  if guarded then
    rec.verdict = "allow"
    rec.action = "none"
    rec.confidence = "high"
    rec.reason = fname .. " executed and set guarded=true"
    return rec
  end

  -- 3.15 sets no flag: if the filter executed and the chain continued into ai-proxy (normalize-request ran,
  -- response came from the service), the guard returned without exiting => allow by construction.
  if ex["normalize-request"] and gro.response and gro.response.source ~= "exit" then
    rec.verdict = "allow"
    rec.action = "none"
    rec.confidence = "medium"
    rec.reason = fname .. " executed and the request proceeded to ai-proxy (no guarded flag on this version)"
    rec.evidence.continued_to_ai_proxy = true
    return rec
  end

  -- executed but no allow flag: the filter exited (400 bad request / 500 regex error).
  -- Attribution comes from the request-debug trace (high) or the AI filter chain (medium).
  local ex = gro.exit or {}
  local source = gro.response and gro.response.source
  local status = gro.response and gro.response.status
  local attributed_here = ex.plugin_name == "ai-prompt-guard"
  local no_later_ai_filter = not (ctx.ai_executed_filters and ctx.ai_executed_filters["normalize-request"])
  if source == "exit" and (attributed_here or (no_later_ai_filter and ex.attribution ~= "request-debug-trace")) then
    rec.status = status
    rec.enforced_by = "ai-prompt-guard"
    rec.confidence = attributed_here and ex.confidence or "medium"
    rec.attribution = attributed_here and ex.attribution or "ai-filter-chain"
    if status == 400 then
      rec.verdict = "deny"
      rec.action = "block"
      rec.reason = "guard-prompt executed without guarded flag; request exited 400 before ai-proxy normalized the request"
    elseif status == 500 then
      rec.verdict = "error"
      rec.action = "block"
      rec.reason = "guard-prompt exited 500 (bad regex or unsupported body)"
    else
      rec.verdict = "unknown"
      rec.reason = "exit after guard-prompt with unexpected status " .. tostring(status)
    end
    return rec
  end

  rec.verdict = "unknown"
  rec.reason = "guard-prompt executed without guarded flag but the exit is attributed to " .. tostring(ex.plugin_name or "nobody")
  return rec
end

---------------------------------------------------------------------------
-- ctx-events: explicit contract for guardrail plugins that announce their
-- decisions by appending to ngx.ctx.guardrail_events (see fixture plugins and
-- docs/adapters.md). This is the recommended integration for custom/vendor
-- guardrails you control: one table.insert per decision, no inference.
---------------------------------------------------------------------------
function _M.ctx_events(ctx)
  local events = ctx.guardrail_events
  if type(events) ~= "table" or #events == 0 then return nil end
  local out = {}
  for i, ev in ipairs(events) do
    if type(ev) == "table" then
      out[#out + 1] = {
        guardrail = ev.guardrail or "unknown-guardrail",
        adapter = "ctx-events@1",
        stage = ev.stage or "unknown",
        verdict = ev.verdict or "unknown",
        mode = ev.mode,
        action = ev.action,
        enforced_by = ev.enforced_by or ev.guardrail,
        status = ev.status,
        provenance = "ctx-events",
        supported = true,
        reason = ev.reason,
        ts_ms = ev.ts_ms,
        seq = i,
        evidence = ev.evidence,
      }
    end
  end
  return out
end

---------------------------------------------------------------------------
-- response-header: vendors that stamp a verdict header on the response
-- (read in header_filter, finalized here). Value grammar accepted:
--   "allow" | "deny" | "detect" | "deny;stage=output;action=block"
---------------------------------------------------------------------------
function _M.response_header(conf, gro)
  local raw = gro._verdict_header_value
  if not raw then return nil end
  local verdict = raw:match("^(%a+)") or "unknown"
  verdict = verdict:lower()
  local ok = { allow = true, deny = true, detect = true, error = true }
  if not ok[verdict] then verdict = "unknown" end
  local stage = raw:match("stage=(%a+)") or "unknown"
  local action = raw:match("action=(%a+)")
  return {
    guardrail = conf.verdict_header_guardrail,
    adapter = "response-header@1",
    stage = stage,
    verdict = verdict,
    action = action,
    provenance = "response-header",
    supported = true,
    reason = "header " .. conf.verdict_header .. " present",
    evidence = { header_value = raw:sub(1, 256) },
  }
end

function _M.collect(conf, ctx, gro, configured, internal_supported)
  local out = {}
  local enabled = {}
  for _, a in ipairs(conf.adapters or {}) do enabled[a] = true end

  if enabled["ai-prompt-guard"] then
    local r = _M.ai_prompt_guard(ctx, gro, configured, internal_supported)
    if r then out[#out + 1] = r end
  end
  if enabled["ctx-events"] then
    local rs = _M.ctx_events(ctx)
    if rs then for _, r in ipairs(rs) do out[#out + 1] = r end end
  end
  if enabled["response-header"] then
    local r = _M.response_header(conf, gro)
    if r then out[#out + 1] = r end
  end

  -- known guardrail plugins we cannot read on this edition/version: surface
  -- them as unknown so a configured-but-unobservable guardrail is never a TN.
  local unobservable = { ["ai-semantic-prompt-guard"] = true, ["ai-azure-content-safety"] = true,
                         ["ai-sanitizer"] = true, ["ai-custom-guardrail"] = true }
  if configured and configured.plugins then
    for _, p in ipairs(configured.plugins) do
      if unobservable[p.name] and p.enabled then
        local seen = false
        for _, r in ipairs(out) do if r.guardrail == p.name then seen = true end end
        if not seen then
          out[#out + 1] = {
            guardrail = p.name, adapter = "none", stage = "unknown", verdict = "unknown",
            provenance = "configured-plugins", supported = false, plugin_id = p.id,
            reason = "configured on route but no verified adapter for this guardrail; use ctx-events or response-header",
          }
        end
      end
    end
  end

  return out
end

_M.GUARDRAIL_NAMES = {
  ["ai-prompt-guard"] = true, ["ai-semantic-prompt-guard"] = true, ["ai-azure-content-safety"] = true,
  ["ai-sanitizer"] = true, ["ai-custom-guardrail"] = true,
  ["fixture-input-guard"] = true, ["fixture-output-guard"] = true,
}

return _M
