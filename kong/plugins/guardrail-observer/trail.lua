-- Probe trail: turns the markers left by the head plugin (790), the generated middle probes
-- (gro-probe-<priority>) and the tail plugin (5) into per-gap evidence.
--
-- Facts relied on (verified on Kong 3.10, see docs/phase-trace.md):
--   * every phase runs plugins in descending PRIORITY;
--   * after a kong.response.exit() in access, the remaining access handlers are skipped,
--     so the last probe on the trail bounds the plugin that exited from above and the first
--     missing probe bounds it from below.
-- Nothing here is a verdict: a gap names the plugins that sit in it and what was measured.

local trace = require "kong.plugins.guardrail-observer.trace"
local to_hex = require("resty.string").to_hex

local _M = {}

local HEAD_PRIORITY, TAIL_PRIORITY = 790, 5

local function is_ours(name)
  return name == "guardrail-observer" or name == "guardrail-observer-tail" or name:sub(1, 10) == "gro-probe-"
end

local handler_cache = {}
local function handler_of(name)
  local h = handler_cache[name]
  if h == nil then
    local ok, mod = pcall(require, "kong.plugins." .. name .. ".handler")
    h = ok and type(mod) == "table" and mod or false
    handler_cache[name] = h
  end
  return h or nil
end

local function has_any_phase(name, phases)
  local h = handler_of(name)
  if not h then return false end
  for _, ph in ipairs(phases) do
    if type(h[ph]) == "function" then return true end
  end
  return false
end

-- enabled third-party plugins on this route with lo < priority < hi that implement one of `phases`
local function between(configured, hi, lo, phases)
  local out, seen = {}, {}
  if not configured or not configured.plugins then return out end
  for _, p in ipairs(configured.plugins) do
    if p.enabled and not is_ours(p.name) and not seen[p.name] then
      local pr = trace.plugin_priority(p.name)
      if pr and pr < hi and pr > lo and has_any_phase(p.name, phases) then
        seen[p.name] = true
        out[#out + 1] = { name = p.name, priority = pr, id = p.id, instance_name = p.instance_name }
      end
    end
  end
  table.sort(out, function(a, b) return a.priority > b.priority end)
  return out
end

local function names(list)
  local o = {}
  for i, p in ipairs(list) do o[i] = p.name end
  return o
end

local function expected_probes(configured)
  local out = {}
  if configured and configured.plugins then
    local seen = {}
    for _, p in ipairs(configured.plugins) do
      if p.enabled and p.name:sub(1, 10) == "gro-probe-" and not seen[p.name] then
        seen[p.name] = true
        local pr = trace.plugin_priority(p.name)
        if pr then out[#out + 1] = pr end
      end
    end
  end
  table.sort(out, function(a, b) return a > b end)
  return out
end

local ACCESS = { "access" }
local RESPONSE = { "header_filter", "body_filter" }

-- Returns the `trail` block of the event, or nil when the head did not start one.
function _M.build(ctx, gro, configured)
  local ran = ctx.gro_trail
  if type(ran) ~= "table" or #ran == 0 then return nil end

  local out = { head_priority = HEAD_PRIORITY, tail_priority = TAIL_PRIORITY }
  local expected = expected_probes(configured)
  out.probes_expected = expected
  out.configured_known = configured ~= nil and configured.plugins ~= nil

  -- request side ------------------------------------------------------------
  local t0 = gro.started_at_ms or ran[1].t
  local req, ran_set = {}, {}
  for i, e in ipairs(ran) do
    req[i] = { p = e.p, t = e.t - t0, n = e.n, h = e.h }
    ran_set[e.p] = true
  end
  out.request = req

  local gaps = {}
  for i = 1, #ran - 1 do
    local a, b = ran[i], ran[i + 1]
    local g = { from = a.p, to = b.p, ms = b.t - a.t, plugins = names(between(configured, a.p, b.p, ACCESS)) }
    if a.h and b.h then
      g.rewritten = a.h ~= b.h
      if g.rewritten and a.n and b.n then g.bytes_delta = b.n - a.n end
    end
    gaps[#gaps + 1] = g
  end
  out.gaps = gaps

  local missing = {}
  for _, p in ipairs(expected) do
    if not ran_set[p] then missing[#missing + 1] = p end
  end
  out.missing = missing

  -- who stopped the request? ---------------------------------------------------
  if gro.response and gro.response.source == "exit" then
    local last = ran[#ran]
    local lo = missing[1] or -math.huge       -- highest probe that did not run
    local cands = between(configured, last.p, lo, ACCESS)
    local ex = { from = last.p, to = missing[1], candidates = names(cands), attribution = "probe-trail" }
    local hf = gro.phases and gro.phases.header_filter and gro.phases.header_filter.ts_ms
    if hf then ex.ms = hf - last.t end
    if #cands == 1 then
      ex.plugin_name, ex.plugin_id, ex.instance_name, ex.confidence = cands[1].name, cands[1].id, cands[1].instance_name, "high"
    elseif #cands == 0 then
      ex.confidence = "none"
      ex.note = "no third-party plugin with an access handler sits in this gap"
    else
      ex.confidence = "low"
      ex.note = "several plugins share this gap; add a probe between them (scripts/gen-probes.sh)"
    end
    out.exit = ex
    if not ran_set[HEAD_PRIORITY] then ex.note = "head marker missing" end
  end

  -- response side -------------------------------------------------------------
  local resp = {}
  if gro.stream then
    resp[#resp + 1] = { p = HEAD_PRIORITY, chunks = gro.stream.chunks, bytes = gro.stream.bytes, sha256 = gro.stream.sha256,
                        first_ms = gro.stream.first_chunk_at_ms, eof_ms = gro.stream.eof_at_ms }
  end
  if type(ctx.gro_rtrail) == "table" then
    for _, s in ipairs(ctx.gro_rtrail) do
      -- a probe above ai-proxy never sees eof (ai-proxy ends the body itself), so finish its hash here
      if s._h then
        if s.chunks > 0 then s.sha256 = to_hex(s._h:final()) end
        s._h = nil
      end
      resp[#resp + 1] = { p = s.p, chunks = s.chunks, bytes = s.bytes, sha256 = s.sha256, first_ms = s.first_ms, eof_ms = s.eof_ms }
    end
  end
  if type(ctx.gro_tail) == "table" then
    local s = ctx.gro_tail
    resp[#resp + 1] = { p = TAIL_PRIORITY, chunks = s.chunks, bytes = s.bytes, sha256 = s.sha256,
                        first_ms = s.first_chunk_at_ms, eof_ms = s.eof_at_ms }
  end
  table.sort(resp, function(a, b) return a.p > b.p end)
  local rgaps = {}
  for i = 1, #resp - 1 do
    local a, b = resp[i], resp[i + 1]
    local g = { from = a.p, to = b.p, plugins = names(between(configured, a.p, b.p, RESPONSE)),
                bytes_delta = (b.bytes or 0) - (a.bytes or 0), chunks_delta = (b.chunks or 0) - (a.chunks or 0) }
    if a.sha256 and b.sha256 then g.changed = a.sha256 ~= b.sha256
    elseif (a.bytes or 0) ~= (b.bytes or 0) then g.changed = true end
    if a.first_ms and b.first_ms then g.first_chunk_delay_ms = b.first_ms - a.first_ms end
    rgaps[#rgaps + 1] = g
  end
  for _, r in ipairs(resp) do
    if r.first_ms then r.first_ms = r.first_ms - t0 end
    if r.eof_ms then r.eof_ms = r.eof_ms - t0 end
  end
  out.response = resp
  out.response_gaps = rgaps
  return out
end

return _M
