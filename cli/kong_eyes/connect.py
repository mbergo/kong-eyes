"""koe connect: attach Kong Eyes to a route of any Kong using only plugins Kong already ships.

Nothing is installed on the gateway. Three bundled plugins are added to the route through the Admin API:

  pre-function   first thing in the access phase: note the time (and, optionally, the start of the body)
  post-function  last thing in the access phase: note the time again
  http-log       after the response: one event per request to the Kong Eyes collector, built by a small Lua
                 expression (custom_fields_by_lua) from those two marks and Kong's own request context

What that gives for a route with ONE guardrail plugin, per request: served or stopped; who stopped it (by
elimination: authentication passed and the model plugin never ran, so it was the guardrail); the time the
access chain took, which is the guardrail's time when it is the one slow plugin; whether it waited about its
timeout and was then let through (fail-open); whether the body changed on the way.

What it cannot give: exact time per plugin when several plugins on the route are slow, and anything about
a second guardrail (they share the one bracket). The generated probe plugins exist for that.

Works on DB-backed Kong (plugins are created by id, idempotent) and on DB-less Kong (the running config is
read, extended and posted back; it lives in memory until the next restart, so `--print-yaml` gives the snippet
to add to your declarative file).
"""
from __future__ import annotations

import json
import socket
import urllib.error
import urllib.parse
import urllib.request
import uuid

TAG = "kong-eyes"
NS = uuid.UUID("6f0f5a0e-6f1c-4f0b-9d0e-2b7f3a0c9e11")
OURS = ("pre-function", "post-function", "http-log")
AUTH_PLUGINS = ("key-auth", "key-auth-enc", "jwt", "basic-auth", "oauth2", "hmac-auth", "ldap-auth", "ldap-auth-advanced",
                "openid-connect", "mtls-auth", "jwt-signer", "oauth2-introspection")
RATE_PLUGINS = ("rate-limiting", "rate-limiting-advanced", "ai-rate-limiting-advanced", "response-ratelimiting")
# plugins that are never "the guardrail"; used only to guess it when --guardrail is not given
NOT_GUARDRAILS = set(AUTH_PLUGINS) | set(RATE_PLUGINS) | set(OURS) | {
    "acl", "cors", "prometheus", "opentelemetry", "zipkin", "datadog", "statsd", "file-log", "tcp-log", "udp-log", "syslog", "loggly",
    "kafka-log", "correlation-id", "request-transformer", "response-transformer", "request-size-limiting", "ip-restriction",
    "bot-detection", "request-termination", "proxy-cache", "grpc-web", "grpc-gateway", "session", "acme", "aws-lambda", "azure-functions",
    "ai-proxy", "ai-proxy-advanced", "ai-prompt-decorator", "ai-prompt-template", "ai-request-transformer", "ai-response-transformer",
    "ai-semantic-cache", "request-validator", "redirect", "standard-webhooks", "canary", "forward-proxy", "upstream-timeout"}
# only used to draw the chain in order; a third-party plugin's priority is not exposed by the Admin API
KNOWN_PRIORITY = {"pre-function": 1000000, "key-auth": 1250, "jwt": 1450, "basic-auth": 1100, "oauth2": 1400, "hmac-auth": 1030,
                  "openid-connect": 1050, "acl": 950, "rate-limiting": 910, "rate-limiting-advanced": 910, "ai-prompt-guard": 771,
                  "ai-proxy": 770, "ai-proxy-advanced": 770, "prometheus": 13, "http-log": 12, "post-function": -1000}

PRE = """-- kong-eyes: first mark (bundled-plugin mode)
local s = kong.ctx.shared
ngx.update_time(); s.ke_t0 = ngx.now()
if __BODY__ then
  local b = kong.request.get_raw_body()
  if b then s.ke_n0 = #b; s.ke_h0 = ngx.md5(b); if __PROMPT__ > 0 then s.ke_body = b:sub(1, __PROMPT__) end end
end"""

POST = """-- kong-eyes: second mark (bundled-plugin mode)
local s = kong.ctx.shared
ngx.update_time(); s.ke_t1 = ngx.now()
if __BODY__ then local b = kong.request.get_raw_body(); if b then s.ke_n1 = #b; s.ke_h1 = ngx.md5(b) end end"""

# Runs in the log phase inside http-log, in Kong's default Lua sandbox. __X__ values are filled in by the CLI.
EVENT = """return (function()
  local s, c = kong.ctx.shared, ngx.ctx
  local GUARD, AUTH, RATE, TIMEOUT = __GUARD__, __AUTH__, __RATE__, __TIMEOUT__
  ngx.update_time()
  local now, start = math.floor(ngx.now() * 1000), math.floor(ngx.req.start_time() * 1000)
  local status, source = kong.response.get_status(), kong.response.get_source()
  local consumer, route, service = kong.client.get_consumer(), kong.router.get_route(), kong.router.get_service()
  local ex = c.ai_executed_filters or {}
  local rid = ngx.var.kong_request_id or ngx.var.request_id or ""
  local t0, t1 = s.ke_t0, s.ke_t1
  local trail = { mode = "bundled-bracket", probes_expected = {}, request = {}, gaps = {}, configured_known = true,
                  head_priority = 1000000, tail_priority = -1000 }
  local exit, verdict
  if source == "exit" and t0 and not t1 then
    -- stopped somewhere between the two marks; name the plugin by elimination
    local who, why = GUARD, "authentication passed and the request never reached the end of the access phase"
    if AUTH and (status == 401 or status == 407 or not consumer) then who, why = AUTH, "no authenticated consumer"
    elseif RATE and status == 429 then who, why = RATE, "status 429" end
    local ms = c.KONG_ACCESS_ENDED_AT and math.max(0, math.floor(c.KONG_ACCESS_ENDED_AT - t0 * 1000 + 0.5)) or nil
    trail.exit = { candidates = { who }, plugin_name = who, confidence = "medium", ms = ms, after = 1000000, note = why }
    exit = { status = status, plugin_name = who, attribution = "bundled-bracket", confidence = "medium",
             probe_trail = { candidates = { who }, confidence = "medium" } }
    if who == GUARD then verdict = { verdict = "deny", action = "block", enforced_by = GUARD, status = status, reason = "stopped inside the bracket: " .. why } end
  elseif t0 and t1 then
    local ms = math.floor((t1 - t0) * 1000 + 0.5)
    trail.gaps[1] = { from = 1000000, to = -1000, ms = ms, plugins = { GUARD }, rewritten = (s.ke_h0 ~= nil and s.ke_h1 ~= nil and s.ke_h0 ~= s.ke_h1) or false,
                      bytes_delta = (s.ke_n0 and s.ke_n1) and (s.ke_n1 - s.ke_n0) or nil, note = "time of the whole access chain" }
    verdict = { verdict = "allow", action = "none", reason = "the request passed the guardrail and continued (allow by construction)" }
  end
  if verdict then
    verdict.guardrail, verdict.stage, verdict.mode, verdict.adapter, verdict.provenance, verdict.supported = GUARD, "input", "block", "bundled-bracket@1", "kong-eyes-bracket", true
  end
  local filters = {}
  for k, v in pairs(ex) do if v then filters[#filters + 1] = k end end
  table.sort(filters)
  return {
    schema_version = "1.1", event_type = "kong_observation", observer_version = "__VERSION__-bundled", observer_mode = "bundled plugins (pre-function, post-function, http-log)",
    kong_version = kong.version, event_id = ngx.md5(rid .. "|" .. (route and route.id or "") .. "|" .. start), request_id = rid,
    started_at_ms = start, ended_at_ms = now, duration_ms = now - start, environment = __ENV__, policy_version = __POLICY__, gateway = __GATEWAY__,
    route = route and { id = route.id, name = route.name } or nil, service = service and { id = service.id, name = service.name } or nil,
    consumer = consumer and { id = consumer.id, username = consumer.username } or nil,
    runner = { present = false, trusted = false, reason = "bundled-mode" },
    request = { method = kong.request.get_method(), path = kong.request.get_path(), body_bytes = s.ke_n0, body_sha256 = s.ke_h0, body_prefix = s.ke_body },
    response = { status = status, source = source, proxied = c.KONG_PROXIED and true or false, upstream_status = ngx.var.upstream_status,
                 content_type = kong.response.get_header("content-type") },
    exit = exit, trail = trail, guardrails = verdict and { verdict } or {},
    guardrails_configured = { { name = GUARD, enabled = true, priority = __GUARD_PRIORITY__ } },
    configured_plugins = { plugins = __CONFIGURED__ }, plugin_chain = __CHAIN__,
    thresholds = TIMEOUT and { guardrail_timeouts_ms = { [GUARD] = TIMEOUT } } or nil,
    ai = { executed_filters = filters }, capture = { body_mode = __CAPTURE__ },
    gaps = { "bundled-mode:one-bracket-for-the-whole-access-chain", "bundled-mode:attribution-by-elimination", "bundled-mode:no-response-side-marks" },
  }
end)()"""


class Kong:
    def __init__(self, admin_url: str, token: str | None = None, konnect: str | None = None):
        """konnect: the control plane's name when admin_url is a Konnect control plane's core-entities address."""
        self.base = admin_url.rstrip("/")
        self.konnect = konnect
        self.headers = {"Content-Type": "application/json", "User-Agent": "koe"}
        if token:
            self.headers["Authorization" if konnect else "Kong-Admin-Token"] = f"Bearer {token}" if konnect else token
        local = any(h in self.base for h in ("//localhost", "//127.0.0.1"))
        self._open = urllib.request.build_opener(urllib.request.ProxyHandler({})) if local else urllib.request.build_opener()

    def call(self, method: str, path: str, body=None):
        req = urllib.request.Request(self.base + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers=self.headers)
        try:
            with self._open.open(req, timeout=60) as r:
                raw = r.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            if self.konnect and e.code in (401, 403):
                raise SystemExit(f"Konnect refused the token ({e.code}). Create a personal access token in Konnect and pass it as KONNECT_TOKEN.") from None
            raise SystemExit(f"Kong Admin API {method} {path} -> {e.code}: {e.read().decode()[:400]}") from None
        except urllib.error.URLError as e:
            raise SystemExit(f"cannot reach Kong's Admin API at {self.base}: {e.reason}") from None

    def info(self) -> dict:
        if self.konnect:                 # Konnect has no node to ask; its control planes store config in a database and ship these plugins
            return {"version": "Konnect", "edition": f"control plane {self.konnect}", "dbless": False, "role": "control_plane",
                    "untrusted_lua": "sandbox", "available": set(OURS), "konnect": True}
        d = self.call("GET", "/")
        c = d.get("configuration") or {}
        return {"version": d.get("version"), "edition": d.get("edition", "community"), "dbless": c.get("database") == "off",
                "role": c.get("role", "traditional"), "untrusted_lua": c.get("untrusted_lua", "sandbox"),
                "available": set((d.get("plugins") or {}).get("available_on_server") or {})}

    def pages(self, path: str) -> list[dict]:
        out, offset = [], None
        while True:
            d = self.call("GET", path + ("&" if "?" in path else "?") + "size=1000" + (f"&offset={urllib.parse.quote(offset, safe='')}" if offset else ""))
            out += d.get("data") or []
            offset = d.get("offset")
            if not offset:
                return out

    def route(self, name_or_id: str) -> dict:
        if not self.konnect:
            return self.call("GET", f"/routes/{urllib.parse.quote(name_or_id)}")
        for r in self.pages("/routes"):                    # Konnect looks routes up by id only
            if name_or_id in (r.get("name"), r["id"]):
                return r
        raise SystemExit(f"this control plane has no route called {name_or_id}")


KONNECT_REGIONS = ("us", "eu", "au", "me", "in", "sg")


def konnect(token: str, region: str = "us", control_plane: str | None = None, api_url: str | None = None, choose=None) -> Kong:
    """A Konnect control plane, addressed like an Admin API. Lists the control planes and picks one."""
    api = (api_url or f"https://{region}.api.konghq.com").rstrip("/")
    root = Kong(api + "/v2", token, konnect="?")
    cps, page = [], 1
    while True:
        d = root.call("GET", f"/control-planes?page%5Bsize%5D=100&page%5Bnumber%5D={page}")
        cps += d.get("data") or []
        total = ((d.get("meta") or {}).get("page") or {}).get("total") or len(cps)
        if not d.get("data") or len(cps) >= total:
            break
        page += 1
    if not cps:
        raise SystemExit(f"this Konnect account has no control planes in region {region}. Try --konnect-region ({', '.join(KONNECT_REGIONS)}).")
    if control_plane:
        hit = [c for c in cps if control_plane in (c.get("name"), c.get("id"))]
        if not hit:
            raise SystemExit(f"no control plane called {control_plane} (found: {', '.join(c['name'] for c in cps)})")
        cp = hit[0]
    elif len(cps) == 1:
        cp = cps[0]
    else:
        cp = choose(cps) if choose else None
        if cp is None:
            raise SystemExit(f"more than one control plane: run again with --control-plane NAME ({', '.join(c['name'] for c in cps)})")
    return Kong(f"{api}/v2/control-planes/{cp['id']}/core-entities", token, konnect=cp.get("name") or cp["id"])


def lua(v) -> str:
    """A Python value as a Lua literal."""
    if v is None:
        return "nil"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v)
    if isinstance(v, (list, tuple)):
        return "{ " + ", ".join(lua(x) for x in v) + " }"
    if isinstance(v, dict):
        return "{ " + ", ".join(f"[{json.dumps(k)}] = {lua(x)}" for k, x in v.items()) + " }"
    raise TypeError(type(v))


def plan(kong: Kong, a) -> dict:
    """Read the gateway, decide what to add, and say why. Nothing is changed here."""
    info = kong.info()
    missing = [p for p in OURS if p not in info["available"]]
    if missing:
        raise SystemExit(f"this Kong does not have {', '.join(missing)} enabled (KONG_PLUGINS). Bundled mode needs all three.")
    if info["untrusted_lua"] == "off":
        raise SystemExit("this Kong runs with untrusted_lua=off, which disables pre-function, post-function and custom log fields. "
                         "Use the probe plugins instead (scripts/gen-probes.sh).")
    route = kong.route(a.route)
    rid, sid = route["id"], (route.get("service") or {}).get("id")
    scoped = kong.pages(f"/routes/{rid}/plugins")
    inherited = [p for p in kong.pages("/plugins") if not p.get("route") and not p.get("consumer") and
                 (not p.get("service") or (p["service"] or {}).get("id") == sid)]
    effective = {p["name"]: p for p in inherited}
    effective.update({p["name"]: p for p in scoped})                       # route scope wins
    mine = [p for p in scoped if TAG in (p.get("tags") or [])]
    clash = [p["name"] for p in scoped if p["name"] in OURS and TAG not in (p.get("tags") or [])]
    if clash:
        raise SystemExit(f"route {a.route} already has its own {', '.join(clash)}. Kong allows one instance of a plugin per route, and Kong Eyes "
                         "will not take over yours. Use another route, or the probe plugins.")
    names = [n for n, p in effective.items() if p.get("enabled", True)]
    guard = a.guardrail
    if not guard:
        cands = [n for n in names if n not in NOT_GUARDRAILS and not n.startswith("gro-probe-") and not n.startswith("guardrail-observer")]
        if len(cands) != 1:
            raise SystemExit(f"could not tell which plugin is the guardrail on {a.route} (candidates: {', '.join(sorted(cands)) or 'none'}). Pass --guardrail NAME.")
        guard = cands[0]
    elif guard not in names:
        raise SystemExit(f"{guard} is not an enabled plugin on route {a.route} (found: {', '.join(sorted(names))})")
    auth = next((n for n in names if n in AUTH_PLUGINS), None)
    rate = next((n for n in names if n in RATE_PLUGINS), None)
    gprio = a.guardrail_priority or 800
    chain = sorted(({"name": n, "priority": gprio if n == guard else KNOWN_PRIORITY.get(n, 500)} for n in names if n not in OURS),
                   key=lambda x: -x["priority"])
    u = urllib.parse.urlsplit(a.ingest_url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise SystemExit("--ingest-url must be the collector's http(s) URL, e.g. https://eyes.example.com/ingest/kong")
    endpoint = urllib.parse.urlunsplit((u.scheme, (f"kong:{a.ingest_token}@" if a.ingest_token else "") + u.hostname + (f":{u.port}" if u.port else ""),
                                        u.path or "/ingest/kong", u.query, ""))
    body = bool(a.detect_rewrites or a.show_prompts)
    pre, post = PRE, POST
    for k, v in {"__BODY__": lua(body), "__PROMPT__": str(int(a.show_prompts or 0))}.items():
        pre, post = pre.replace(k, v), post.replace(k, v)
    from . import __version__
    host = urllib.parse.urlsplit(kong.base).hostname or "kong"
    gateway = getattr(a, "gateway_name", None) or (f"{kong.konnect} (Konnect)" if kong.konnect else socket.gethostname() if host in ("localhost", "127.0.0.1") else host)
    event = EVENT
    for k, v in {"__GUARD__": lua(guard), "__AUTH__": lua(auth), "__RATE__": lua(rate), "__TIMEOUT__": lua(a.timeout_ms), "__VERSION__": __version__,
                 "__ENV__": lua(a.environment), "__GATEWAY__": lua(gateway), "__POLICY__": lua(a.policy_version), "__GUARD_PRIORITY__": str(gprio),
                 "__CONFIGURED__": lua([{"name": n, "enabled": True} for n in sorted(names) if n not in OURS]), "__CHAIN__": lua(chain),
                 "__CAPTURE__": lua("bounded" if a.show_prompts else "hash" if body else "none")}.items():
        event = event.replace(k, v)

    def plug(name: str, config: dict) -> dict:
        return {"id": str(uuid.uuid5(NS, f"{rid}/{name}")), "name": name, "instance_name": f"kong-eyes-{name}-{rid[:8]}", "route": {"id": rid},
                "tags": [TAG], "enabled": True, "config": config}
    plugins = [plug("pre-function", {"access": [pre]}), plug("post-function", {"access": [post]}),
               plug("http-log", {"http_endpoint": endpoint, "method": "POST", "content_type": "application/json", "timeout": 5000, "keepalive": 60000,
                                 "queue": {"max_batch_size": 50, "max_coalescing_delay": 1, "max_entries": 10000, "max_retry_time": 120},
                                 "custom_fields_by_lua": {"guardrail_observer": event}})]
    return {"info": info, "route": route, "gateway": gateway, "guardrail": guard, "auth": auth, "rate": rate, "chain": chain, "plugins": plugins, "already": mine,
            "others_on_route": sorted(n for n in names if n not in OURS)}


def _dbless_apply(kong: Kong, edit) -> None:
    try:
        import yaml
    except ImportError:
        raise SystemExit("this Kong is DB-less; changing it needs PyYAML (pip install pyyaml)") from None
    cfg = yaml.safe_load(kong.call("GET", "/config")["config"])
    edit(cfg)
    kong.call("POST", "/config?check_hash=0", {"config": yaml.safe_dump(cfg)})


def apply(kong: Kong, p: dict) -> None:
    rid = p["route"]["id"]
    if p["info"]["dbless"]:
        def edit(cfg):
            ids = {x["id"] for x in p["plugins"]}
            cfg["plugins"] = [x for x in cfg.get("plugins") or [] if x.get("id") not in ids] + [dict(x, route=rid) for x in p["plugins"]]
        _dbless_apply(kong, edit)
    else:
        for x in p["plugins"]:
            kong.call("PUT", f"/plugins/{x['id']}", x)


def remove(kong: Kong, route_name: str) -> list[str]:
    info = kong.info()
    route = kong.route(route_name)
    mine = [x for x in kong.pages(f"/routes/{route['id']}/plugins") if TAG in (x.get("tags") or [])]
    if not mine:
        return []
    if info["dbless"]:
        ids = {x["id"] for x in mine}
        _dbless_apply(kong, lambda cfg: cfg.__setitem__("plugins", [x for x in cfg.get("plugins") or [] if x.get("id") not in ids]))
    else:
        for x in mine:
            kong.call("DELETE", f"/plugins/{x['id']}")
    return [x["name"] for x in mine]


def connected(kong: Kong) -> list[dict]:
    routes = {r["id"]: r.get("name") or r["id"] for r in kong.pages("/routes")}
    out: dict[str, dict] = {}
    for x in kong.pages("/plugins"):
        if TAG in (x.get("tags") or []) and x.get("route"):
            r = out.setdefault(x["route"]["id"], {"route": routes.get(x["route"]["id"]), "plugins": [], "collector": None})
            r["plugins"].append(x["name"])
            if x["name"] == "http-log":
                u = urllib.parse.urlsplit(x["config"].get("http_endpoint") or "")
                r["collector"] = f"{u.scheme}://{u.hostname}{':' + str(u.port) if u.port else ''}{u.path}"
    return list(out.values())


def snippet(p: dict) -> str:
    """The same three plugins as declarative YAML, for a DB-less gateway's own config file."""
    rows = [dict({k: v for k, v in x.items() if k not in ("route", "id")}, route=p["route"].get("name") or p["route"]["id"]) for x in p["plugins"]]
    try:
        import yaml
    except ImportError:
        return json.dumps({"plugins": rows}, indent=2)
    return yaml.safe_dump({"plugins": rows}, sort_keys=False, width=200)
