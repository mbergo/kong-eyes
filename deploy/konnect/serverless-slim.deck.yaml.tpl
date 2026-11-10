# Konnect SERVERLESS gateway: custom plugins (installed or streamed) are not supported there, so this
# is the "slim" observer — bundled http-log + custom_fields_by_lua computing the ai-prompt-guard verdict
# from the same internal ctx the full plugin uses. Limits vs the full plugin: no request-debug phase trace,
# no stream timeline/hashes, no HMAC check of runner metadata (trusted on this TEST route only), no
# configured-plugins listing. Everything else (labels, joins, matrix, dashboards) is identical.
# Placeholders are filled by scripts/konnect-serverless-attach.sh; nothing secret lives in this template.
_format_version: "3.0"
_transform: true
_konnect:
  control_plane_name: __CP_NAME__

consumers:
  - username: guardrail-runner
    tags: [guardrail-observer]
    keyauth_credentials:
      - key: "__RUNNER_APIKEY__"
        tags: [guardrail-observer]

services:
  - name: guardrail-kimi
    url: __KIMI_BASE_URL__
    tags: [guardrail-observer]
    routes:
      - name: ai-kimi-konnect-route
        paths: [ /ai/kimi-konnect ]
        strip_path: true
        tags: [guardrail-observer]
        plugins:
          - name: key-auth
            tags: [guardrail-observer]
            config: { key_names: [ apikey ], hide_credentials: true }
          - name: ai-prompt-guard
            tags: [guardrail-observer]
            config:
              allow_all_conversation_history: true
              deny_patterns:
                - "(?i)ignore\\s+(all\\s+|any\\s+)?(previous|prior|above)\\s+instructions"
                - "(?i)(reveal|print|show|dump)\\s+(me\\s+)?(your|the)\\s+system\\s+prompt"
                - "(?i)\\b(ssn|social\\s+security\\s+number)s?\\b"
                - "(?i)\\b(developer|dan)\\s+mode\\b"
                - "(?i)exfiltrat(e|ion)\\s+.*(credential|secret|token)"
          - name: ai-proxy
            tags: [guardrail-observer]
            config:
              route_type: llm/v1/chat
              auth: { header_name: Authorization, header_value: "Bearer __KIMI_API_KEY__" }
              logging: { log_statistics: true, log_payloads: false }
              model:
                provider: openai
                name: __KIMI_MODEL__
                options:
                  upstream_url: __KIMI_BASE_URL__/chat/completions
                  max_tokens: 512
          - name: http-log
            tags: [guardrail-observer]
            config:
              http_endpoint: "__INGEST_ENDPOINT__"
              method: POST
              content_type: application/json
              timeout: 10000
              keepalive: 60000
              queue: { max_batch_size: 20, max_coalescing_delay: 1, max_entries: 10000, max_retry_time: 300 }
              custom_fields_by_lua:
                guardrail_observer: |
                  return (function()
                    local ctx = ngx.ctx
                    local ex = ctx.ai_executed_filters or {}
                    local ns = ctx.ai_namespaced_ctx or {}
                    -- filter name: "guard-prompt" on 3.10, "guard-request" on 3.15 (verified on Konnect serverless 3.15.0.6)
                    local fname = (ex["guard-request"] ~= nil or ns["guard-request"] ~= nil) and "guard-request" or "guard-prompt"
                    local gp = ns[fname]
                    local executed = ex[fname] and true or false
                    local guarded = (type(gp) == "table" and gp.guarded == true) or false
                    local status = kong.response.get_status()
                    local source = kong.response.get_source()
                    local verdict, reason, action, enforced_by, vstatus
                    if not executed then verdict, reason = "not_run", fname .. " filter not executed"
                    elseif guarded then verdict, reason, action = "allow", fname .. " set guarded=true", "none"
                    elseif ex["normalize-request"] and source ~= "exit" then
                      -- the guard returned and the chain continued into ai-proxy: an allow by construction (3.15 sets no flag)
                      verdict, reason, action = "allow", fname .. " executed and the request proceeded to ai-proxy (no guarded flag on this version)", "none"
                    elseif source == "exit" and status == 400 and not ex["normalize-request"] then
                      verdict, reason, action, enforced_by, vstatus = "deny", "guard-prompt executed without guarded flag; exit 400 before ai-proxy normalized the request", "block", "ai-prompt-guard", 400
                    elseif source == "exit" and status == 500 then verdict, reason, action, enforced_by, vstatus = "error", "guard-prompt exited 500", "block", "ai-prompt-guard", 500
                    else verdict, reason = "unknown", "executed without guarded flag and no attributable exit" end
                    local raw = kong.request.get_header("x-observer-run")
                    local run_id, case_id, trial, sent
                    if raw then run_id, case_id, trial, sent = raw:match("^([^;]+);([^;]+);([^;]+);(%d+)$") end
                    ngx.update_time()
                    local now = math.floor(ngx.now() * 1000)
                    local start = math.floor(ngx.req.start_time() * 1000)
                    local filters = {}
                    for k, v in pairs(ex) do if v then filters[#filters + 1] = k end end
                    table.sort(filters)
                    local rid = ngx.var.kong_request_id or ngx.var.request_id or ""
                    local route = kong.router.get_route()
                    local service = kong.router.get_service()
                    local consumer = kong.client.get_consumer()
                    local g = ns._global or {}
                    local model
                    local nr = ns["normalize-request"]
                    if type(nr) == "table" and type(nr.model) == "table" then model = { provider = nr.model.provider, name = nr.model.name } end
                    return {
                      schema_version = "1.0", event_type = "kong_observation", observer_version = "0.1.0-slim",
                      observer_mode = "konnect-serverless-slim (http-log custom_fields_by_lua)",
                      kong_version = kong.version, event_id = ngx.md5(rid .. "|" .. (route and route.id or "") .. "|" .. start),
                      request_id = rid, started_at_ms = start, ended_at_ms = now, duration_ms = now - start,
                      environment = "konnect-serverless", policy_version = "pg-v1",
                      route = route and { id = route.id, name = route.name } or nil,
                      service = service and { id = service.id, name = service.name } or nil,
                      consumer = consumer and { id = consumer.id, username = consumer.username } or nil,
                      runner = { present = raw ~= nil, trusted = raw ~= nil, reason = raw and "slim-mode:no-signature-check (test route only)" or "no_runner_header",
                                 run_id = run_id, case_id = case_id, trial = tonumber(trial), sent_at_ms = tonumber(sent),
                                 skew_ms = sent and (start - tonumber(sent)) or nil },
                      request = { method = kong.request.get_method(), path = kong.request.get_path(), content_length = tonumber(kong.request.get_header("content-length")),
                                  accept_encoding = kong.request.get_header("accept-encoding") },
                      response = { status = status, source = source, proxied = ctx.KONG_PROXIED and true or false, upstream_status = ngx.var.upstream_status,
                                   content_type = kong.response.get_header("content-type"), content_encoding = kong.response.get_header("content-encoding") },
                      exit = (source == "exit") and { status = status, plugin_name = (executed and not guarded) and "ai-prompt-guard" or nil,
                                                      attribution = (executed and not guarded) and "ai-filter-chain" or "unavailable", confidence = (executed and not guarded) and "medium" or "none" } or nil,
                      guardrails = { { guardrail = "ai-prompt-guard", adapter = "ai-prompt-guard@1-slim", stage = "input", verdict = verdict, mode = "block",
                                       action = action, enforced_by = enforced_by, status = vstatus, provenance = "kong-internal-ctx", supported = true, reason = reason,
                                       evidence = { executed = executed, guarded_flag = guarded, filter = fname, continued_to_ai_proxy = ex["normalize-request"] and true or false } } },
                      ai = { executed_filters = filters, stream_mode = g.stream_mode and true or false, model = model,
                             response_body_bytes = type(g.response_body) == "string" and #g.response_body or nil },
                      upstream = { kong_proxied = ctx.KONG_PROXIED and true or false, upstream_status = ngx.var.upstream_status,
                                   ai_proxy_request_normalized = ex["normalize-request"] and true or false,
                                   ai_response_body_present = g.response_body ~= nil, latencies_ms = { kong = ctx.KONG_PROXY_LATENCY or ctx.KONG_RESPONSE_LATENCY, proxy = ctx.KONG_WAITING_TIME } },
                      capture = { body_mode = "none", metadata_only = true },
                      gaps = { "slim-mode:no-phase-trace", "slim-mode:no-stream-timeline", "slim-mode:unsigned-runner-metadata" },
                    }
                  end)()
