local typedefs = require "kong.db.schema.typedefs"

-- guardrail-observer: passive evidence collector for AI guardrail evaluation.
-- It never changes bytes, headers or routing. It enriches the Kong serialized
-- log under `config.log_namespace` so any bundled log plugin (http-log, file-log,
-- tcp-log, opentelemetry...) can ship the evidence asynchronously.

return {
  name = "guardrail-observer",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- identity of the deployment, copied into every event (low cardinality)
          { environment = { type = "string", default = "dev",
              description = "Environment label copied into every event (dev/staging/prod)." } },
          { policy_version = { type = "string",
              description = "Operator-declared version of the guardrail policy under test. Copied verbatim; the observer also computes a config fingerprint." } },

          -- where to put the evidence in kong.log.serialize()
          { log_namespace = { type = "string", default = "guardrail_observer",
              match = "^[%w_]+$",
              description = "Top-level key added to the Kong log serializer output." } },

          -- authenticated test-runner metadata
          { runner_header = { type = "string", default = "X-Observer-Run",
              description = "Header carrying runner metadata: run_id;case_id;trial;sent_at_ms" } },
          { runner_signature_header = { type = "string", default = "X-Observer-Sig",
              description = "Header carrying hex HMAC-SHA256 of the runner header value." } },
          { runner_shared_secret = { type = "string", referenceable = true, encrypted = true,
              description = "Shared secret used to verify the runner signature. Unsigned or invalid metadata is recorded as untrusted, never dropped." } },
          { runner_max_skew_ms = { type = "integer", default = 300000, gt = 0,
              description = "Reject runner metadata whose sent_at_ms is further than this from the gateway clock (replay protection)." } },

          -- what to capture
          { capture_request_metadata = { type = "boolean", default = true } },
          { capture_body_mode = { type = "string", default = "hash",
              one_of = { "none", "hash", "bounded" },
              description = "none: sizes only. hash: sizes + sha256. bounded: hash + first max_capture_bytes of request/response (opt-in; synthetic traffic only unless you have authorization)." } },
          { max_capture_bytes = { type = "integer", default = 4096, between = { 64, 65536 } } },
          { max_chunks_recorded = { type = "integer", default = 512, between = { 1, 8192 },
              description = "Upper bound of per-chunk timeline entries kept for streaming responses." } },
          { phase_trace = { type = "boolean", default = true,
              description = "Record which plugins were collected for downstream phases and which AI filters executed (Kong 3.10 internal state; see docs/phase-trace.md)." } },
          { attribute_exits = { type = "boolean", default = true,
              description = "Attribute short-circuit responses to a plugin using Kong's request-debug trace (requests must carry X-Kong-Request-Debug: * + token) or, as a fallback, the AI filter chain. Records a gap when neither is available." } },
          { configured_plugins = { type = "boolean", default = true,
              description = "List the plugin instances configured for the matched route/service/global (cached per route)." } },
          { config_cache_ttl = { type = "integer", default = 30, between = { 1, 3600 } } },

          -- probe trail (see docs/probes.md)
          { probe_trail = { type = "boolean", default = true,
              description = "Start a probe trail on every request. With generated gro-probe-<priority> plugins on the route this gives per-guardrail latency, rewrite location and exit attribution on ordinary traffic (no request-debug header needed)." } },
          { trail_header = { type = "string",
              description = "Optional request header that carries the trail as opaque codes (off when unset). The head always overwrites any inbound value. The header is sent upstream." } },
          { guardrail_plugins = { type = "array", elements = { type = "string" }, default = {},
              description = "Names of your own guardrail plugins on this route. They are added to the built-in list for coverage checks and for the policy fingerprint." } },
          { guardrail_timeouts = { type = "map", keys = { type = "string" }, values = { type = "integer", gt = 0 },
              description = "Per-guardrail timeout in ms. A request that was allowed after spending about this long in a guardrail's gap is reported as a suspected fail-open." } },

          -- verdict adapters
          { adapters = { type = "array", default = { "ai-prompt-guard", "ctx-events", "response-header" },
              elements = { type = "string", one_of = { "ai-prompt-guard", "ctx-events", "response-header" } } } },
          { verdict_header = { type = "string", default = "X-Guardrail-Verdict",
              description = "Header name read by the response-header adapter (vendor guardrails that announce verdicts in headers)." } },
          { verdict_header_guardrail = { type = "string", default = "header-guardrail" } },
        },
      },
    },
  },
}
