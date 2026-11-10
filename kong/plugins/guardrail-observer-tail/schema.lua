local typedefs = require "kong.db.schema.typedefs"

return {
  name = "guardrail-observer-tail",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { log_namespace = { type = "string", default = "guardrail_observer", match = "^[%w_]+$" } },
          { capture_body_mode = { type = "string", default = "hash", one_of = { "none", "hash", "bounded" } } },
          { max_capture_bytes = { type = "integer", default = 4096, between = { 64, 65536 } } },
          { max_chunks_recorded = { type = "integer", default = 512, between = { 1, 8192 } } },
        },
      },
    },
  },
}
