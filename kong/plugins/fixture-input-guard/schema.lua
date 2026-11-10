local typedefs = require "kong.db.schema.typedefs"

return {
  name = "fixture-input-guard",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { mode = { type = "string", default = "block", one_of = { "block", "detect", "disabled" } } },
          { deny_markers = { type = "array", elements = { type = "string" }, default = { "[[VIOLATION]]" } } },
          { decoy_markers = { type = "array", elements = { type = "string" }, default = { "[[DECOY]]" },
              description = "Benign markers the fixture deliberately blocks (seeded false positives)." } },
          { no_verdict_markers = { type = "array", elements = { type = "string" }, default = { "[[FIXTURE_NO_VERDICT]]" } } },
          { error_markers = { type = "array", elements = { type = "string" }, default = { "[[FIXTURE_ERROR]]" } } },
          { slow_markers = { type = "array", elements = { type = "string" }, default = { "[[FIXTURE_SLOW]]" },
              description = "Markers that make the fixture wait slow_ms and then allow silently (seeded fail-open)." } },
          { slow_ms = { type = "integer", default = 400, between = { 1, 30000 } } },
          { block_status = { type = "integer", default = 403, between = { 400, 599 } } },
          { refusal_message = { type = "string", default = "request blocked by policy (fixture)" } },
        },
      },
    },
  },
}
