local typedefs = require "kong.db.schema.typedefs"

return {
  name = "fixture-output-guard",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { mode = { type = "string", default = "block", one_of = { "block", "detect", "disabled" } } },
          { deny_markers = { type = "array", elements = { type = "string" }, default = { "[[VIOLATION]]" } } },
          { enforce_delay_chunks = { type = "integer", default = 0, between = { 0, 1000 },
              description = "Streaming only: abort this many chunks AFTER the chunk containing the marker. 0 = replace the offending chunk itself (no leak). >0 seeds an enforcement failure." } },
          { max_inspect_bytes = { type = "integer", default = 1048576, between = { 1024, 16777216 } } },
          { refusal_message = { type = "string", default = "response withheld by policy (fixture)" } },
        },
      },
    },
  },
}
