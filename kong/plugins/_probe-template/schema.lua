local typedefs = require "kong.db.schema.typedefs"

return {
  name = "__NAME__",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { hash_body = { type = "boolean", default = true,
              description = "Hash the request body and response stream at this position so rewrites can be located." } },
          { max_hash_bytes = { type = "integer", default = 65536, between = { 0, 1048576 },
              description = "Request bodies larger than this are measured but not hashed." } },
          { emit_header = { type = "boolean", default = false,
              description = "Also append this probe's opaque code to a request header (crosses process boundaries; sent upstream)." } },
          { header_name = { type = "string", default = "X-Gro-Trail" } },
        },
      },
    },
  },
}
