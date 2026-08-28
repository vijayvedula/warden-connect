-- Plugin configuration.
--
-- Every field here is passed straight to wc_init as JSON and validated there. The typedefs
-- below catch a shape error at `kong config` time rather than at worker start; they are not a
-- second validator, and nothing is defaulted here that the library does not default.
local typedefs = require("kong.db.schema.typedefs")

return {
  name = "warden-connect",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- Where the library is. Absolute path, or a name for the dynamic loader.
          { library_path = { type = "string", default = "wc_kong" } },

          { contracts = { type = "array", required = true, elements = { type = "string" } } },
          { routes = { type = "string", required = true } },

          -- No default. Both sources are legitimate, they have different threat models, and a
          -- PEP that guessed would be one whose identity source nobody can state.
          { identity = { type = "string", required = true, one_of = { "tls", "xfcc" } } },
          { mesh_origin = { type = "string" } },

          { issuer_pub = { type = "string" } },
          { jwks_file = { type = "string" } },
          { jwks_url = { type = "string" } },
          { kid = { type = "string" } },

          { mediator_id = { type = "string", required = true } },
          { issuer_id = { type = "string", required = true } },

          { mode = { type = "string", default = "enforce", one_of = { "enforce", "observe" } } },
          { pin_max_age = { type = "number", default = 0 } },
          { max_stale = { type = "number", default = 0 } },
          { any_zone = { type = "boolean", default = false } },

          -- Required once any loaded contract bounds a rate or concurrency ceiling: those
          -- counters are per worker, so the ceiling in force is the configured one times
          -- worker_processes. "node" is refused by the library as not built, rather than
          -- accepted as a value that changes nothing.
          { ceiling_scope = { type = "string", one_of = { "worker", "node" } } },

          -- Where the decision trail is appended. %w is replaced with the worker id and is
          -- REQUIRED when worker_processes > 1: each worker keeps its own hash chain, and two
          -- appending to one file interleave into a trail that never verifies.
          { evidence_path = { type = "string" } },
          { evidence_delivery = { type = "string", one_of = { "blocking", "fail-safe" } } },

          -- Gate 8 is not optional. This exists for a staged rollout and nothing else, so it
          -- is spelled out rather than looking like a tuning knob.
          { no_pin = { type = "boolean", default = false } },
        },
      },
    },
  },
}
