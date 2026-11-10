package = "kong-plugin-guardrail-observer"
version = "0.1.0-1"

source = {
  url = "git+https://github.com/mbergo/kong-original.git",
  dir = "kong-original/guardrail-observer/kong",
}

description = {
  summary = "Passive evidence collector for AI guardrail evaluation on Kong Gateway 3.10 (observer + tail + synthetic fixture guardrails)",
  license = "Apache 2.0",
}

dependencies = {
  "lua ~> 5.1",
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.guardrail-observer.handler"]      = "plugins/guardrail-observer/handler.lua",
    ["kong.plugins.guardrail-observer.schema"]       = "plugins/guardrail-observer/schema.lua",
    ["kong.plugins.guardrail-observer.trace"]        = "plugins/guardrail-observer/trace.lua",
    ["kong.plugins.guardrail-observer.adapters"]     = "plugins/guardrail-observer/adapters.lua",
    ["kong.plugins.guardrail-observer.runner_auth"]  = "plugins/guardrail-observer/runner_auth.lua",
    ["kong.plugins.guardrail-observer.trail"]        = "plugins/guardrail-observer/trail.lua",
    -- default probe set (regenerate with scripts/gen-probes.sh for your own guardrail priorities)
    ["kong.plugins.gro-probe-773.handler"]           = "plugins/gro-probe-773/handler.lua",
    ["kong.plugins.gro-probe-773.schema"]            = "plugins/gro-probe-773/schema.lua",
    ["kong.plugins.gro-probe-765.handler"]           = "plugins/gro-probe-765/handler.lua",
    ["kong.plugins.gro-probe-765.schema"]            = "plugins/gro-probe-765/schema.lua",
    ["kong.plugins.gro-probe-750.handler"]           = "plugins/gro-probe-750/handler.lua",
    ["kong.plugins.gro-probe-750.schema"]            = "plugins/gro-probe-750/schema.lua",
    ["kong.plugins.guardrail-observer-tail.handler"] = "plugins/guardrail-observer-tail/handler.lua",
    ["kong.plugins.guardrail-observer-tail.schema"]  = "plugins/guardrail-observer-tail/schema.lua",
    ["kong.plugins.fixture-input-guard.handler"]     = "plugins/fixture-input-guard/handler.lua",
    ["kong.plugins.fixture-input-guard.schema"]      = "plugins/fixture-input-guard/schema.lua",
    ["kong.plugins.fixture-output-guard.handler"]    = "plugins/fixture-output-guard/handler.lua",
    ["kong.plugins.fixture-output-guard.schema"]     = "plugins/fixture-output-guard/schema.lua",
  },
}
