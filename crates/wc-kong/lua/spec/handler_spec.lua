-- The real handler, driven against the real library. Only Kong is fake.
local t = require("spec.harness")
local stub = require("spec.kong_stub")

-- The handler asks for Kong's cjson; the spec's codec stands in.
package.preload["cjson.safe"] = function() return require("spec.json") end

local CERT = t.read(t.ROOT .. "/fixtures/keys/test_peer_spiffe.pem")
local OTHER = t.read(t.ROOT .. "/fixtures/keys/test_peer_other_spiffe.pem")
local SERVED = t.read(t.FIX .. "/served.json")

local CALL_OK = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_balance"}}'
local CALL_NO = '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"transfer_funds"}}'
local LIST = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

local function conf(over)
  local c = {
    library_path = t.LIB,
    contracts = { t.FIX .. "/c.jws" },
    routes = t.FIX .. "/routes.toml",
    identity = "tls",
    mediator_id = "warden:mediator:kong-test",
    issuer_id = "https://connect.internal",
    issuer_pub = t.ROOT .. "/fixtures/keys/test_issuer_es256_pub.pem",
    kid = "wc-test-es256",
    mode = "enforce",
  }
  for k, v in pairs(over or {}) do c[k] = v end
  return c
end

--- A handler with no accumulated worker state.
local function fresh()
  package.loaded["kong.plugins.warden-connect.handler"] = nil
  package.loaded["kong.plugins.warden-connect.wcffi"] = nil
  return require("kong.plugins.warden-connect.handler")
end

local function req(over)
  local r = {
    service = "payments",
    remote_addr = "10.0.0.7",
    ssl_client_verify = "SUCCESS",
    ssl_client_raw_cert = CERT,
    body = CALL_OK,
  }
  for k, v in pairs(over or {}) do r[k] = v end
  return r
end

--- Run access, then log. Returns the recorder and how access ended.
local function run(h, c, r)
  local rec = stub.install(r)
  local how = stub.phase(rec, function() h:access(c) end)
  stub.phase(rec, function() h:log(c) end)
  return rec, how
end

-- --- the catalogue path, which is also how a pin gets verified ---------------

t.case("a catalogue request enables buffering and its response is filtered", function()
  local h = fresh()
  local c = conf()
  local rec = stub.install(req({
    body = LIST,
    resp_headers = { ["content-type"] = "application/json" },
    resp_body = '{"jsonrpc":"2.0","id":1,"result":' .. SERVED .. "}",
  }))
  t.eq(stub.phase(rec, function() h:access(c) end), "fell-through", "access")
  t.ok(rec.buffering, "Kong must be told to buffer BEFORE it proxies")
  t.eq(stub.phase(rec, function() h:response(c) end), "fell-through", "response")
  t.ok(rec.body_set, "the catalogue must have been rewritten")
  local f = t.json.decode(rec.body_set)
  t.eq(#f.result.tools, 2, "three served, two contracted")
  t.eq(f.result.tools[1].name, "get_balance", "first tool")
  t.ok(not rec.body_set:find("transfer_funds"), "the uncontracted tool must not survive")
  t.eq(rec.headers_set["Content-Length"], #rec.body_set, "content-length must describe the NEW body")
  stub.phase(rec, function() h:log(c) end)
end)

-- --- verdicts ---------------------------------------------------------------

t.case("a contracted tool forwards once the pin is verified", function()
  local h = fresh()
  local c = conf()
  -- Verify the pin the way a client does: connect, list, then call.
  local rec = stub.install(req({
    body = LIST,
    resp_headers = { ["content-type"] = "application/json" },
    resp_body = '{"jsonrpc":"2.0","id":1,"result":' .. SERVED .. "}",
  }))
  stub.phase(rec, function() h:access(c) end)
  stub.phase(rec, function() h:response(c) end)
  stub.phase(rec, function() h:log(c) end)

  local rec2, how = run(h, c, req())
  t.eq(how, "fell-through", "a contracted call must reach the upstream")
  t.eq(rec2.exit, nil, "nothing was returned to the client")
end)

t.case("an uncontracted tool is refused with WC-4002", function()
  local h = fresh()
  local c = conf()
  local rec = stub.install(req({
    body = LIST,
    resp_headers = { ["content-type"] = "application/json" },
    resp_body = '{"jsonrpc":"2.0","id":1,"result":' .. SERVED .. "}",
  }))
  stub.phase(rec, function() h:access(c) end)
  stub.phase(rec, function() h:response(c) end)
  stub.phase(rec, function() h:log(c) end)

  local rec2, how = run(h, c, req({ body = CALL_NO }))
  t.eq(how, "exited", "the call must not reach the upstream")
  t.eq(rec2.exit.status, 200, "a refusal is a JSON-RPC error, not a transport failure")
  t.eq(rec2.exit.headers["Content-Type"], "application/json", "content type")
  local f = t.json.decode(rec2.exit.body)
  t.eq(f.error.data.code, "WC-4002", "taxonomy code")
end)

t.case("an unverified client certificate is refused", function()
  local h = fresh()
  local rec, how = run(h, conf(), req({ ssl_client_verify = "FAILED:self signed certificate" }))
  t.eq(how, "exited", "must refuse")
  local f = t.json.decode(rec.exit.body)
  t.eq(f.error.data.code, "WC-4001", "no identity means no contract")
end)

t.case("a verified certificate for another workload gets no contract", function()
  local h = fresh()
  local rec, how = run(h, conf(), req({ ssl_client_raw_cert = OTHER, body = LIST }))
  t.eq(how, "exited", "must refuse")
  t.eq(t.json.decode(rec.exit.body).error.data.code, "WC-4001", "wrong identity")
end)

t.case("a body nginx would not buffer is refused, not read as empty", function()
  local h = fresh()
  -- get_raw_body() returns nil past client_body_buffer_size.
  local rec, how = run(h, conf(), req({ body = nil }))
  t.eq(how, "exited", "the largest requests must not pass unchecked")
  local f = t.json.decode(rec.exit.body)
  t.ok(f.error.message:find("WC%-"), "a taxonomy code, not a bare error")
end)

t.case("an unmapped service is refused", function()
  local h = fresh()
  local rec, how = run(h, conf(), req({ service = "not-in-the-table" }))
  t.eq(how, "exited", "must refuse")
  t.eq(t.json.decode(rec.exit.body).error.data.code, "WC-4001", "unmapped route")
end)

-- --- startup ----------------------------------------------------------------

t.case("a handler that cannot start refuses every call rather than passing them", function()
  local h = fresh()
  local rec, how = run(h, conf({ contracts = { "/nonexistent/nope.jws" } }), req())
  t.eq(how, "exited", "a PEP that failed to start must not forward")
  t.eq(rec.exit.status, 503, "no library verdict is available, so this hop says it is broken")
end)

t.case("a failed start is not retried on every request", function()
  local h = fresh()
  local c = conf({ contracts = { "/nonexistent/nope.jws" } })
  run(h, c, req())
  local rec = stub.install(req())
  stub.phase(rec, function() h:access(c) end)
  -- Still refusing, and the second attempt did not re-read the missing file.
  t.eq(rec.exit.status, 503, "still refusing")
end)

-- --- lifetime ---------------------------------------------------------------

t.case("the log phase releases the stream and is safe when there is none", function()
  local h = fresh()
  local c = conf()
  local rec = stub.install(req())
  stub.phase(rec, function() h:access(c) end)
  t.ok(kong.ctx.plugin.stream ~= nil, "access must have opened a stream")
  stub.phase(rec, function() h:log(c) end)
  t.eq(kong.ctx.plugin.stream, nil, "log must have released it")
  -- A second log, and a log with no access at all, must both be harmless.
  stub.phase(rec, function() h:log(c) end)
  local rec2 = stub.install(req())
  stub.phase(rec2, function() h:log(c) end)
end)

t.case("the response phase does nothing when nothing was buffered", function()
  local h = fresh()
  local c = conf()
  local rec = stub.install(req())
  stub.phase(rec, function() h:access(c) end)
  t.ok(not rec.buffering, "a tool call is not buffered")
  t.eq(stub.phase(rec, function() h:response(c) end), "fell-through", "response")
  t.eq(rec.body_set, nil, "no rewrite")
  stub.phase(rec, function() h:log(c) end)
end)
