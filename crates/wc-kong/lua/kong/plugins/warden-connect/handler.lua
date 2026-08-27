-- warden-connect as a Kong plugin.
--
-- The plugin gathers evidence and moves bytes. Every verdict comes from libwc_kong, which is
-- the same decision code the Envoy filter runs — see crates/wc-gateway.
--
-- # Fail closed
--
-- Any negative return, any missing handle, any error loading the library: refuse. There is no
-- path through this file that forwards a frame the library did not approve. The one thing the
-- plugin says on its own is the refusal frame for a caught panic, and even that is built by
-- the library so it cannot diverge from a real verdict.

local cjson = require("cjson.safe")
local wc = require("kong.plugins.warden-connect.wcffi")

local WardenConnect = {
  -- Ahead of rate limiting and the proxy, behind authentication plugins: nothing downstream
  -- should do work for a call that is about to be refused. Identity here comes from the
  -- transport rather than from an auth plugin, so this does not depend on one running first.
  PRIORITY = 1000,
  VERSION = "0.1.1",
}

-- One handle per worker. Kong instantiates the handler once per worker, so this upvalue is
-- worker-local by construction.
local handle = nil
local init_error = nil

local CONFIG_KEYS = {
  "contracts", "routes", "identity", "mesh_origin", "issuer_pub", "jwks_file",
  "jwks_url", "kid", "mediator_id", "issuer_id", "mode", "pin_max_age",
  "max_stale", "any_zone", "no_pin",
}

local function config_json(conf)
  local t = {}
  for _, k in ipairs(CONFIG_KEYS) do
    if conf[k] ~= nil then
      t[k] = conf[k]
    end
  end
  return cjson.encode(t)
end

--- Refuse, with a frame the library built.
local function refuse(frame, code)
  kong.log.notice("warden-connect: refused, WC-", code or 0)
  -- 200 with a JSON-RPC error, not an HTTP error: an MCP client surfaces a transport failure
  -- as "the server is broken" and a JSON-RPC error as a refused call, and the agent has to be
  -- able to tell those apart.
  return kong.response.exit(200, frame, { ["Content-Type"] = "application/json" })
end

--- Refuse when the library could not give us a frame — a caught panic, or no handle at all.
local function refuse_bare(code, detail)
  kong.log.err("warden-connect: ", detail)
  local frame = handle and select(1, wc.refusal(code, detail)) or nil
  if not frame then
    -- The library is unusable, so there is no frame to send and no honest JSON-RPC answer.
    -- 503 says "this hop is broken", which is true, and is not mistakable for a refusal.
    return kong.response.exit(503, "warden-connect is not able to decide this call\n")
  end
  return refuse(frame, code)
end

function WardenConnect:init_worker()
  -- Nothing here: the configuration arrives per plugin instance, not at worker start.
end

local function lib_version()
  return require("ffi").string(wc.C.wc_version())
end

--- Build the handle on first use, once per worker.
local function ensure(conf)
  if handle then
    return handle
  end
  if init_error then
    return nil
  end
  local lib, err = wc.load(conf.library_path)
  if not lib then
    init_error = err
    return nil
  end
  local h, why = wc.init(config_json(conf))
  if not h then
    init_error = why
    return nil
  end
  handle = h
  kong.log.notice("warden-connect ", lib_version(), ": ",
                  tonumber(wc.C.wc_contract_count(h)), " contract(s) verified")
  return handle
end

--- What the plugin observed about the caller. Never what it was told.
local function peer_json(conf)
  local service = kong.router.get_service()
  local route = kong.router.get_route()
  local p = {
    service = service and service.name or nil,
    route = route and route.name or nil,
    remote = ngx.var.remote_addr,
  }
  if conf.identity == "tls" then
    p.tls_verify = ngx.var.ssl_client_verify
    p.cert_pem = ngx.var.ssl_client_raw_cert
  else
    p.xfcc = kong.request.get_header("x-forwarded-client-cert")
    -- A unix listener reports an empty remote_addr; the socket path is the origin that
    -- `mesh_origin` is compared against.
    if not p.remote or p.remote == "" then
      p.remote = "unix:" .. (ngx.var.unix_socket_path or "")
    end
  end
  return cjson.encode(p)
end

function WardenConnect:access(conf)
  local h = ensure(conf)
  if not h then
    return refuse_bare(8004, "not started: " .. tostring(init_error))
  end

  local s, why = wc.stream(h, peer_json(conf))
  if not s then
    return refuse_bare(8004, "no stream: " .. tostring(why))
  end
  kong.ctx.plugin.stream = s

  -- nginx returns nil once the body exceeds client_body_buffer_size. That is not an empty
  -- body, and treating it as one would forward exactly the largest requests unchecked. The
  -- library refuses on an empty slice; this passes it through rather than deciding here.
  local body = kong.request.get_raw_body() or ""

  local verdict, frame, code = wc.on_request(s, body)
  if verdict == wc.REFUSE then
    return refuse(frame, code)
  end
  if verdict < 0 then
    return refuse_bare(8004, "the filter returned " .. tostring(verdict))
  end
  if verdict == wc.BUFFER then
    -- Kong decides buffering before it proxies, which is why the library answers this at the
    -- request phase: by the response phase it would be too late to ask.
    kong.service.request.enable_buffering()
    kong.ctx.plugin.buffered = true
  end
end

function WardenConnect:response(conf) -- luacheck: no unused args
  local s = kong.ctx.plugin.stream
  if not s or not kong.ctx.plugin.buffered then
    -- Not a catalogue. The verdict was taken on the request and the body is not inspected;
    -- Kong only runs this phase when some plugin enabled buffering, so this is the belt.
    return
  end

  local ctype = kong.service.response.get_header("Content-Type") or ""
  local verdict, frame, code = wc.on_response_headers(s, ctype)
  if verdict == wc.REFUSE then
    return refuse(frame, code)
  end
  if verdict < 0 then
    return refuse_bare(8004, "the filter returned " .. tostring(verdict))
  end
  if verdict == wc.SKIP then
    return
  end

  local body = kong.service.response.get_raw_body() or ""
  local action, out, ocode = wc.on_response_body(s, body)
  if action == wc.REFUSE then
    return refuse(out, ocode)
  end
  if action < 0 then
    return refuse_bare(8004, "the filter returned " .. tostring(action))
  end
  if action == wc.REWRITE then
    -- The upstream's content-length describes the body we are replacing. Leaving it makes the
    -- filtered catalogue unparseable at the client — this cost the Envoy path a debugging
    -- session, so it is removed here too.
    kong.response.set_header("Content-Length", #out)
    kong.response.set_raw_body(out)
  end
end

function WardenConnect:log(conf) -- luacheck: no unused args
  -- Deterministic release. The stream holds this contract's concurrency slot, so leaving it to
  -- the collector would let a finished request keep consuming a ceiling.
  local s = kong.ctx.plugin.stream
  if s then
    wc.stream_free(s)
    kong.ctx.plugin.stream = nil
  end
end

return WardenConnect
