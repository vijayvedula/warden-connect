-- The Kong and nginx surface the handler touches, and nothing more.
--
-- Everything the plugin did is recorded so a spec can assert on it. The point is to drive the
-- REAL handler against the REAL library: only the host is fake.
local json = require("spec.json")

local M = {}

--- Build a fresh environment. `req` describes the request the plugin will see.
function M.install(req)
  local rec = {
    exit = nil,          -- { status, body, headers }
    buffering = false,
    headers_set = {},
    body_set = nil,
    logs = {},
  }

  -- `kong.response.exit` does not return in Kong; it unwinds. Modelled with an error carrying
  -- a sentinel, so a spec can tell "the handler refused" from "the handler fell through".
  local EXIT = {}
  rec.EXIT = EXIT

  _G.ngx = {
    var = {
      remote_addr = req.remote_addr,
      ssl_client_verify = req.ssl_client_verify,
      ssl_client_raw_cert = req.ssl_client_raw_cert,
      unix_socket_path = req.unix_socket_path,
    },
  }

  _G.kong = {
    ctx = { plugin = {} },
    log = {
      err = function(...) rec.logs[#rec.logs + 1] = { "err", ... } end,
      warn = function(...) rec.logs[#rec.logs + 1] = { "warn", ... } end,
      notice = function(...) rec.logs[#rec.logs + 1] = { "notice", ... } end,
    },
    router = {
      get_service = function() return req.service and { name = req.service } or nil end,
      get_route = function() return req.route and { name = req.route } or nil end,
    },
    request = {
      get_raw_body = function() return req.body end,
      get_header = function(n) return (req.headers or {})[n:lower()] end,
    },
    response = {
      exit = function(status, body, headers)
        rec.exit = { status = status, body = body, headers = headers }
        error(EXIT)
      end,
      set_header = function(k, v) rec.headers_set[k] = v end,
      set_raw_body = function(b) rec.body_set = b end,
    },
    service = {
      request = {
        enable_buffering = function() rec.buffering = true end,
      },
      response = {
        get_header = function(n) return (req.resp_headers or {})[n:lower()] end,
        get_raw_body = function() return req.resp_body end,
      },
    },
  }
  return rec
end

--- Run one plugin phase, catching the unwind `kong.response.exit` performs.
function M.phase(rec, fn, ...)
  local ok, err = pcall(fn, ...)
  if ok then
    return "fell-through"
  end
  if err == rec.EXIT then
    return "exited"
  end
  error(err)
end

M.json = json
return M
