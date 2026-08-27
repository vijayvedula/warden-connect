-- The FFI binding to libwc_kong.
--
-- This file is the third statement of the same ABI: Rust declares it, include/wc_kong.h
-- describes it, and this cdef restates it for LuaJIT. Three statements can disagree, and a
-- disagreement here is not a crash — it is Lua reading a struct field at the wrong offset and
-- acting on a verdict that means something else. spec/abi_spec.lua compares this cdef against
-- the header, so a divergence fails the suite rather than production.
--
-- Nothing in this file makes a policy decision. Every verdict comes from the library.

local ffi = require("ffi")

ffi.cdef([[
typedef struct wc_handle wc_handle;
typedef struct wc_stream wc_stream;

typedef struct {
  uint8_t *ptr;
  size_t   len;
  int      code;
} wc_out;

wc_handle  *wc_init(const uint8_t *cfg_json, size_t len, wc_out *err);
void        wc_free(wc_handle *h);
int         wc_contract_count(const wc_handle *h);
const char *wc_version(void);

wc_stream  *wc_stream_new(const wc_handle *h, const uint8_t *peer_json, size_t len, wc_out *err);
void        wc_stream_free(wc_stream *s);

int wc_on_request(wc_stream *s, const uint8_t *body, size_t len, wc_out *out);
int wc_on_response_headers(wc_stream *s, const uint8_t *ctype, size_t len, wc_out *out);
int wc_on_response_body(wc_stream *s, const uint8_t *body, size_t len, wc_out *out);
int wc_refusal(int code, const uint8_t *detail, size_t len, wc_out *out);

void wc_out_free(wc_out *out);
]])

local M = {}

-- Verdicts, mirrored from wc_kong.h. Compared against it by the spec.
M.FORWARD    = 0
M.REFUSE     = 1
M.BUFFER     = 2
M.SKIP       = 3
M.PASS       = 4
M.REWRITE    = 5
M.ERR_PANIC  = -1
M.ERR_BADARG = -2
M.ERR_CONFIG = -3

--- Load the library. `path` may be absolute, or a name for the loader's search path.
function M.load(path)
  local ok, lib = pcall(ffi.load, path or "wc_kong")
  if not ok then
    return nil, "cannot load " .. tostring(path or "wc_kong") .. ": " .. tostring(lib)
  end
  M.C = lib
  return lib
end

--- Take ownership of whatever a call left in `out`, and release it.
--
-- A fresh wc_out per call rather than one per worker: a shared buffer would be correct only as
-- long as nothing yields between filling it and reading it, and `kong.response.exit` yields.
-- Reusing it would make this a bug that appears under concurrency and never in a test.
local function take(out)
  local body, code = nil, out[0].code
  if out[0].ptr ~= nil and out[0].len > 0 then
    body = ffi.string(out[0].ptr, out[0].len)
  end
  M.C.wc_out_free(out)
  return body, code
end
M.take = take

--- A fresh out parameter.
function M.out()
  return ffi.new("wc_out[1]")
end

--- Build the process-wide handle. Returns handle, or nil plus the reason.
function M.init(cfg_json)
  local out = M.out()
  local h = M.C.wc_init(cfg_json, #cfg_json, out)
  local why = take(out)
  if h == nil then
    return nil, why or "wc_init failed without a reason, which is itself a bug"
  end
  return h
end

--- Open a stream. Returns stream, or nil plus the reason.
--
-- The finaliser is a backstop, not the plan: a stream holds this contract's concurrency slot
-- until it is dropped, so waiting for the collector would let a leaked stream consume a ceiling.
-- The handler frees it in `log`; this catches the paths where `log` never runs.
function M.stream(h, peer_json)
  local out = M.out()
  local s = M.C.wc_stream_new(h, peer_json, #peer_json, out)
  local why = take(out)
  if s == nil then
    return nil, why or "wc_stream_new failed without a reason"
  end
  return ffi.gc(s, M.C.wc_stream_free)
end

--- Free a stream now, cancelling its finaliser so it is not freed twice.
function M.stream_free(s)
  if s == nil then
    return
  end
  ffi.gc(s, nil)
  M.C.wc_stream_free(s)
end

--- The refusal frame for a code the plugin has to answer with on its own.
function M.refusal(code, detail)
  local out = M.out()
  M.C.wc_refusal(code, detail, #detail, out)
  local body, c = take(out)
  return body, c
end

function M.on_request(s, body)
  local out = M.out()
  local v = M.C.wc_on_request(s, body, #body, out)
  local frame, code = take(out)
  return v, frame, code
end

function M.on_response_headers(s, ctype)
  local out = M.out()
  local v = M.C.wc_on_response_headers(s, ctype, #ctype, out)
  local frame, code = take(out)
  return v, frame, code
end

function M.on_response_body(s, body)
  local out = M.out()
  local v = M.C.wc_on_response_body(s, body, #body, out)
  local frame, code = take(out)
  return v, frame, code
end

return M
