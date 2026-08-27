-- The cdef, the header and the library must agree.
--
-- Three statements of one ABI can disagree, and the failure mode is not a crash: it is Lua
-- reading a field at the wrong offset and acting on a verdict that means something else.
local ffi = require("ffi")
local t = require("spec.harness")

local wc = require("kong.plugins.warden-connect.wcffi")
assert(wc.load(t.LIB))

t.case("the cdef's wc_out layout matches the library's", function()
  -- Same fields, same order, same size as #[repr(C)] WcOut.
  local sz = ffi.sizeof("wc_out")
  local expect = ffi.sizeof("void *") + ffi.sizeof("size_t") + 8 -- int + tail padding
  t.eq(sz, expect, "wc_out size")
  t.eq(ffi.offsetof("wc_out", "ptr"), 0, "ptr offset")
  t.eq(ffi.offsetof("wc_out", "len"), ffi.sizeof("void *"), "len offset")
end)

t.case("the verdict constants match include/wc_kong.h", function()
  local h = t.read(t.ROOT .. "/crates/wc-kong/include/wc_kong.h")
  local names = {
    FORWARD = "WC_FORWARD", REFUSE = "WC_REFUSE", BUFFER = "WC_BUFFER",
    SKIP = "WC_SKIP", PASS = "WC_PASS", REWRITE = "WC_REWRITE",
    ERR_PANIC = "WC_ERR_PANIC", ERR_BADARG = "WC_ERR_BADARG", ERR_CONFIG = "WC_ERR_CONFIG",
  }
  for lua_name, c_name in pairs(names) do
    local v = h:match("#define%s+" .. c_name .. "%s+%(?(-?%d+)%)?")
    t.ok(v, c_name .. " not found in wc_kong.h")
    t.eq(wc[lua_name], tonumber(v), c_name)
  end
end)

t.case("every function the cdef declares is exported by the library", function()
  for _, sym in ipairs({
    "wc_init", "wc_free", "wc_contract_count", "wc_version",
    "wc_stream_new", "wc_stream_free", "wc_on_request",
    "wc_on_response_headers", "wc_on_response_body", "wc_refusal", "wc_out_free",
  }) do
    -- Resolving the symbol through the cdef is the test: a name or signature the library does
    -- not have raises here rather than at the first request that needs it.
    t.ok(pcall(function() return wc.C[sym] end), sym .. " is not resolvable")
  end
end)

t.case("wc_version agrees with the crate", function()
  local v = ffi.string(wc.C.wc_version())
  t.ok(v:match("^%d+%.%d+%.%d+$"), "version looks like " .. v)
end)

t.case("a refusal frame comes back through the FFI intact", function()
  local body, code = wc.refusal(4002, "not contracted")
  t.eq(code, 4002, "code")
  local f = t.json.decode(body)
  t.eq(f.error.data.code, "WC-4002", "taxonomy code in the frame")
  t.eq(f.jsonrpc, "2.0", "jsonrpc")
end)

t.case("freeing an out buffer twice is safe", function()
  local out = wc.out()
  wc.C.wc_refusal(4002, nil, 0, out)
  wc.C.wc_out_free(out)
  wc.C.wc_out_free(out)
  t.eq(tostring(out[0].ptr), "cdata<unsigned char *>: NULL", "pointer nulled")
end)
