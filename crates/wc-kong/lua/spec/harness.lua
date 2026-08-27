-- A test runner small enough to read.
local M = { passed = 0, failed = 0, failures = {} }

M.ROOT = os.getenv("WC_ROOT") or "."
M.LIB = os.getenv("WC_LIB") or error("WC_LIB must point at the built cdylib")
M.FIX = os.getenv("WC_FIX") or error("WC_FIX must point at the fixture directory")
M.json = require("spec.json")

function M.read(p)
  local f = assert(io.open(p, "rb"), "cannot read " .. p)
  local s = f:read("*a")
  f:close()
  return s
end

function M.case(name, fn)
  local ok, err = pcall(fn)
  if ok then
    M.passed = M.passed + 1
    io.write("  ok   ", name, "\n")
  else
    M.failed = M.failed + 1
    M.failures[#M.failures + 1] = name .. ": " .. tostring(err)
    io.write("  FAIL ", name, "\n       ", tostring(err), "\n")
  end
end

function M.ok(v, msg)
  if not v then error(msg or "expected a truthy value", 2) end
end

function M.eq(got, want, what)
  if got ~= want then
    error(string.format("%s: got %s, want %s", what or "value", tostring(got), tostring(want)), 2)
  end
end

function M.report()
  io.write(string.format("\n%d passed, %d failed\n", M.passed, M.failed))
  os.exit(M.failed == 0 and 0 or 1)
end

return M
