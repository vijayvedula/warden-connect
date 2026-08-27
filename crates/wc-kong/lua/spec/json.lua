-- A minimal JSON codec, standing in for cjson.safe.
--
-- Test scaffolding only: the plugin uses Kong's cjson. It exists because the shapes crossing
-- the FFI are JSON, and a spec that hand-built those strings would not be testing the encoder
-- the handler actually calls into. Escaping is the part that matters here — a PEM is a string
-- full of newlines, and getting that wrong is the bug this stands guard over.
local M = {}

local ESC = { ['"'] = '\\"', ['\\'] = '\\\\', ['\n'] = '\\n', ['\r'] = '\\r', ['\t'] = '\\t' }

local function enc(v)
  local t = type(v)
  if v == nil then return "null" end
  if t == "boolean" then return tostring(v) end
  if t == "number" then return string.format("%.14g", v) end
  if t == "string" then
    return '"' .. v:gsub('[%c"\\]', function(c)
      return ESC[c] or string.format("\\u%04x", c:byte())
    end) .. '"'
  end
  if t == "table" then
    if #v > 0 or next(v) == nil then
      local parts = {}
      for i = 1, #v do parts[i] = enc(v[i]) end
      return "[" .. table.concat(parts, ",") .. "]"
    end
    local keys = {}
    for k in pairs(v) do keys[#keys + 1] = k end
    table.sort(keys)
    local parts = {}
    for _, k in ipairs(keys) do parts[#parts + 1] = enc(tostring(k)) .. ":" .. enc(v[k]) end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  error("cannot encode " .. t)
end
M.encode = function(v) local ok, s = pcall(enc, v); return ok and s or nil end

-- Decode, enough for the frames the library returns.
local function skip(s, i) return s:find("[^ \t\r\n]", i) or i end
local dec
local function dstr(s, i)
  local out, j = {}, i + 1
  while true do
    local c = s:sub(j, j)
    if c == '"' then return table.concat(out), j + 1 end
    if c == "\\" then
      local n = s:sub(j + 1, j + 1)
      local m = { n = "\n", t = "\t", r = "\r", b = "\b", f = "\f" }
      if n == "u" then
        out[#out + 1] = string.char(tonumber(s:sub(j + 2, j + 5), 16) % 256); j = j + 6
      else
        out[#out + 1] = m[n] or n; j = j + 2
      end
    else
      if c == "" then error("unterminated string") end
      out[#out + 1] = c; j = j + 1
    end
  end
end
dec = function(s, i)
  i = skip(s, i)
  local c = s:sub(i, i)
  if c == '"' then return dstr(s, i) end
  if c == "{" then
    local o = {}; i = skip(s, i + 1)
    if s:sub(i, i) == "}" then return o, i + 1 end
    while true do
      local k; k, i = dstr(s, skip(s, i)); i = skip(s, i) + 1
      local v; v, i = dec(s, i); o[k] = v; i = skip(s, i)
      if s:sub(i, i) == "}" then return o, i + 1 end
      i = i + 1
    end
  end
  if c == "[" then
    local a = {}; i = skip(s, i + 1)
    if s:sub(i, i) == "]" then return a, i + 1 end
    while true do
      local v; v, i = dec(s, i); a[#a + 1] = v; i = skip(s, i)
      if s:sub(i, i) == "]" then return a, i + 1 end
      i = i + 1
    end
  end
  local lit = s:match("^true", i) or s:match("^false", i) or s:match("^null", i)
  if lit then
    return (lit == "true" and true) or (lit == "false" and false) or nil, i + #lit
  end
  local num = s:match("^%-?%d+%.?%d*[eE]?[%+%-]?%d*", i)
  if num then return tonumber(num), i + #num end
  error("bad json at " .. i .. ": " .. s:sub(i, i + 20))
end
M.decode = function(s) local ok, v = pcall(function() return (dec(s, 1)) end); return ok and v or nil end

return M
