------------------------------------------------------------------------------------
-- MIT License                                                                    --
--                                                                                --
-- Copyright (c) 2018-2022  Egor Skriptunoff                                      --
--                                                                                --
-- Permission is hereby granted, free of charge, to any person obtaining a copy   --
-- of this software and associated documentation files (the "Software"), to deal  --
-- in the Software without restriction, including without limitation the rights   --
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      --
-- copies of the Software, and to permit persons to whom the Software is          --
-- furnished to do so, subject to the following conditions:                       --
--                                                                                --
-- The above copyright notice and this permission notice shall be included in all --
-- copies or substantial portions of the Software.                                --
--                                                                                --
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     --
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       --
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    --
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         --
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  --
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  --
-- SOFTWARE.                                                                      --
------------------------------------------------------------------------------------
local gsub = string.gsub
local byte = string.byte
local char = string.char
local string_rep = string.rep

local AND_of_two_bytes = {[0] = 0}
local idx = 0
for y = 0, 127 * 256, 256 do
  for x = y, y + 127 do
    x = AND_of_two_bytes[x] * 2
    AND_of_two_bytes[idx] = x
    AND_of_two_bytes[idx + 1] = x
    AND_of_two_bytes[idx + 256] = x
    AND_of_two_bytes[idx + 257] = x + 1
    idx = idx + 2
  end
  idx = idx + 256
end

local function and_or_xor(x, y, operation)
  local x0 = x % 2^32
  local y0 = y % 2^32
  local rx = x0 % 256
  local ry = y0 % 256
  local res = AND_of_two_bytes[rx + ry * 256]
  x = x0 - rx
  y = (y0 - ry) / 256
  rx = x % 65536
  ry = y % 256
  res = res + AND_of_two_bytes[rx + ry] * 256
  x = (x - rx) / 256
  y = (y - ry) / 256
  rx = x % 65536 + y % 256
  res = res + AND_of_two_bytes[rx] * 65536
  res = res + AND_of_two_bytes[(x + y - rx) / 256] * 16777216
  if operation then
    res = x0 + y0 - operation * res
  end
  return res
end

local function AND(x, y)
  return and_or_xor(x, y)
end

local function XOR(x, y, z, t, u)      -- 2..5 arguments
  if z then
    if t then
      if u then
        t = and_or_xor(t, u, 2)
      end
      z = and_or_xor(z, t, 2)
    end
    y = and_or_xor(y, z, 2)
  end
  return and_or_xor(x, y, 2)
end

local function XOR_BYTE(x, y)
  return x + y - 2 * AND_of_two_bytes[x + y * 256]
end

local function hex_to_bin(hex_string)
  return (gsub(hex_string, "%x%x",
    function (hh)
      return char(tonumber(hh, 16))
    end
  ))
end


local function pad_and_xor(str, result_length, byte_for_xor)
  return gsub(str, ".",
      function(c)
        return char(XOR_BYTE(byte(c), byte_for_xor))
      end
  )..string_rep(char(byte_for_xor), result_length - #str)
end

-- local block_size_for_HMAC = {
--    ["sha224"]     =  64,
--    ["sha256"]     =  64,
--    ["sha512_224"] = 128,
--    ["sha512_256"] = 128,
--    ["sha384"]     = 128,
--    ["sha512"]     = 128,
--    ["sha3_224"]   = 144,  -- (1600 - 2 * 224) / 8
--    ["sha3_256"]   = 136,  -- (1600 - 2 * 256) / 8
--    ["sha3_384"]   = 104,  -- (1600 - 2 * 384) / 8
--    ["sha3_512"]   =  72,  -- (1600 - 2 * 512) / 8
-- }

local function hmac(hash_func, key, message)
  -- Create an instance (private objects for current calculation)
  -- local block_size = block_size_for_HMAC[hash_func]
  local block_size = 128 -- block_size_for_HMAC[hash_func]
  if not block_size then
      error("Unknown hash function", 2)
  end
  if #key > block_size then
      key = hex_to_bin(hash_func(key))
  end
  local append = hash_func()(pad_and_xor(key, block_size, 0x36))
  local result

  local function partial(message_part)
      if not message_part then
        result = result or hash_func(pad_and_xor(key, block_size, 0x5C)..hex_to_bin(append()))
        return result
      elseif result then
        error("Adding more chunks is not allowed after receiving the result", 2)
      else
        append(message_part)
        return partial
      end
  end

  if message then
      -- Actually perform calculations and return the HMAC of a message
      return partial(message)()
  else
      -- Return function for chunk-by-chunk loading of a message
      -- User should feed every chunk of the message as single argument to this function and finally get HMAC by invoking this function without an argument
      return partial
  end
end


function shmac(hash_func, key, message)
  return hmac(hash_func, key, message)
end


------------------------------------------------------------------------------------
-- MIT License                                                                    --
--                                                                                --
-- Copyright (c) 2018-2022  Egor Skriptunoff                                      --
--                                                                                --
-- Permission is hereby granted, free of charge, to any person obtaining a copy   --
-- of this software and associated documentation files (the "Software"), to deal  --
-- in the Software without restriction, including without limitation the rights   --
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell      --
-- copies of the Software, and to permit persons to whom the Software is          --
-- furnished to do so, subject to the following conditions:                       --
--                                                                                --
-- The above copyright notice and this permission notice shall be included in all --
-- copies or substantial portions of the Software.                                --
--                                                                                --
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR     --
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,       --
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE    --
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER         --
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,  --
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE  --
-- SOFTWARE.                                                                      --
------------------------------------------------------------------------------------