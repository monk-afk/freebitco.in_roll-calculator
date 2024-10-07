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
local sub = string.sub
local byte = string.byte
local char = string.char
local floor = math.floor
local unpack = table.unpack
local math_min = math.min
local math_max = math.max
local string_rep = string.rep
local table_concat = table.concat
local string_format = string.format


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

HEX = pcall(string_format, "%x", 2^31) and function(x) -- returns string of 8 lowercase hexadecimal digits
  return string_format("%08x", x % 4294967296)
end

-- Inner loop functions
local sha256_feed_64
local sha2_K_lo = {}
local sha2_K_hi = {}
local sha2_H_lo = {}
local sha2_H_hi = {}
local sha2_H_ext256 = {[224] = {}, [256] = sha2_H_hi}
local sha2_H_ext512_lo = {[384] = {}, [512] = sha2_H_lo}
local sha2_H_ext512_hi = {[384] = {}, [512] = sha2_H_hi}
local common_W = {}
local K_lo_modulo = 4294967296
local hi_factor = 0

XOR = XOR or XORA5

local function sha256_feed_64(H, str, offs, size)
  local W, K = common_W, sha2_K_hi
  local h1, h2, h3, h4, h5, h6, h7, h8 = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
  for pos = offs, offs + size - 1, 64 do
    for j = 1, 16 do
      pos = pos + 4
      local a, b, c, d = byte(str, pos - 3, pos)
      W[j] = ((a * 256 + b) * 256 + c) * 256 + d
    end
    for j = 17, 64 do
      local a, b = W[j-15], W[j-2]
      local a7, a18, b17, b19 = a / 2^7, a / 2^18, b / 2^17, b / 2^19
      W[j] = (XOR(a7 % 1 * (2^32 - 1) + a7, a18 % 1 * (2^32 - 1) + a18, (a - a % 2^3) / 2^3) + W[j-16] + W[j-7]
          + XOR(b17 % 1 * (2^32 - 1) + b17, b19 % 1 * (2^32 - 1) + b19, (b - b % 2^10) / 2^10)) % 2^32
    end
    local a, b, c, d, e, f, g, h = h1, h2, h3, h4, h5, h6, h7, h8
    for j = 1, 64 do
      e = e % 2^32
      local e6, e11, e7 = e / 2^6, e / 2^11, e * 2^7
      local e7_lo = e7 % 2^32
      local z = AND(e, f) + AND(-1-e, g) + h + K[j] + W[j]
          + XOR(e6 % 1 * (2^32 - 1) + e6, e11 % 1 * (2^32 - 1) + e11, e7_lo + (e7 - e7_lo) / 2^32)
      h = g
      g = f
      f = e
      e = z + d
      d = c
      c = b
      b = a % 2^32
      local b2, b13, b10 = b / 2^2, b / 2^13, b * 2^10
      local b10_lo = b10 % 2^32
      a = z + AND(d, c) + AND(b, XOR(d, c)) +
          XOR(b2 % 1 * (2^32 - 1) + b2, b13 % 1 * (2^32 - 1) + b13, b10_lo + (b10 - b10_lo) / 2^32)
    end
    h1, h2, h3, h4 = (a + h1) % 2^32, (b + h2) % 2^32, (c + h3) % 2^32, (d + h4) % 2^32
    h5, h6, h7, h8 = (e + h5) % 2^32, (f + h6) % 2^32, (g + h7) % 2^32, (h + h8) % 2^32
  end
  H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8] = h1, h2, h3, h4, h5, h6, h7, h8
end

do
   local function mul(src1, src2, factor, result_length)
    local result, carry, value, weight = {}, 0.0, 0.0, 1.0
    for j = 1, result_length do
     for k = math_max(1, j + 1 - #src2), math_min(j, #src1) do
      carry = carry + factor * src1[k] * src2[j + 1 - k]
     end
     local digit = carry % 2^24
     result[j] = floor(digit)
     carry = (carry - digit) / 2^24
     value = value + digit * weight
     weight = weight * 2^24
    end
    return result, value
   end

   local idx, step, p, one, sqrt_hi, sqrt_lo = 0, {4, 1, 2, -2, 2}, 4, {1}, sha2_H_hi, sha2_H_lo
   repeat
    p = p + step[p % 6]
    local d = 1
    repeat
     d = d + step[d % 6]
     if d*d > p then -- next prime number is found
      local root = p^(1/3)
      local R = root * 2^40
      R = mul({R - R % 1}, one, 1.0, 2)
      local _, delta = mul(R, mul(R, R, 1.0, 4), -1.0, 4)
      local hi = R[2] % 65536 * 65536 + floor(R[1] / 256)
      local lo = R[1] % 256 * 16777216 + floor(delta * (2^-56 / 3) * root / p)
      if idx < 16 then
         root = p^(1/2)
         R = root * 2^40
         R = mul({R - R % 1}, one, 1.0, 2)
         _, delta = mul(R, R, -1.0, 2)
         local hi = R[2] % 65536 * 65536 + floor(R[1] / 256)
         local lo = R[1] % 256 * 16777216 + floor(delta * 2^-17 / root)
         local idx = idx % 8 + 1
         sha2_H_ext256[224][idx] = lo
         sqrt_hi[idx], sqrt_lo[idx] = hi, lo + hi * hi_factor
         if idx > 7 then
          sqrt_hi, sqrt_lo = sha2_H_ext512_hi[384], sha2_H_ext512_lo[384]
         end
      end
      idx = idx + 1
      sha2_K_hi[idx], sha2_K_lo[idx] = hi, lo % K_lo_modulo + hi * hi_factor
      break
     end
    until p % d == 0
   until idx > 79
end


--------------------------------------------------------------------------------
-- MAIN FUNCTIONS
--------------------------------------------------------------------------------

local function sha256ext(width, message)
   -- Create an instance (private objects for current calculation)
   local H, length, tail = {unpack(sha2_H_ext256[width])}, 0.0, ""
   local function partial(message_part)
    if message_part then
     if tail then
      length = length + #message_part
      local offs = 0
      if tail ~= "" and #tail + #message_part >= 64 then
         offs = 64 - #tail
         sha256_feed_64(H, tail..sub(message_part, 1, offs), 0, 64)
         tail = ""
      end
      local size = #message_part - offs
      local size_tail = size % 64
      sha256_feed_64(H, message_part, offs, size - size_tail)
      tail = tail..sub(message_part, #message_part + 1 - size_tail)
      return partial
     else
      error("Adding more chunks is not allowed after receiving the result", 2)
     end
    else
     if tail then
      local final_blocks = {tail, "\128", string_rep("\0", (-9 - length) % 64 + 1)}
      tail = nil
      -- Assuming user data length is shorter than (2^53)-9 bytes
      -- Anyway, it looks very unrealistic that someone would spend more than a year of calculations to process 2^53 bytes of data by using this Lua script :-)
      -- 2^53 bytes = 2^56 bits, so "bit-counter" fits in 7 bytes
      length = length * (8 / 256^7)  -- convert "byte-counter" to "bit-counter" and move decimal point to the left
      for j = 4, 10 do
         length = length % 1 * 256
         final_blocks[j] = char(floor(length))
      end
      final_blocks = table_concat(final_blocks)
      sha256_feed_64(H, final_blocks, 0, #final_blocks)
      local max_reg = width / 32
      for j = 1, max_reg do
         H[j] = HEX(H[j])
      end
      H = table_concat(H, "", 1, max_reg)
     end
     return H
    end
   end

   if message then
    -- Actually perform calculations and return the SHA256 digest of a message
    return partial(message)()
   else
    -- Return function for chunk-by-chunk loading
    -- User should feed every chunk of input data as single argument to this function and finally get SHA256 digest by invoking this function without an argument
    return partial
   end
end



function sha256(message)
  return sha256ext(256, message)
end

function sha224(message)
  return sha256ext(224, message)
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