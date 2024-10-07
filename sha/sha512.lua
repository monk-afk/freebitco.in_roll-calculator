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
local string_format = string.format
local math_min = math.min
local math_max = math.max
local table_concat = table.concat
local byte = string.byte
local char = string.char
local string_rep = string.rep
local sub = string.sub
local ceil = math.ceil
local floor = math.floor
local unpack = table.unpack


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

local function XORA5(x, y)
  return XOR(x, y or 0xA5A5A5A5) % 4294967296
end



--------------------------------------------------------------------------------
-- CREATING OPTIMIZED INNER LOOP
--------------------------------------------------------------------------------

local sha512_feed_128
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

local function sha512_feed_128(H_lo, H_hi, str, offs, size)
  local W, K_lo, K_hi = common_W, sha2_K_lo, sha2_K_hi
  local h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo = H_lo[1], H_lo[2], H_lo[3], H_lo[4], H_lo[5], H_lo[6], H_lo[7], H_lo[8]
  local h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi = H_hi[1], H_hi[2], H_hi[3], H_hi[4], H_hi[5], H_hi[6], H_hi[7], H_hi[8]
  for pos = offs, offs + size - 1, 128 do
    for j = 1, 16*2 do
      pos = pos + 4
      local a, b, c, d = byte(str, pos - 3, pos)
      W[j] = ((a * 256 + b) * 256 + c) * 256 + d
    end
    for jj = 17*2, 80*2, 2 do
      local a_hi, a_lo, b_hi, b_lo = W[jj-31], W[jj-30], W[jj-5], W[jj-4]
      local b_hi_6, b_hi_19, b_hi_29, b_lo_19, b_lo_29, a_hi_1, a_hi_7, a_hi_8, a_lo_1, a_lo_8 =
        b_hi % 2^6, b_hi % 2^19, b_hi % 2^29, b_lo % 2^19, b_lo % 2^29, a_hi % 2^1, a_hi % 2^7, a_hi % 2^8, a_lo % 2^1, a_lo % 2^8
      local tmp1 = XOR((a_lo - a_lo_1) / 2^1 + a_hi_1 * 2^31, (a_lo - a_lo_8) / 2^8 + a_hi_8 * 2^24, (a_lo - a_lo % 2^7) / 2^7 + a_hi_7 * 2^25) % 2^32
        + XOR((b_lo - b_lo_19) / 2^19 + b_hi_19 * 2^13, b_lo_29 * 2^3 + (b_hi - b_hi_29) / 2^29, (b_lo - b_lo % 2^6) / 2^6 + b_hi_6 * 2^26) % 2^32
        + W[jj-14] + W[jj-32]
      local tmp2 = tmp1 % 2^32
      W[jj-1] = (XOR((a_hi - a_hi_1) / 2^1 + a_lo_1 * 2^31, (a_hi - a_hi_8) / 2^8 + a_lo_8 * 2^24, (a_hi - a_hi_7) / 2^7)
        + XOR((b_hi - b_hi_19) / 2^19 + b_lo_19 * 2^13, b_hi_29 * 2^3 + (b_lo - b_lo_29) / 2^29, (b_hi - b_hi_6) / 2^6)
        + W[jj-15] + W[jj-33] + (tmp1 - tmp2) / 2^32) % 2^32
      W[jj] = tmp2
    end
    local a_lo, b_lo, c_lo, d_lo, e_lo, f_lo, g_lo, h_lo = h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo
    local a_hi, b_hi, c_hi, d_hi, e_hi, f_hi, g_hi, h_hi = h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi
    for j = 1, 80 do
      local jj = 2*j
      local e_lo_9, e_lo_14, e_lo_18, e_hi_9, e_hi_14, e_hi_18 = e_lo % 2^9, e_lo % 2^14, e_lo % 2^18, e_hi % 2^9, e_hi % 2^14, e_hi % 2^18
      local tmp1 = (AND(e_lo, f_lo) + AND(-1-e_lo, g_lo)) % 2^32 + h_lo + K_lo[j] + W[jj]
        + XOR((e_lo - e_lo_14) / 2^14 + e_hi_14 * 2^18, (e_lo - e_lo_18) / 2^18 + e_hi_18 * 2^14, e_lo_9 * 2^23 + (e_hi - e_hi_9) / 2^9) % 2^32
      local z_lo = tmp1 % 2^32
      local z_hi = AND(e_hi, f_hi) + AND(-1-e_hi, g_hi) + h_hi + K_hi[j] + W[jj-1] + (tmp1 - z_lo) / 2^32
        + XOR((e_hi - e_hi_14) / 2^14 + e_lo_14 * 2^18, (e_hi - e_hi_18) / 2^18 + e_lo_18 * 2^14, e_hi_9 * 2^23 + (e_lo - e_lo_9) / 2^9)
      h_lo = g_lo;  h_hi = g_hi
      g_lo = f_lo;  g_hi = f_hi
      f_lo = e_lo;  f_hi = e_hi
      tmp1 = z_lo + d_lo
      e_lo = tmp1 % 2^32
      e_hi = (z_hi + d_hi + (tmp1 - e_lo) / 2^32) % 2^32
      d_lo = c_lo;  d_hi = c_hi
      c_lo = b_lo;  c_hi = b_hi
      b_lo = a_lo;  b_hi = a_hi
      local b_lo_2, b_lo_7, b_lo_28, b_hi_2, b_hi_7, b_hi_28 = b_lo % 2^2, b_lo % 2^7, b_lo % 2^28, b_hi % 2^2, b_hi % 2^7, b_hi % 2^28
      tmp1 = z_lo + (AND(d_lo, c_lo) + AND(b_lo, XOR(d_lo, c_lo))) % 2^32
        + XOR((b_lo - b_lo_28) / 2^28 + b_hi_28 * 2^4, b_lo_2 * 2^30 + (b_hi - b_hi_2) / 2^2, b_lo_7 * 2^25 + (b_hi - b_hi_7) / 2^7) % 2^32
      a_lo = tmp1 % 2^32
      a_hi = (z_hi + AND(d_hi, c_hi) + AND(b_hi, XOR(d_hi, c_hi)) + (tmp1 - a_lo) / 2^32
        + XOR((b_hi - b_hi_28) / 2^28 + b_lo_28 * 2^4, b_hi_2 * 2^30 + (b_lo - b_lo_2) / 2^2, b_hi_7 * 2^25 + (b_lo - b_lo_7) / 2^7)) % 2^32
    end
    a_lo = h1_lo + a_lo
    h1_lo = a_lo % 2^32
    h1_hi = (h1_hi + a_hi + (a_lo - h1_lo) / 2^32) % 2^32
    a_lo = h2_lo + b_lo
    h2_lo = a_lo % 2^32
    h2_hi = (h2_hi + b_hi + (a_lo - h2_lo) / 2^32) % 2^32
    a_lo = h3_lo + c_lo
    h3_lo = a_lo % 2^32
    h3_hi = (h3_hi + c_hi + (a_lo - h3_lo) / 2^32) % 2^32
    a_lo = h4_lo + d_lo
    h4_lo = a_lo % 2^32
    h4_hi = (h4_hi + d_hi + (a_lo - h4_lo) / 2^32) % 2^32
    a_lo = h5_lo + e_lo
    h5_lo = a_lo % 2^32
    h5_hi = (h5_hi + e_hi + (a_lo - h5_lo) / 2^32) % 2^32
    a_lo = h6_lo + f_lo
    h6_lo = a_lo % 2^32
    h6_hi = (h6_hi + f_hi + (a_lo - h6_lo) / 2^32) % 2^32
    a_lo = h7_lo + g_lo
    h7_lo = a_lo % 2^32
    h7_hi = (h7_hi + g_hi + (a_lo - h7_lo) / 2^32) % 2^32
    a_lo = h8_lo + h_lo
    h8_lo = a_lo % 2^32
    h8_hi = (h8_hi + h_hi + (a_lo - h8_lo) / 2^32) % 2^32
  end
  H_lo[1], H_lo[2], H_lo[3], H_lo[4], H_lo[5], H_lo[6], H_lo[7], H_lo[8] = h1_lo, h2_lo, h3_lo, h4_lo, h5_lo, h6_lo, h7_lo, h8_lo
  H_hi[1], H_hi[2], H_hi[3], H_hi[4], H_hi[5], H_hi[6], H_hi[7], H_hi[8] = h1_hi, h2_hi, h3_hi, h4_hi, h5_hi, h6_hi, h7_hi, h8_hi
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

local idx = 0
local step = {4, 1, 2, -2, 2}
local p = 4
local one = {1}
local sqrt_hi = sha2_H_hi
local sqrt_lo = sha2_H_lo
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

-- Calculating IVs for SHA512/224 and SHA512/256
for width = 224, 256, 32 do
  local H_lo, H_hi = {}, {}
  for j = 1, 8 do
    H_lo[j] = XORA5(sha2_H_lo[j])
    H_hi[j] = XORA5(sha2_H_hi[j])
  end
  sha512_feed_128(H_lo, H_hi, "SHA-512/"..tostring(width).."\128"..string_rep("\0", 115).."\88", 0, 128)
  sha2_H_ext512_lo[width] = H_lo
  sha2_H_ext512_hi[width] = H_hi
end


local function sha512ext(width, message)
  local length, tail, H_lo, H_hi = 0.0, "", {unpack(sha2_H_ext512_lo[width])}, not HEX64 and {unpack(sha2_H_ext512_hi[width])}
  local function partial(message_part)
    if message_part then
      if tail then
        length = length + #message_part
        local offs = 0
        if tail ~= "" and #tail + #message_part >= 128 then
          offs = 128 - #tail
          sha512_feed_128(H_lo, H_hi, tail..sub(message_part, 1, offs), 0, 128)
          tail = ""
        end
        local size = #message_part - offs
        local size_tail = size % 128
        sha512_feed_128(H_lo, H_hi, message_part, offs, size - size_tail)
        tail = tail..sub(message_part, #message_part + 1 - size_tail)
        return partial
      else
        error("Adding more chunks is not allowed after receiving the result", 2)
      end
    else
      if tail then
        local final_blocks = {tail, "\128", string_rep("\0", (-17-length) % 128 + 9)}
        tail = nil
        length = length * (8 / 256^7)
        for j = 4, 10 do
          length = length % 1 * 256
          final_blocks[j] = char(floor(length))
        end
        final_blocks = table_concat(final_blocks)
        sha512_feed_128(H_lo, H_hi, final_blocks, 0, #final_blocks)
        local max_reg = ceil(width / 64)
        for j = 1, max_reg do
          H_lo[j] = HEX(H_hi[j])..HEX(H_lo[j])
        end
        H_hi = nil
        H_lo = sub(table_concat(H_lo, "", 1, max_reg), 1, width / 4)
      end
      return H_lo
    end
  end

  if message then
    return partial(message)()
  else
    return partial
  end
end




function sha512(message)
  return sha512ext(512, message)
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