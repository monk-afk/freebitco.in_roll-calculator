--[[ This script generates the 10000 roll numbers from 8 hexadecimal
    similar to the roll generator but without using hmac.
    The output is saved to macd_ranges.txt ]]

local max_int = 4294967296 -- max integer for 4 byte hexadecimal (16^8)
local last_shift = 9  -- non-zero to get zero
local last_int = 0
local mac_data = {}

local floor = math.floor -- localize the floor

for hex_int = 0, max_int do
  local shifted = floor((hex_int / 429496.7295) + 0.5) -- the roll win number

  -- we'll record when the win number changes
  if shifted ~= last_shift then
    mac_data[#mac_data+1] = {
      string.format("%05d", shifted), -- roll winning number
      string.format("%08x", hex_int), -- macd "first 8 digits"
      hex_int, -- hexadecimal integer
      (hex_int - last_int) -- range between this shift and last shift
    }

    last_int = hex_int
    last_shift = shifted
  end
end

local file = io.open("./macd_ranges.txt", "a+")
file:write("Win#   \tMACD-8  \troll  \trolls since shift\n")
for n = 1, #mac_data do
  file:write(table.concat(mac_data[n], "  \t"), "\n")
end
file:close()



------------------------------------------------------------------------------------
-- MIT License                                                                    --
--                                                                                --
-- Copyright © 2024 monk                                                          --
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