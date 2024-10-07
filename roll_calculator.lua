--==[[ freebitco.in roll calculator ]]==--

dofile("./sha/sha512.lua")
dofile("./sha/sha256.lua")
dofile("./sha/hmac.lua")


local function get_winning_number(data)
  local nonce            = data.nonce
  local server_seed      = data.server_seed
  local client_seed      = data.client_seed
  local server_seed_hash = sha256(server_seed)
  local client_seed_hash = sha256(client_seed)
  local string1 = nonce..":"..server_seed..":"..nonce
  local string2 = nonce..":"..client_seed..":"..nonce
  local hmac512 = shmac(sha512, string2, string1)
  local chars_8 = string.sub(hmac512, 0, 8)
  local hex_int = tonumber(chars_8, 16)
  local shifted = math.floor((hex_int / 429496.7295) + 0.5)
  return shifted, server_seed_hash
end


local data = {
  nonce = 123456,
  server_seed = "monk", -- this is the part they keep secret until after the roll is made
  client_seed = "knom"  -- this is usually a random seed, and the user can set it manually
}  -- Will print: 8009    9b550d15e298bd082ff0378694e05688e79f6a710a600ec00b834e8b15d6f6e4

local win_number, server_seed_hash = get_winning_number(data)

print(win_number, server_seed_hash)


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