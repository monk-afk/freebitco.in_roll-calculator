## freebitco.in roll calculator

This is a recreation of the instructions provided by https://freebitco.in under the hyperlink "THIS GAME IS PROVABLY FAIR!", which details how rolls are calculated:

  >  1. Two strings are created :
  >      STRING1 = "[NONCE]:[SERVER SEED]:[NONCE]"
  >      STRING2 = "[NONCE]:[CLIENT SEED]:[NONCE]"
  >  2. Then HMAC-SHA512 is used to hash STRING1 with STRING2 as the secret key, giving us a 128 character hex string.
  >  3. The first 8 characters of the hex string are taken and converted to a decimal.
  >  4. This decimal is then divided by 429496.7295 and rounded off to the nearest whole number.
  >  5. This whole number is used as your roll, with the maximum possible value being 10,000.

Before each roll, freebitco.in will show users their client seed, the nonce, and a the server seed hash.

The server seed (not hashed) is kept secret until after the roll is made.

After the roll, the user is given the server seed so they may verify the roll.

They also provide a link to their verifier tool, https://s3.amazonaws.com/roll-verifier/verify.html

___

## Usage

Extract the contents of this repository, then run from terminal command: 

```bash
$ lua roll_calculator.lua
8009    9b550d15e298bd082ff0378694e05688e79f6a710a600ec00b834e8b15d6f6e4
```

This prints the roll number and server_seed_hash.

In this package, we use the following seeds:

```lua
local data = {
  nonce = 123456,
  server_seed = "monk", -- this is the part they keep secret until after the roll is made
  client_seed = "knom"  -- this is usually a random seed, and the user can set it manually
}  -- Will print: 8009    9b550d15e298bd082ff0378694e05688e79f6a710a600ec00b834e8b15d6f6e4

```

The same number will be generated from the roll-verifier provided by freebitco.in:

https://s3.amazonaws.com/roll-verifier/verify.html?server_seed=monk&client_seed=knom&server_seed_hash=9b550d15e298bd082ff0378694e05688e79f6a710a600ec00b834e8b15d6f6e4&nonce=123456

___

SHA hashing library sourced from https://github.com/Egor-Skriptunoff/pure_lua_SHA used under license