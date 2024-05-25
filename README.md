# @sunknudsen/totp

## Generate and validate TOTP tokens.

## Installation

```console
$ npm install @sunknudsen/totp
```

## Usage

```typescript
import {
  generateSecret,
  generateUri,
  generateToken,
  validateToken,
} from "@sunknudsen/totp"

const secret = generateSecret()

console.log(secret)
// DMJKP7AU22WKWRG3DNIQ3ERA

const uri = generateUri(
  "Superbacked",
  "john@protonmail.com",
  "DMJKP7AU22WKWRG3DNIQ3ERA",
  "Superbacked"
)

console.log(uri)
// otpauth://totp/Superbacked:john%40protonmail.com?secret=DMJKP7AU22WKWRG3DNIQ3ERA&issuer=Superbacked&algorithm=SHA256&digits=6&period=30

const token = generateToken("DMJKP7AU22WKWRG3DNIQ3ERA")

console.log(token)
// 616692

const result = validateToken("DMJKP7AU22WKWRG3DNIQ3ERA", "616692")

console.log(result)
// true
```