import {
  generateSecret,
  generateUri,
  generateToken,
  validateToken,
} from "./index"

const referenceLabel = "Superbacked"
const referenceUsername = "john@protonmail.com"
const referenceSecret = "DMJKP7AU22WKWRG3DNIQ3ERA"
const referenceIssuer = referenceLabel
const referenceUri =
  "otpauth://totp/Superbacked:john%40protonmail.com?secret=DMJKP7AU22WKWRG3DNIQ3ERA&issuer=Superbacked&algorithm=SHA1&digits=6&period=30"
const referenceUri256 =
  "otpauth://totp/Superbacked:john%40protonmail.com?secret=DMJKP7AU22WKWRG3DNIQ3ERA&issuer=Superbacked&algorithm=SHA256&digits=6&period=30"
const referenceTimestamps = [1664596800000, 1664596770000]
const referenceTokens = ["616692", "415925"]
const referenceTokens256 = ["067612", "654664"]

test("generate secret", async () => {
  const secret = generateSecret()
  expect(secret).toMatch(/[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]{24}/)
})

test("generate secret using user-defined length", async () => {
  const secret = generateSecret(32)
  expect(secret).toMatch(/[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]{32}/)
})

test("generate URI", async () => {
  const uri = generateUri(
    referenceLabel,
    referenceUsername,
    referenceSecret,
    referenceIssuer
  )
  expect(uri).toEqual(referenceUri)
})

test("generate URI using SHA256", async () => {
  const uri = generateUri(
    referenceLabel,
    referenceUsername,
    referenceSecret,
    referenceIssuer,
    'SHA256'
  )
  expect(uri).toEqual(referenceUri256)
})

test("generate token", async () => {
  const token = generateToken(referenceSecret)
  expect(token).toMatch(/[0-9]{6}/)
})

test("generate token using SHA256", async () => {
  const token = generateToken(referenceSecret, undefined, 'SHA256')
  expect(token).toMatch(/[0-9]{6}/)
})

test("generate token using reference timestamp", async () => {
  const token = generateToken(referenceSecret, referenceTimestamps[0])
  expect(token).toEqual(referenceTokens[0])
})

test("generate token using reference timestamp and SHA256", async () => {
  const token = generateToken(referenceSecret, referenceTimestamps[0], 'SHA256')
  expect(token).toEqual(referenceTokens256[0])
})

test("validate invalid token", async () => {
  const result = validateToken(referenceSecret, "103945")
  expect(result).toEqual(false)
})

test("validate valid token", async () => {
  const result = validateToken(
    referenceSecret,
    referenceTokens[0],
    1,
    referenceTimestamps[0]
  )
  expect(result).toEqual(true)
})

test("validate valid token using SHA256", async () => {
  const result = validateToken(
    referenceSecret,
    referenceTokens256[0],
    1,
    referenceTimestamps[0],
    'SHA256'
  )
  expect(result).toEqual(true)
})

test("validate valid token using lower case secret", async () => {
  const result = validateToken(
    referenceSecret.toLowerCase(),
    referenceTokens[0],
    1,
    referenceTimestamps[0]
  )
  expect(result).toEqual(true)
})

test("validate valid but expired past token", async () => {
  const result = validateToken(
    referenceSecret,
    referenceTokens[1],
    1,
    referenceTimestamps[0]
  )
  expect(result).toEqual(false)
})

test("validate valid past token", async () => {
  const result = validateToken(
    referenceSecret,
    referenceTokens[1],
    1,
    referenceTimestamps[1]
  )
  expect(result).toEqual(true)
})

test("validate valid past token using SHA256", async () => {
  const result = validateToken(
    referenceSecret,
    referenceTokens256[1],
    1,
    referenceTimestamps[1],
    'SHA256'
  )
  expect(result).toEqual(true)
})

test("validate valid past token using threshold 2", async () => {
  const result = validateToken(
    referenceSecret,
    referenceTokens[1],
    2,
    referenceTimestamps[0]
  )
  expect(result).toEqual(true)
})

test("validate valid past token using threshold 2 and SHA256", async () => {
  const result = validateToken(
    referenceSecret,
    referenceTokens256[1],
    2,
    referenceTimestamps[0],
    'SHA256'
  )
  expect(result).toEqual(true)
})
