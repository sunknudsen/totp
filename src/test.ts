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
const referenceTimestamp = 1670589924041
const referenceToken = "771101"

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

test("generate token", async () => {
  const token = generateToken(referenceSecret)
  expect(token).toMatch(/[0-9]{6}/)
})

test("generate token using reference timestamp", async () => {
  const token = generateToken(referenceSecret, referenceTimestamp)
  expect(token).toEqual(referenceToken)
})

test("validate invalid token", async () => {
  const result = validateToken(referenceSecret, "103945", referenceTimestamp)
  expect(result).toEqual(false)
})

test("validate valid token", async () => {
  const result = validateToken(
    referenceSecret,
    referenceToken,
    referenceTimestamp
  )
  expect(result).toEqual(true)
})
