import {
  generateSecret,
  generateUri,
  generateToken,
  validateToken,
  HashAlgorithm,
} from "./index"

const referenceLabel = "Superbacked"
const referenceUsername = "john@protonmail.com"
const referenceSecret = "DMJKP7AU22WKWRG3DNIQ3ERA"
const referenceIssuer = referenceLabel
const referenceUri = {
  SHA1: "otpauth://totp/Superbacked:john%40protonmail.com?secret=DMJKP7AU22WKWRG3DNIQ3ERA&issuer=Superbacked&algorithm=SHA1&digits=6&period=30",
  SHA256: "otpauth://totp/Superbacked:john%40protonmail.com?secret=DMJKP7AU22WKWRG3DNIQ3ERA&issuer=Superbacked&algorithm=SHA256&digits=6&period=30",
  SHA512: "otpauth://totp/Superbacked:john%40protonmail.com?secret=DMJKP7AU22WKWRG3DNIQ3ERA&issuer=Superbacked&algorithm=SHA512&digits=6&period=30",
};
const referenceTimestamps = [1664596800000, 1664596770000]
const referenceTokens = {
  SHA1: ["616692", "415925"],
  SHA256: ["067612", "654664"],
  SHA512: ["431432", "415901"],
}
const referenceDimensions: (undefined | HashAlgorithm)[] = [undefined, "SHA1", "SHA256", "SHA512"];

test("generate secret", async () => {
  const secret = generateSecret()
  expect(secret).toMatch(/[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]{24}/)
})

test("generate secret using user-defined length", async () => {
  const secret = generateSecret(32)
  expect(secret).toMatch(/[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]{32}/)
})

test("generate URI", async () => {
  for (const algorithm of referenceDimensions) {
    const uri = generateUri(
      referenceLabel,
      referenceUsername,
      referenceSecret,
      referenceIssuer,
      algorithm
    )
    expect(uri).toEqual(referenceUri[algorithm ?? 'SHA1'])
  }
})

test("generate token", async () => {
  for (const algorithm of referenceDimensions) {
    const token = generateToken(referenceSecret, algorithm)
    expect(token).toMatch(/[0-9]{6}/)
  }
})

test("generate token using reference timestamp", async () => {
  for (const algorithm of referenceDimensions) {
    const token = generateToken(referenceSecret, algorithm, referenceTimestamps[0])
    expect(token).toEqual(referenceTokens[algorithm ?? 'SHA1'][0])
  }
})

test("validate invalid token", async () => {
  const result = validateToken(referenceSecret, "103945")
  expect(result).toEqual(false)
})

test("validate valid token", async () => {
  for (const algorithm of referenceDimensions) {
    const result = validateToken(
      referenceSecret,
      referenceTokens[algorithm ?? 'SHA1'][0],
      1,
      algorithm,
      referenceTimestamps[0]
    )
    expect(result).toEqual(true)
  }
})

test("validate valid token using lower case secret", async () => {
  for (const algorithm of referenceDimensions) {
    const result = validateToken(
      referenceSecret.toLowerCase(),
      referenceTokens[algorithm ?? 'SHA1'][0],
      1,
      algorithm,
      referenceTimestamps[0]
    )
    expect(result).toEqual(true)
  }
})

test("validate valid but expired past token", async () => {
  for (const algorithm of referenceDimensions) {
    const result = validateToken(
      referenceSecret,
      referenceTokens[algorithm ?? 'SHA1'][1],
      1,
      algorithm,
      referenceTimestamps[0]
    )
    expect(result).toEqual(false)
  }
})

test("validate valid past token", async () => {
  for (const algorithm of referenceDimensions) {
    const result = validateToken(
      referenceSecret,
      referenceTokens[algorithm ?? 'SHA1'][1],
      1,
      algorithm,
      referenceTimestamps[1]
    )
    expect(result).toEqual(true)
  }
})

test("validate valid past token using threshold 2", async () => {
  for (const algorithm of referenceDimensions) {
    const result = validateToken(
      referenceSecret,
      referenceTokens[algorithm ?? 'SHA1'][1],
      2,
      algorithm,
      referenceTimestamps[0]
    )
    expect(result).toEqual(true)
  }
})
