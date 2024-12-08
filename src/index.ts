import { randomBytes, createHmac } from "crypto"

const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

export type hashAlgorithm = "SHA1" | "SHA256";

const base32ToHex = (base32: string) => {
  let bits = ""
  let hex = ""
  for (let index = 0; index < base32.length; index++) {
    const value = charset.indexOf(base32.charAt(index))
    bits += `00000${value.toString(2)}`.slice(-5)
  }
  for (let index = 0; index < bits.length - 3; index += 4) {
    const chunk = bits.substring(index, index + 4)
    hex = hex + parseInt(chunk, 2).toString(16)
  }
  return hex
}

/**
 * Generate secret
 * @param length optional, length (defaults to `24`)
 * @returns secret
 */
export const generateSecret = (length = 24) => {
  return randomBytes(length)
    .map((value) =>
      charset.charCodeAt(Math.floor((value * charset.length) / 256))
    )
    .toString()
}

/**
 * Generate URI
 * @param label label
 * @param username username
 * @param secret secret
 * @param issuer issuer
 * @returns URI
 */
export const generateUri = (
  label: string,
  username: string,
  secret: string,
  issuer: string,
  algorithm: hashAlgorithm = "SHA1"
) => {
  // See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
  return `otpauth://totp/${encodeURIComponent(label)}:${encodeURIComponent(
    username
  )}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(
    issuer
  )}&algorithm=${algorithm}&digits=6&period=30`
}

/**
 * Generate token
 * @param secret secret
 * @param timestamp optional, timestamp used for deterministic unit tests (defaults to current timestamp)
 * @returns token
 */
export const generateToken = (
  secret: string,
  timestamp = Date.now(),
  algorithm: hashAlgorithm = 'SHA1'
) => {
  const message = Buffer.from(
    `0000000000000000${Math.floor(Math.round(timestamp / 1000) / 30).toString(
      16
    )}`.slice(-16),
    "hex"
  )
  const key = Buffer.from(base32ToHex(secret.toUpperCase()), "hex")
  const hmac = createHmac(algorithm, key)
  hmac.setEncoding("hex")
  hmac.update(message)
  hmac.end()
  const data = hmac.read()
  return (
    parseInt(data.substr(parseInt(data.slice(-1), 16) * 2, 8), 16) & 2147483647
  )
    .toString()
    .slice(-6)
}

/**
 * Validate token
 * @param secret secret
 * @param token token
 * @param threshold optional, number of valid periods (defaults to `1`)
 * @param timestamp optional, timestamp used for deterministic unit tests (defaults to current timestamp)
 * @returns boolean
 */
export const validateToken = (
  secret: string,
  token: string,
  threshold: number = 1,
  timestamp = Date.now(),
  algorithm: hashAlgorithm = 'SHA1'
) => {
  for (let index = 0; index < threshold; index++) {
    if (token === generateToken(secret, timestamp - index * 30 * 1000, algorithm)) {
      return true
    }
  }
  return false
}
