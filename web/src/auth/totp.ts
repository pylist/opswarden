const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const periodMs = 30_000;

export async function generateTOTPCode(
  base32Secret: string,
  now = Date.now(),
  digits = 6,
): Promise<string> {
  if (
    !Number.isFinite(now) ||
    now < 0 ||
    !Number.isInteger(digits) ||
    digits < 6 ||
    digits > 8
  ) {
    throw new Error("invalid TOTP parameters");
  }
  const secret = decodeBase32(base32Secret);
  const counter = BigInt(Math.floor(now / periodMs));
  const message = new ArrayBuffer(8);
  new DataView(message).setBigUint64(0, counter);
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    secret,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.sign("HMAC", key, message),
  );
  const offset = digest[digest.length - 1] & 0x0f;
  const value =
    (((digest[offset] & 0x7f) << 24) |
      (digest[offset + 1] << 16) |
      (digest[offset + 2] << 8) |
      digest[offset + 3]) >>>
    0;
  secret.fill(0);
  digest.fill(0);
  return String(value % 10 ** digits).padStart(digits, "0");
}

export async function verifyTOTPCode(
  base32Secret: string,
  code: string,
  now = Date.now(),
): Promise<boolean> {
  if (!/^\d{6}$/.test(code) || !Number.isFinite(now) || now < 0) {
    return false;
  }
  for (const offset of [-1, 0, 1]) {
    const candidateTime = now + offset * periodMs;
    if (candidateTime < 0) continue;
    const expected = await generateTOTPCode(base32Secret, candidateTime);
    if (sameCode(expected, code)) return true;
  }
  return false;
}

function decodeBase32(value: string) {
  const normalized = value.trim().toUpperCase().replace(/=+$/u, "");
  if (!normalized || !/^[A-Z2-7]+$/u.test(normalized)) {
    throw new Error("invalid Base32 secret");
  }
  const output: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of normalized) {
    buffer = (buffer << 5) | alphabet.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      output.push((buffer >>> bits) & 0xff);
      buffer &= bits === 0 ? 0 : (1 << bits) - 1;
    }
  }
  if (bits > 0 && buffer !== 0) {
    throw new Error("non-canonical Base32 secret");
  }
  return Uint8Array.from(output);
}

function sameCode(left: string, right: string) {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}
