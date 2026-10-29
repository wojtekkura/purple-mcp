// Crypto helpers — bearer hashing + constant-time compare.
//
// KV stores no secret material — only user metadata + the bearer hash. The
// shared console token lives in Secrets Store (encrypted at rest there).

// SHA-256 hex digest of a bearer token. KV keys are `token:<hex>` so a KV dump
// never reveals raw bearer values; intercepting the bearer in transit remains a
// TLS problem.
export async function sha256Hex(input: string): Promise<string> {
  const buf = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

// Constant-time string compare for opaque secrets (admin key check).
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}
