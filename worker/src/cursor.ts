// HMAC-signed cursors. Used by the SDL poller to hand the agent a tamper-proof
// "resume" token when a PowerQuery doesn't finish within the per-request poll
// budget. The agent echoes the cursor back to continue polling.
//
// GraphQL domains (alerts/vuln/misconfig) use the upstream's own opaque relay
// `endCursor` as `next_cursor` directly — those are already validated server-side
// and don't pass through this signer.
//
// Format: `psl1.<base64url(json)>.<base64url(hmac-sha256)>`

import { ValidationError } from "./errors.js";

const PREFIX = "psl1";

export interface CursorSigner {
  sign(payload: unknown): Promise<string>;
  verify(cursor: string): Promise<unknown>;
}

export async function createCursorSigner(hmacKey: string): Promise<CursorSigner> {
  if (!hmacKey) throw new Error("createCursorSigner requires a non-empty HMAC key");
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(hmacKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );

  async function mac(data: string): Promise<Uint8Array> {
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
    return new Uint8Array(sig);
  }

  return {
    async sign(payload: unknown): Promise<string> {
      const body = b64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
      const sig = b64urlEncode(await mac(`${PREFIX}.${body}`));
      return `${PREFIX}.${body}.${sig}`;
    },
    async verify(cursor: string): Promise<unknown> {
      const parts = cursor.split(".");
      if (parts.length !== 3 || parts[0] !== PREFIX) {
        throw new ValidationError("Malformed cursor.", {
          hint: "Pass the exact `next_cursor` string returned by the previous call, unmodified.",
        });
      }
      const [, body, sig] = parts;
      const expected = b64urlEncode(await mac(`${PREFIX}.${body}`));
      if (!timingSafeEqual(sig!, expected)) {
        throw new ValidationError("Cursor signature is invalid (tampered or minted by another deployment).", {
          hint: "Re-issue the original query without a cursor to mint a fresh one.",
        });
      }
      try {
        return JSON.parse(new TextDecoder().decode(b64urlDecode(body!)));
      } catch {
        throw new ValidationError("Cursor payload is not valid JSON.");
      }
    },
  };
}

function b64urlEncode(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
