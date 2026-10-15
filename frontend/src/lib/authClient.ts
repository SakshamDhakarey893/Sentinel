/**
 * Sentinel Cryptographic Challenge-Response Authentication Client
 *
 * Implements zero-knowledge proof-of-possession using client-side ECDH (P-256)
 * and HMAC-SHA256 to authenticate users with the Sentinel relay server without
 * ever transmitting private keys.
 */

const SESSION_TOKEN_PREFIX = "sentinel_session_token_";

/**
 * Solves an ECDH challenge received from the Sentinel relay:
 * 1. Imports the server's ephemeral public key (SPKI DER base64).
 * 2. Computes the shared secret using the user's Identity Private Key (P-256).
 * 3. Derives an HMAC-SHA256 key from the shared secret.
 * 4. Signs the server's challenge nonce using HMAC-SHA256.
 * 5. Returns the base64-encoded proof.
 */
export async function solveChallenge(
  identityPrivateKey: CryptoKey,
  serverEphemeralPubB64: string,
  nonceB64: string,
): Promise<string> {
  // 1. Decode and import server's ephemeral public key
  const binaryPub = Uint8Array.from(atob(serverEphemeralPubB64.trim()), (c) =>
    c.charCodeAt(0),
  );
  const serverPubKey = await crypto.subtle.importKey(
    "spki",
    binaryPub,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );

  // 2. Perform Diffie-Hellman key agreement
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: serverPubKey },
    identityPrivateKey,
    256,
  );

  // 3. Import shared secret as an HMAC-SHA256 key
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  // 4. Sign the challenge nonce
  const nonceBytes = Uint8Array.from(atob(nonceB64.trim()), (c) =>
    c.charCodeAt(0),
  );
  const signature = await crypto.subtle.sign("HMAC", hmacKey, nonceBytes);

  // 5. Return base64 response
  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

/**
 * Executes the full cryptographic challenge-response protocol with the relay server.
 */
export async function authenticateWithRelay(
  apiBase: string,
  username: string,
  identityPrivateKey: CryptoKey,
): Promise<{ success: boolean; token?: string; error?: string }> {
  try {
    const cleanUser = username.trim().toLowerCase();

    // Step 1: Request cryptographic challenge
    const chalRes = await fetch(`${apiBase}/api/auth/challenge`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: cleanUser }),
    });

    if (!chalRes.ok) {
      const err = await chalRes.json().catch(() => ({}));
      return {
        success: false,
        error:
          err.message ||
          `Challenge request rejected by relay (HTTP ${chalRes.status})`,
      };
    }

    const chalData = await chalRes.json();
    if (
      !chalData.success ||
      !chalData.challenge_id ||
      !chalData.server_ephemeral_pub ||
      !chalData.nonce
    ) {
      return {
        success: false,
        error: chalData.message || "Invalid challenge received from relay",
      };
    }

    // Step 2: Solve challenge using client's private identity key
    const responseB64 = await solveChallenge(
      identityPrivateKey,
      chalData.server_ephemeral_pub,
      chalData.nonce,
    );

    // Step 3: Verify proof with relay
    const verifyRes = await fetch(`${apiBase}/api/auth/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: cleanUser,
        challenge_id: chalData.challenge_id,
        response: responseB64,
      }),
    });

    const verifyData = await verifyRes.json();
    if (!verifyData.success || !verifyData.token) {
      return {
        success: false,
        error: verifyData.message || "Cryptographic proof verification failed",
      };
    }

    // Save session token in sessionStorage (memory-safe per tab)
    saveStoredSessionToken(cleanUser, verifyData.token);

    return {
      success: true,
      token: verifyData.token,
    };
  } catch (err: any) {
    return {
      success: false,
      error: `Authentication failed: ${err?.message || String(err)}`,
    };
  }
}

/**
 * Retrieves cached session token for a given user.
 */
export function getStoredSessionToken(username: string): string | null {
  if (typeof window === "undefined") return null;
  try {
    return sessionStorage.getItem(
      `${SESSION_TOKEN_PREFIX}${username.trim().toLowerCase()}`,
    );
  } catch {
    return null;
  }
}

/**
 * Saves session token in sessionStorage.
 */
export function saveStoredSessionToken(username: string, token: string): void {
  if (typeof window === "undefined") return;
  try {
    sessionStorage.setItem(
      `${SESSION_TOKEN_PREFIX}${username.trim().toLowerCase()}`,
      token.trim(),
    );
  } catch {}
}

/**
 * Clears stored session token.
 */
export function clearStoredSessionToken(username?: string): void {
  if (typeof window === "undefined") return;
  try {
    if (username) {
      sessionStorage.removeItem(
        `${SESSION_TOKEN_PREFIX}${username.trim().toLowerCase()}`,
      );
    } else {
      const keys = Object.keys(sessionStorage);
      for (const k of keys) {
        if (k.startsWith(SESSION_TOKEN_PREFIX)) {
          sessionStorage.removeItem(k);
        }
      }
    }
  } catch {}
}
