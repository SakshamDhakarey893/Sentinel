export async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"],
  );
}

export async function exportPublicKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("spki", key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

export async function importPublicKey(b64: string): Promise<CryptoKey> {
  const binary = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "spki",
    binary,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    [],
  );
}

export async function exportPrivateKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("pkcs8", key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

export async function importPrivateKey(b64: string): Promise<CryptoKey> {
  const binary = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey(
    "pkcs8",
    binary,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey", "deriveBits"],
  );
}

export async function deriveSharedSecret(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
): Promise<ArrayBuffer> {
  return crypto.subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256,
  );
}

export function extractPublicKeyFromPkcs8(pkcs8B64: string): string | null {
  try {
    const binary = Uint8Array.from(atob(pkcs8B64), (c) => c.charCodeAt(0));
    const marker = [0xa1, 0x44, 0x03, 0x42, 0x00, 0x04];
    for (let i = 0; i < binary.length - 68; i++) {
      let match = true;
      for (let j = 0; j < marker.length; j++) {
        if (binary[i + j] !== marker[j]) {
          match = false;
          break;
        }
      }
      if (match) {
        const point = binary.slice(i + 5, i + 5 + 65);
        const SPKI_P256_HEADER = new Uint8Array([
          0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
          0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
          0x42, 0x00,
        ]);
        const spki = new Uint8Array(SPKI_P256_HEADER.length + 65);
        spki.set(SPKI_P256_HEADER, 0);
        spki.set(point, SPKI_P256_HEADER.length);
        return btoa(String.fromCharCode(...spki));
      }
    }
  } catch {}
  return null;
}
