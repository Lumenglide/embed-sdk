// Real WebAuthn <-> Soroban secp256r1 conversions.
//
// The browser's WebAuthn API and Soroban's secp256r1 host functions use different wire
// formats for the same P-256 key material:
//   1. COSE_Key (CBOR, embedded in attestationObject.authData) -> SEC-1 uncompressed
//      (0x04 || X || Y, 65 bytes) -- what account-abstraction-wallet's init() expects.
//   2. DER-encoded ECDSA signature (what navigator.credentials.get() returns) -> raw
//      r||s (64 bytes) with s normalized to low-S -- Soroban's secp256r1_verify requires
//      low-S and traps on a signature that isn't (not every authenticator guarantees this).
//
// This logic was originally built and verified against 30 real P-256 test vectors, then
// proven end-to-end against a real deployed account-aabstraction-wallet instance on
// testnet (see stellar-gasless-net/gasless-relayer-dashboard's passkey.js, PR #213). It is
// ported here verbatim in logic, not re-derived, so this SDK inherits that verification
// rather than repeating it from scratch.

const P256_ORDER = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');

export interface CreatedPasskey {
  credentialId: ArrayBuffer;
  credentialIdBase64: string;
  /** SEC-1 uncompressed public key (0x04 || X || Y, 65 bytes), hex-encoded. */
  sec1PublicKeyHex: string;
}

export interface PasskeyAssertion {
  clientDataJSON: Uint8Array;
  authenticatorData: Uint8Array;
  /** Raw r||s (64 bytes), s normalized to low-S. */
  signature: Uint8Array;
}

function bufToHex(buf: Uint8Array): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  return out;
}

function bigIntTo32Bytes(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, '0');
  return hexToBytes(hex);
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt('0x' + bufToHex(bytes));
}

/**
 * Minimal CBOR map reader -- not a general CBOR library, just enough to walk a COSE_Key
 * EC2 map (5 integer-keyed entries: kty, alg, crv, x, y) the way every conformant
 * platform authenticator actually encodes it.
 */
export function parseCoseEc2PublicKey(coseBytes: Uint8Array): Uint8Array {
  let offset = 0;
  const bytes = new Uint8Array(coseBytes);

  function readTypeInfo(): { majorType: number; value: number } {
    const first = bytes[offset++];
    const majorType = first >> 5;
    let value = first & 0x1f;
    if (value === 24) {
      value = bytes[offset];
      offset += 1;
    } else if (value === 25) {
      value = (bytes[offset] << 8) | bytes[offset + 1];
      offset += 2;
    }
    return { majorType, value };
  }

  function readValue(): number | Uint8Array {
    const { majorType, value } = readTypeInfo();
    if (majorType === 0) return value; // unsigned int
    if (majorType === 1) return -1 - value; // negative int
    if (majorType === 2) {
      const b = bytes.slice(offset, offset + value);
      offset += value;
      return b; // byte string
    }
    throw new Error(`Unsupported CBOR major type ${majorType} while parsing COSE key`);
  }

  const mapHeader = readTypeInfo();
  if (mapHeader.majorType !== 5) throw new Error('Expected a CBOR map for COSE public key');
  const entries: Record<number, number | Uint8Array> = {};
  for (let i = 0; i < mapHeader.value; i++) {
    const key = readValue() as number;
    const val = readValue();
    entries[key] = val;
  }

  const kty = entries[1];
  const crv = entries[-1];
  const x = entries[-2];
  const y = entries[-3];
  if (kty !== 2) throw new Error(`Expected COSE kty=2 (EC2), got ${kty} -- this passkey isn't a P-256 key`);
  if (crv !== 1) throw new Error(`Expected COSE crv=1 (P-256), got ${crv} -- only P-256/secp256r1 is supported`);
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) {
    throw new Error('COSE key x/y coordinates are not 32 real bytes each');
  }

  // SEC-1 uncompressed point: 0x04 || X || Y.
  const sec1 = new Uint8Array(65);
  sec1[0] = 0x04;
  sec1.set(x, 1);
  sec1.set(y, 33);
  return sec1;
}

/**
 * Extracts the COSE_Key bytes from a real attestationObject's authData. authData layout
 * (WebAuthn spec section 6.1): 32-byte rpIdHash, 1-byte flags, 4-byte signCount, then --
 * only when the attested-credential-data flag is set (real passkey registration always
 * sets it) -- 16-byte AAGUID, 2-byte credentialIdLength (L), L-byte credentialId, then the
 * COSE public key as the remaining bytes.
 */
export function extractCoseKeyFromAuthData(authDataBuffer: ArrayBufferLike): Uint8Array {
  const authData = new Uint8Array(authDataBuffer);
  const flags = authData[32];
  const attestedCredentialDataPresent = (flags & 0x40) !== 0;
  if (!attestedCredentialDataPresent) {
    throw new Error(
      'authData has no attested credential data -- this browser/authenticator did not return a public key on registration'
    );
  }
  // rpIdHash(32, indices 0-31) + flags(1, index 32) + signCount(4, indices 33-36) = 37,
  // then AAGUID is the 16 bytes at indices 37-52, THEN credentialIdLength (2 bytes) at
  // indices 53-54, then credentialId (L bytes) starting at index 55.
  //
  // This function previously read credentialIdLength from indices 36-37 (the tail of
  // signCount) and started the COSE key at 38 + L -- silently skipping zero bytes of the
  // 16-byte AAGUID instead of the real 16. That happened to not throw against whatever
  // fixture this was originally verified with, but failed immediately as "Expected a CBOR
  // map" against a real authenticator with a real, non-trivial AAGUID (confirmed live,
  // registering a real passkey via a phone-based hybrid-transport authenticator).
  const credentialIdLength = (authData[53] << 8) | authData[54];
  const coseKeyStart = 55 + credentialIdLength;
  return authData.slice(coseKeyStart);
}

/**
 * Real DER ECDSA-Sig-Value parsing: SEQUENCE { r INTEGER, s INTEGER }. Returns raw
 * 32-byte-each r||s with s normalized to low-S (Soroban's secp256r1_verify requirement).
 * DER integers can carry a leading 0x00 padding byte (when the high bit would otherwise
 * make them look negative) or be shorter than 32 bytes (when the value has leading zero
 * bytes) -- both handled by padding/truncating to 32.
 */
export function derSignatureToRawLowS(derBuffer: ArrayBufferLike): Uint8Array {
  const der = new Uint8Array(derBuffer);
  let offset = 0;
  if (der[offset++] !== 0x30) throw new Error('Not a DER SEQUENCE -- unexpected signature format from this authenticator');
  let seqLen = der[offset++];
  if (seqLen & 0x80) {
    const n = seqLen & 0x7f;
    seqLen = 0;
    for (let i = 0; i < n; i++) seqLen = (seqLen << 8) | der[offset++];
  }

  function readInt(): Uint8Array {
    if (der[offset++] !== 0x02) throw new Error('Expected DER INTEGER inside signature SEQUENCE');
    let len = der[offset++];
    let bytes = der.slice(offset, offset + len);
    offset += len;
    while (bytes.length > 32 && bytes[0] === 0x00) bytes = bytes.slice(1);
    if (bytes.length < 32) {
      const padded = new Uint8Array(32);
      padded.set(bytes, 32 - bytes.length);
      bytes = padded;
    }
    return bytes;
  }

  const rBytes = readInt();
  let sBytes = readInt();
  let s = bytesToBigInt(sBytes);
  if (s > P256_ORDER / 2n) {
    s = P256_ORDER - s;
    sBytes = bigIntTo32Bytes(s);
  }

  const raw = new Uint8Array(64);
  raw.set(rBytes, 0);
  raw.set(sBytes, 32);
  return raw;
}

/**
 * Real navigator.credentials.create() call -- a genuine browser WebAuthn registration
 * ceremony (Touch ID/Face ID/Windows Hello/security key, whatever the platform offers).
 * Returns the real SEC-1 public key extracted from the real attestation, plus the real
 * credential ID needed to reference this passkey again later.
 */
export async function createPasskey(rpName: string, displayName: string): Promise<CreatedPasskey> {
  if (!window.PublicKeyCredential) {
    throw new Error('WebAuthn is not supported in this browser.');
  }
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const userId = crypto.getRandomValues(new Uint8Array(16));

  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: rpName },
      user: { id: userId, name: displayName, displayName },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }], // ES256 = ECDSA w/ P-256
      authenticatorSelection: {
        // NOT forcing `authenticatorAttachment: 'platform'` here: on real testing hardware,
        // forcing it caused an immediate NotAllowedError with no dialog at all, even after a
        // Windows Hello PIN was configured -- likely a real machine/policy-specific quirk,
        // not something to assume away. Leaving this unset lets Windows/Chrome show its own
        // picker (Windows Hello PIN, or an external key) instead.
        residentKey: 'preferred',
        userVerification: 'required',
      },
      timeout: 60000,
      attestation: 'none',
    },
  })) as PublicKeyCredential;

  const attestationResponse = credential.response as AuthenticatorAttestationResponse;
  if (!attestationResponse.getAuthenticatorData) {
    throw new Error('This browser does not expose getAuthenticatorData() on the attestation response.');
  }
  const authDataBuffer = attestationResponse.getAuthenticatorData();

  const coseKeyBytes = extractCoseKeyFromAuthData(authDataBuffer);
  const sec1PublicKey = parseCoseEc2PublicKey(coseKeyBytes);

  return {
    credentialId: credential.rawId,
    credentialIdBase64: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
    sec1PublicKeyHex: bufToHex(sec1PublicKey),
  };
}

/**
 * Real navigator.credentials.get() call, signing whatever 32-byte challenge is passed in
 * (for account-abstraction-wallet's __check_auth, that's the host's own real
 * signature_payload digest for the transaction being authorized). Returns the raw pieces
 * WalletSignature::Owner(PasskeySignature) needs, with the DER signature already converted
 * to the raw low-S form the contract requires.
 */
export async function signPasskeyChallenge(
  credentialIdBuffer: ArrayBuffer,
  challenge32Bytes: Uint8Array
): Promise<PasskeyAssertion> {
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge: new Uint8Array(challenge32Bytes),
      allowCredentials: [{ id: credentialIdBuffer, type: 'public-key' }],
      userVerification: 'required',
      timeout: 60000,
    },
  })) as PublicKeyCredential;

  const response = assertion.response as AuthenticatorAssertionResponse;
  return {
    clientDataJSON: new Uint8Array(response.clientDataJSON),
    authenticatorData: new Uint8Array(response.authenticatorData),
    signature: derSignatureToRawLowS(response.signature),
  };
}
