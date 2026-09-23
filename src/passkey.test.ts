import { describe, it, expect } from 'vitest';
import { generateKeyPairSync, sign as nodeSign, verify as nodeVerify } from 'node:crypto';
import { derSignatureToRawLowS, extractCoseKeyFromAuthData, parseCoseEc2PublicKey } from './passkey.js';

/** Real CBOR encoding of a COSE_Key EC2 map (kty=2, alg=-7, crv=1, x, y) -- the exact
 * 5-entry structure a conformant WebAuthn authenticator actually produces. */
function encodeCoseEc2Key(x: Uint8Array, y: Uint8Array): Uint8Array {
  return new Uint8Array([
    0xa5, // map, 5 entries
    0x01, 0x02, // kty: 2 (EC2)
    0x03, 0x26, // alg: -7 (ES256)
    0x20, 0x01, // crv: 1 (P-256)
    0x21, 0x58, 0x20, ...x, // x: byte string, 32 bytes
    0x22, 0x58, 0x20, ...y, // y: byte string, 32 bytes
  ]);
}

/** Builds a real, spec-correct authData buffer: 32-byte rpIdHash + 1-byte flags (attested
 * credential data bit set) + 4-byte signCount + 16-byte AAGUID + 2-byte credentialIdLength
 * + credentialId + the COSE key. Uses a genuinely non-zero AAGUID and a realistic
 * (non-trivial-length) credential ID -- exactly the shape that exposed the real offset bug
 * this test guards against. */
function buildAuthData(coseKey: Uint8Array, aaguid: Uint8Array, credentialId: Uint8Array): Uint8Array {
  const rpIdHash = new Uint8Array(32).fill(0xaa);
  const flags = new Uint8Array([0x40 | 0x01]); // attested credential data + user present
  const signCount = new Uint8Array([0x00, 0x00, 0x00, 0x01]);
  const credentialIdLength = new Uint8Array([(credentialId.length >> 8) & 0xff, credentialId.length & 0xff]);
  return new Uint8Array([...rpIdHash, ...flags, ...signCount, ...aaguid, ...credentialIdLength, ...credentialId, ...coseKey]);
}

// Real P-256 keypairs and real DER signatures, generated via Node's own crypto module --
// not fabricated fixtures. This proves derSignatureToRawLowS's DER parsing and low-S
// normalization against signatures Node itself considers valid, by round-tripping through
// Node's own 'ieee-p1363' (raw r||s) verifier.
describe('derSignatureToRawLowS', () => {
  it('converts a real DER-encoded P-256 signature to a raw r||s that Node verifies as ieee-p1363', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const message = Buffer.from('lumenglide real conversion test vector');

    const derSignature = nodeSign('sha256', message, { key: privateKey, dsaEncoding: 'der' });
    const raw = derSignatureToRawLowS(derSignature.buffer.slice(derSignature.byteOffset, derSignature.byteOffset + derSignature.byteLength));

    expect(raw.length).toBe(64);

    const isValid = nodeVerify(
      'sha256',
      message,
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      Buffer.from(raw)
    );
    expect(isValid).toBe(true);
  });

  it('produces a low-S signature (s <= order/2) across many real signatures', () => {
    const P256_ORDER = BigInt('0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551');
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });

    for (let i = 0; i < 20; i++) {
      const message = Buffer.from(`vector ${i}`);
      const derSignature = nodeSign('sha256', message, { key: privateKey, dsaEncoding: 'der' });
      const raw = derSignatureToRawLowS(
        derSignature.buffer.slice(derSignature.byteOffset, derSignature.byteOffset + derSignature.byteLength)
      );
      const s = BigInt('0x' + Buffer.from(raw.slice(32, 64)).toString('hex'));
      expect(s <= P256_ORDER / 2n).toBe(true);
    }
  });

  it('rejects a buffer that is not a DER SEQUENCE', () => {
    const garbage = new Uint8Array([0x01, 0x02, 0x03]);
    expect(() => derSignatureToRawLowS(garbage.buffer)).toThrow('Not a DER SEQUENCE');
  });
});

// Regression test for a real bug found during live testnet verification (2026-09-23):
// extractCoseKeyFromAuthData read credentialIdLength from the wrong offset (the tail of
// signCount) and never skipped the 16-byte AAGUID at all. This passed against whatever this
// code was originally verified with, but failed immediately with "Expected a CBOR map for
// COSE public key" against a real phone-based (hybrid-transport) authenticator's real,
// non-trivial AAGUID and credential ID -- confirmed live, not simulated.
describe('extractCoseKeyFromAuthData + parseCoseEc2PublicKey', () => {
  it('correctly extracts a real EC2 public key from authData with a non-zero AAGUID and a realistic credential ID length', () => {
    const { publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const sec1 = publicKey.export({ type: 'spki', format: 'der' });
    // The last 65 bytes of an SPKI-encoded P-256 public key are the raw SEC-1 uncompressed
    // point (0x04 || X || Y) -- everything before that is the fixed SPKI algorithm header.
    const rawSec1 = sec1.subarray(sec1.length - 65);
    const x = rawSec1.subarray(1, 33);
    const y = rawSec1.subarray(33, 65);

    const coseKey = encodeCoseEc2Key(new Uint8Array(x), new Uint8Array(y));
    // A real, non-zero, non-trivial AAGUID (16 bytes) -- the exact thing the old, buggy
    // offset calculation never accounted for.
    const aaguid = new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00]);
    // A realistic, longer-than-trivial credential ID, like real synced/discoverable
    // passkeys use (not the very short IDs a hardware key might produce).
    const credentialId = crypto.getRandomValues(new Uint8Array(48));
    const authData = buildAuthData(coseKey, aaguid, credentialId);

    const extracted = extractCoseKeyFromAuthData(authData.buffer);
    const sec1Result = parseCoseEc2PublicKey(extracted);

    expect(Buffer.from(sec1Result).toString('hex')).toBe(Buffer.from(rawSec1).toString('hex'));
  });

  it('throws a clear error when the attested-credential-data flag is not set', () => {
    const authData = new Uint8Array(37); // rpIdHash + flags(=0, no bit set) + signCount
    expect(() => extractCoseKeyFromAuthData(authData.buffer)).toThrow('no attested credential data');
  });
});
