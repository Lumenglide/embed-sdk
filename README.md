# @lumenglide/embed-sdk

A TypeScript SDK for embedding a passkey-secured, gasless smart account into any Stellar/
Soroban dApp. Instead of building this yourself, a dApp installs this package and gets:
real WebAuthn passkey creation, a real deployed `account-abstraction-wallet` instance per
user, and real transaction execution authorized entirely by the passkey -- no seed phrase,
no browser extension required for day-to-day use.

## What's real right now (v0.1.0)

- **Passkey creation and signing** (`src/passkey.ts`): real `navigator.credentials.create()`/
  `.get()` calls, with the real COSE-to-SEC-1 public key conversion and DER-to-raw-low-S
  signature conversion this ecosystem's contracts require. This logic is ported, not
  reinvented, from `stellar-gasless-net/gasless-relayer-dashboard`'s `passkey.js`
  (PR #213), which verified it against 30 real P-256 test vectors and a real deployed
  wallet on testnet. `src/passkey.test.ts` adds its own real-crypto regression tests using
  Node's own `crypto` module.
- **Wallet deployment and execution** (`src/wallet.ts`): deploys a fresh
  `account-abstraction-wallet` instance from an already-installed wasm hash, and calls its
  `execute()` authorized by a real passkey assertion.

  **Status: confirmed live on testnet, end-to-end, no seed phrase anywhere in the
  authorization path.** A real passkey created via a genuine WebAuthn ceremony (Windows
  Hello and a phone-based hybrid/cross-device authenticator have both been used), a real
  `account-abstraction-wallet` deployed and initialized with that passkey's public key, and
  a real `execute()` call authorized ENTIRELY by that passkey -- independently confirmed via
  `server.getTransaction()` and the public stellar.expert explorer (not just this SDK's own
  optimistic "sent" resolution), e.g.
  [this transaction](https://stellar.expert/explorer/testnet/tx/d824b3c219e08d2386fa898e0e3fb3d4c8a2bea060d89bcf004f90d7332774e0)
  invoking the native XLM SAC's `symbol()` through a freshly deployed wallet.

  Getting there surfaced four real, previously-unverified bugs, each confirmed by reading
  the installed SDK/contract source directly and by diagnosing real on-chain failures (not
  assumed away):
  1. The dashboard's original code called `@stellar/stellar-sdk`'s exported `authorizeEntry`
     helper, which hardcodes an ed25519 `Keypair.verify()` check on whatever the signer
     callback returns -- it throws for every real passkey call, since a passkey's secp256r1
     signature is not an ed25519 one. Fixed by manually replicating the real custom-account
     authorization protocol instead of using that helper. See the comment block at the top
     of `src/wallet.ts`.
  2. Soroban's protocol now defaults to `SorobanCredentialsAddressV2` (CAP-71) for
     address-credentialed auth entries, not the older v1 `SorobanCredentialsAddress` this
     code originally matched exclusively on. The v1-only check silently let real v2 entries
     pass through **unsigned** (`signature: void`) -- accepted by simulation and submission,
     but genuinely failed on-chain. Confirmed via `getTransaction()` diagnostics on a
     transaction this SDK itself had reported as sent successfully.
  3. The transaction's CPU-instruction budget is computed by the first simulation, before a
     real passkey signature exists. Verifying a real secp256r1 signature inside
     `__check_auth` costs meaningfully more than the placeholder signature used at that
     first simulation, so the locked-in budget undercounts the real cost and the transaction
     traps with `resource_limit_exceeded`. Fixed by re-simulating (`tx.simulate()`) after
     attaching the real signature, which `@stellar/stellar-sdk`'s own `assembleTransaction`
     is explicitly written to support (it preserves an already-signed auth entry and only
     refreshes the resource/fee data).
  4. `SorobanCredentialsAddressV2` signs a **different preimage struct** than v1 --
     `HashIdPreimage.envelopeTypeSorobanAuthorizationWithAddress` (CAP-71), which also binds
     the signer's address into the signed bytes, not the plain
     `envelopeTypeSorobanAuthorization` v1 uses. Using the v1 preimage shape for a v2 entry
     produces a well-formed but *wrong* digest -- the passkey happily signs a
     plausible-looking challenge that never matches the host's real `signature_payload`.
     Confirmed by decoding the actual signed `clientDataJSON` and the real on-chain
     `signature_payload` from a `__check_auth` diagnostic event and comparing them
     byte-for-byte, then reading `@stellar/stellar-sdk`'s own reference `authorizeEntry`
     source to find the correct preimage-selection logic.
- **Relayer client** (`src/relayer.ts`): a thin, typed wrapper around a real
  `stellar-gasless-relayer` instance's `/v1/relay` endpoint.

## What is NOT wired together yet -- the real next milestone

`wallet.ts`'s `executeViaPasskey` still requires a **fee-paying wallet signature**
(Freighter, xBull, etc.) for the outer transaction, even though the passkey authorizes the
actual call. That means today's flow is passkey-authorized but not yet gasless
end-to-end. Making it genuinely gasless means: build the transaction, get the passkey's
authorization entry, then submit the fully-authorized XDR through `relayer.ts`'s
`relayTransaction()` instead of `tx.signAndSend()` -- so the end user never needs a funded
account or a browser wallet extension at all. That integration is the next real piece of
work, not something this version claims to have solved.

Also not yet built: a session-key request/grant flow (the contract already supports
`add_session_key`/`get_session_key`; this SDK doesn't expose it yet), and the actual
`embed-widget` UI package (the "Connect" button + modal a dApp actually drops into their
page) -- that's a separate package in this org, built on top of this one.

## Install

```bash
npm install @lumenglide/embed-sdk
```

## Usage (current, non-gasless flow)

```ts
import { createPasskey, deployPasskeyWallet, executeViaPasskey } from '@lumenglide/embed-sdk';

const config = {
  walletWasmHash: '...', // an already-installed account-abstraction-wallet wasm hash
  networkPassphrase: 'Test SDF Network ; September 2015',
  rpcUrl: 'https://soroban-testnet.stellar.org',
  relayerUrl: 'https://your-relayer.example.com',
  relayerApiKey: 'your-dapp-api-key',
};

const passkey = await createPasskey('Your dApp Name', 'user@example.com');
const walletId = await deployPasskeyWallet(config, funderAddress, funderSignTransaction, passkey.sec1PublicKeyHex);
const { result, txHash } = await executeViaPasskey(config, {
  walletContractId: walletId,
  feePayerAddress: funderAddress,
  feePayerSignTransaction: funderSignTransaction,
  credentialIdBuffer: passkey.credentialId,
});
```

## Development

```bash
npm install
npm test        # real crypto regression tests
npm run build   # type-check and emit dist/
```
