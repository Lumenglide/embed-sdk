// Deploy and drive a real account-abstraction-wallet instance, authorized entirely by a
// real WebAuthn passkey assertion. Adapted from the end-to-end flow first proven in
// stellar-gasless-net/gasless-relayer-dashboard's passkey.js (PR #213) -- generalized here
// to take network/wasm-hash config instead of hardcoded testnet constants, so this SDK
// works for any dApp embedding it, not just that one dashboard demo.

import { Client as ContractClient } from '@stellar/stellar-sdk/contract';
import { hash, xdr } from '@stellar/stellar-sdk';
import { hexToBytes, signPasskeyChallenge } from './passkey.js';
import type { LumenglideConfig, SignTransaction } from './types.js';

// NOTE on why this file does NOT use @stellar/stellar-sdk's exported `authorizeEntry`
// helper for the custom-account signing step below:
//
// That helper's signer callback contract only supports standard Stellar (ed25519) accounts
// -- after calling the signer, it hard-codes `Keypair.fromPublicKey(publicKey).verify(payload,
// signature)` and, on success, wraps the result in the fixed `{ public_key, signature }`
// ScVal map that only a standard-account __check_auth understands (see
// node_modules/@stellar/stellar-base/lib/auth.js). A passkey's secp256r1 signature is not an
// ed25519 signature and account-abstraction-wallet's __check_auth expects a completely
// different ScVal shape (`WalletSignature::Owner(PasskeySignature)`), so that verify call
// would simply throw for every real passkey-authorized call. This was confirmed by reading
// the installed @stellar/stellar-base@13.x source directly, not assumed.
//
// For a *custom* account contract, the real protocol (see
// https://developers.stellar.org/docs/build/guides/transactions/signing-with-custom-accounts)
// is: the entry's `SorobanAddressCredentials.signature` field is opaque to the host -- it is
// passed straight through as the `signature: Val` argument to the account contract's own
// `__check_auth`, whatever shape that contract defines. The digest that must be signed is
// `sha256(HashIdPreimage::envelopeTypeSorobanAuthorization({ networkId, nonce, invocation,
// signatureExpirationLedger }))`, computed identically to what `authorizeEntry` computes
// internally -- we replicate that computation here, then substitute our own custom ScVal
// for the signature instead of going through the ed25519-only path.

/**
 * Deploys a fresh account-abstraction-wallet instance from the already-installed wasm hash
 * (no re-upload needed) and initializes it with the given passkey's SEC-1 public key.
 * `funderAddress`/`funderSignTransaction` pay for and sign both real transactions -- the
 * funder retains no ongoing authority over the wallet; only the passkey controls execute()
 * from here on (the funder is only ever the `owner` used for session-key admin actions).
 */
export async function deployPasskeyWallet(
  config: LumenglideConfig,
  funderAddress: string,
  funderSignTransaction: SignTransaction,
  sec1PublicKeyHex: string
): Promise<string> {
  const deployTx = await ContractClient.deploy(null, {
    wasmHash: config.walletWasmHash,
    format: 'hex',
    networkPassphrase: config.networkPassphrase,
    rpcUrl: config.rpcUrl,
    publicKey: funderAddress,
    signTransaction: funderSignTransaction,
  });
  const deployedSent = await deployTx.signAndSend();
  const deployedClient = deployedSent.result as InstanceType<typeof ContractClient>;
  const walletContractId = (deployedClient as any).options.contractId as string;

  const initTx = await (deployedClient as any).init(
    { owner: funderAddress, passkey_pubkey: hexToBytes(sec1PublicKeyHex) },
    { timeoutInSeconds: 1800 }
  );
  await initTx.signAndSend();

  return walletContractId;
}

export interface ExecuteViaPasskeyParams {
  walletContractId: string;
  /** Pays the real network fee as the transaction's source account -- a separate concern
   * from who authorizes the call. Any wallet adapter works here (Freighter, xBull, or a
   * relayer-sponsored fee payer once the gasless path below is wired in). */
  feePayerAddress: string;
  feePayerSignTransaction: SignTransaction;
  credentialIdBuffer: ArrayBuffer;
  /** The contract this call actually invokes -- required, and it must be a DIFFERENT
   * address from `walletContractId`. Soroban's host enforces real re-entrancy protection
   * and rejects a contract calling back into itself (confirmed live: a default of
   * `walletContractId` calling its own `get_owner()` fails with "Contract re-entry is not
   * allowed" during simulation, before authorization is even evaluated). There is no safe
   * default here -- every real use of execute() targets some other contract. */
  targetContractId: string;
  targetFunction: string;
  targetArgs: unknown[];
}

/**
 * Calls a real deployed wallet's execute(), authorized ENTIRELY by a real WebAuthn
 * assertion -- no seed-phrase/Freighter signature anywhere in the authorization itself.
 */
export async function executeViaPasskey(
  config: LumenglideConfig,
  params: ExecuteViaPasskeyParams
): Promise<{ result: unknown; txHash: string }> {
  const { walletContractId, feePayerAddress, feePayerSignTransaction, credentialIdBuffer, targetContractId, targetFunction, targetArgs } =
    params;

  if (targetContractId === walletContractId) {
    throw new Error(
      `executeViaPasskey: targetContractId must not equal walletContractId (${walletContractId}) -- Soroban's host rejects a contract calling back into itself with "Contract re-entry is not allowed," confirmed live via direct simulation. Target a different contract.`
    );
  }

  const walletClient = await ContractClient.from({
    contractId: walletContractId,
    networkPassphrase: config.networkPassphrase,
    rpcUrl: config.rpcUrl,
    publicKey: feePayerAddress,
    signTransaction: feePayerSignTransaction,
  });

  const tx = await (walletClient as any).execute(
    { target: targetContractId, function: targetFunction, args: targetArgs },
    { timeoutInSeconds: 1800 }
  );

  const needsSigning = tx.needsNonInvokerSigningBy();
  if (!needsSigning.includes(walletContractId)) {
    throw new Error(
      `Expected the wallet contract (${walletContractId}) to need its own auth entry, but needsNonInvokerSigningBy() returned: ${JSON.stringify(needsSigning)}`
    );
  }

  await tx.signAuthEntries({
    address: walletContractId,
    // Deliberately NOT the SDK's exported `authorizeEntry` helper -- see the module-level
    // comment at the top of this file for why that helper is incompatible with a custom
    // (non-ed25519) account signature scheme. This replicates its real digest computation
    // by hand, then substitutes our own custom ScVal for the signature.
    authorizeEntry: async (
      entry: InstanceType<typeof xdr.SorobanAuthorizationEntry>,
      _signer: unknown,
      validUntilLedgerSeq: number,
      networkPassphrase: string = config.networkPassphrase
    ) => {
      // Only address-credentialed entries need a signature at all (source-account entries
      // are implicitly authorized by the transaction's own signature) -- matching the real
      // authorizeEntry's own short-circuit for this case. v17's XDR classes are immutable
      // (readonly properties, no setter methods) and credentials carries a string `type`
      // discriminant rather than a numeric switch -- a real, breaking API change from the
      // v13 shape this file was originally written against.
      //
      // Soroban's protocol defines FOUR credential variants (SorobanCredentialsType):
      // sourceAccount, address (v1), addressV2, addressWithDelegates. addressV2 carries the
      // exact same SorobanAddressCredentials payload as v1 -- just exposed under the
      // `.addressV2` property instead of `.address` -- and testnet's live simulation now
      // returns entries typed addressV2, not the older v1 `address` variant. An earlier
      // version of this code only matched `sorobanCredentialsAddress` (v1) and silently
      // returned addressV2 entries UNCHANGED, submitting them with `signature: void` and
      // `signatureExpirationLedger: 0` -- confirmed live: the transaction was accepted by
      // simulation/submission but genuinely FAILED on-chain (checked via
      // server.getTransaction(), not just the optimistic local "sent" resolution).
      // addressWithDelegates has a materially different payload shape and is not handled
      // here since nothing in this SDK's flow produces it.
      const credType = entry.credentials.type;
      if (credType !== 'sorobanCredentialsAddress' && credType !== 'sorobanCredentialsAddressV2') {
        return entry;
      }

      const oldAddrAuth =
        credType === 'sorobanCredentialsAddress' ? entry.credentials.address : entry.credentials.addressV2;
      const networkId = hash(networkPassphrase); // hash() accepts a plain string directly in v17

      // v1 and v2 credentials sign DIFFERENT preimage shapes -- confirmed by reading
      // @stellar/stellar-sdk's own reference `authorizeEntry` implementation
      // (base/auth.js's buildAuthorizationEntryPreimage) directly, after a live signature
      // rejected as InvalidPasskeySignature revealed our client-computed digest didn't match
      // the real on-chain signature_payload (verified byte-for-byte via a diagnostic event
      // dump of the actual __check_auth call). v1 signs the plain
      // envelopeTypeSorobanAuthorization preimage (networkId/nonce/invocation/expiration
      // only). v2 (CAP-71, the variant testnet actually uses) signs
      // envelopeTypeSorobanAuthorizationWithAddress instead -- a DIFFERENT XDR struct that
      // also binds the signer's own address into the signed bytes. Using the v1 preimage
      // shape for a v2 entry silently produces a well-formed but wrong digest: the passkey
      // signs a plausible-looking challenge that the host's real check never matches.
      const preimage =
        credType === 'sorobanCredentialsAddress'
          ? xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
              new xdr.HashIdPreimageSorobanAuthorization({
                networkId,
                nonce: oldAddrAuth.nonce,
                invocation: entry.rootInvocation,
                signatureExpirationLedger: validUntilLedgerSeq,
              })
            )
          : xdr.HashIdPreimage.envelopeTypeSorobanAuthorizationWithAddress(
              new xdr.HashIdPreimageSorobanAuthorizationWithAddress({
                networkId,
                nonce: oldAddrAuth.nonce,
                invocation: entry.rootInvocation,
                address: oldAddrAuth.address,
                signatureExpirationLedger: validUntilLedgerSeq,
              })
            );
      // This 32-byte digest is exactly what account-abstraction-wallet's __check_auth
      // receives as `signature_payload`, and exactly what a real WebAuthn assertion's
      // `challenge` must sign for verify_passkey_signature to accept it on-chain.
      const payload = hash(preimage.toXdr());

      const assertion = await signPasskeyChallenge(credentialIdBuffer, payload);

      const walletSignatureScVal = (walletClient as any).spec.nativeToScVal(
        {
          tag: 'Owner',
          values: [
            {
              client_data_json: assertion.clientDataJSON,
              authenticator_data: assertion.authenticatorData,
              signature: assertion.signature,
            },
          ],
        },
        xdr.ScSpecTypeDef.scSpecTypeUdt(new xdr.ScSpecTypeUdt({ name: 'WalletSignature' }))
      );

      // Set directly, NOT wrapped in scvVec([...]) -- that vec-of-signatures wrapping is
      // the standard-account multi-sig convention the real authorizeEntry hardcodes. A
      // custom account's __check_auth receives whatever ScVal is placed here verbatim as
      // its own `signature: Val` argument.
      //
      // Every XDR value in v17 is immutable (readonly fields, no setters), so the signed
      // entry is a NEW object built from the old one's unchanged fields (address, nonce,
      // rootInvocation) plus the two we're actually setting (signatureExpirationLedger,
      // signature) -- not a mutated clone.
      const newAddrAuth = new xdr.SorobanAddressCredentials({
        address: oldAddrAuth.address,
        nonce: oldAddrAuth.nonce,
        signatureExpirationLedger: validUntilLedgerSeq,
        signature: walletSignatureScVal,
      });
      // Rebuild using whichever variant the network actually sent us -- getting this wrong
      // is exactly the bug being fixed here (see the comment above): silently normalizing
      // to v1 would just move the "returned unsigned" failure from the read side to the
      // write side.
      const newCredentials =
        credType === 'sorobanCredentialsAddress'
          ? xdr.SorobanCredentials.sorobanCredentialsAddress(newAddrAuth)
          : xdr.SorobanCredentials.sorobanCredentialsAddressV2(newAddrAuth);
      return new xdr.SorobanAuthorizationEntry({
        credentials: newCredentials,
        rootInvocation: entry.rootInvocation,
      });
    },
  });

  // The transaction's resource footprint (crucially, the CPU instruction budget) was
  // computed by the FIRST simulation, before our real passkey signature existed -- at that
  // point the auth entry's signature was empty/placeholder. Verifying a real secp256r1
  // (WebAuthn) signature inside __check_auth costs meaningfully more CPU than that
  // placeholder, so the instruction budget locked in by the first simulation undercounts
  // the real cost. Confirmed live via getTransaction() diagnostics on a transaction that
  // the SDK itself reported as sent successfully but that genuinely failed on-chain:
  // resultXdr's operation result was `resource_limit_exceeded`, with a diagnostic event
  // reading "operation instructions exceeds amount specified" during __check_auth. This is
  // not a workaround -- @stellar/stellar-sdk's own assembleTransaction (used internally by
  // simulate()) explicitly preserves already-attached auth entries and only refreshes the
  // resource/fee data when auth is already present, so re-simulating here recomputes the
  // budget for the REAL signed entry without touching the signature we just attached.
  await tx.simulate();

  const sent = await tx.signAndSend();

  // `execute()`'s real Rust signature returns `Val` -- Soroban's fully generic escape-hatch
  // type, not a concrete spec'd return shape. The generated client's automatic native-value
  // decoder (`sent.result`, a getter) can throw on a return value shaped this generically
  // (confirmed live: "Cannot read properties of undefined (reading 'type')" inside
  // `scValToNative`). The actual proof this function exists to provide -- a real,
  // confirmed, passkey-authorized transaction -- doesn't depend on decoding that return
  // value, so a decode failure here is reported, not swallowed silently, but doesn't mask
  // a genuine on-chain success.
  let result: unknown;
  try {
    result = sent.result;
  } catch (err) {
    result = { undecodable: true, reason: (err as Error).message };
  }

  return {
    result,
    txHash: sent.sendTransactionResponse?.hash ?? sent.getTransactionResponse?.txHash ?? '',
  };
}
