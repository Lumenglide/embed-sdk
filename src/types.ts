/** A signer callback compatible with @stellar/stellar-sdk's Client `signTransaction` option
 * -- works with Freighter, xBull, or any other wallet adapter that produces a signed XDR. */
export type SignTransaction = (
  xdr: string,
  opts?: { networkPassphrase?: string; address?: string; submit?: boolean; submitUrl?: string }
) => Promise<{ signedTxXdr: string; signerAddress?: string }>;

export interface LumenglideConfig {
  /** Already-installed account-abstraction-wallet wasm hash on the target network. Avoids
   * re-uploading the contract wasm for every new user -- each embed just deploys a fresh
   * instance from this existing hash. */
  walletWasmHash: string;
  networkPassphrase: string;
  rpcUrl: string;
  /** Base URL of a stellar-gasless-relayer instance (see @stellar-gasless-net/stellar-gasless-relayer)
   * used to submit transactions without the end user ever paying or seeing a gas prompt. */
  relayerUrl: string;
  /** API key issued by the relayer operator for this integrating dApp. */
  relayerApiKey: string;
}

export interface SessionKeyGrant {
  sessionKeyAddress: string;
  allowedContract: string;
  allowedFunctions: string[];
  spendCap?: bigint;
  expiresAt: number;
}
