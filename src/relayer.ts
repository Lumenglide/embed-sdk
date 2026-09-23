// Thin client for stellar-gasless-relayer's real /v1/relay endpoint.
//
// Request/response shape matches the relayer's actual handler (stellar-gasless-net/
// stellar-gasless-relayer, src/index.ts) exactly -- not invented here:
//   POST /v1/relay { innerTransactionXdr, dappApiKey, paymasterAddress }
//   -> 200 { success: true, hash, resultXdr }
//   -> 4xx/5xx { success: false, error }

import type { LumenglideConfig } from './types.js';

export interface RelaySuccess {
  success: true;
  hash: string;
  resultXdr: string;
}

export interface RelayFailure {
  success: false;
  error: string;
}

export type RelayResult = RelaySuccess | RelayFailure;

/**
 * Submits an already-built, already-signed inner transaction XDR to a real
 * stellar-gasless-relayer instance for fee-sponsored (gasless) submission. The end user
 * never pays the network fee and never sees a "fund your wallet" prompt -- the relayer's
 * own sponsoring keypair pool covers it via a real FeeBumpTransaction.
 */
export async function relayTransaction(
  config: Pick<LumenglideConfig, 'relayerUrl' | 'relayerApiKey'>,
  innerTransactionXdr: string,
  paymasterAddress?: string
): Promise<RelayResult> {
  const res = await fetch(`${config.relayerUrl.replace(/\/$/, '')}/v1/relay`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': config.relayerApiKey,
    },
    body: JSON.stringify({ innerTransactionXdr, dappApiKey: config.relayerApiKey, paymasterAddress }),
  });

  const body = (await res.json()) as RelayResult;
  return body;
}
