import { Keypair, TransactionBuilder } from '@stellar/stellar-sdk';
import { createPasskey, deployPasskeyWallet, executeViaPasskey } from '@lumenglide/embed-sdk';
import type { SignTransaction } from '@lumenglide/embed-sdk';

const config = {
  walletWasmHash: '1b3915d3f408b32ce693ed2b59187d998d3551141b87dda7ea252239f24ea047',
  networkPassphrase: 'Test SDF Network ; September 2015',
  rpcUrl: 'https://soroban-testnet.stellar.org',
  relayerUrl: '',
  relayerApiKey: '',
};

const funderStatus = document.getElementById('funderStatus')!;
const createBtn = document.getElementById('createBtn') as HTMLButtonElement;
const createOut = document.getElementById('createOut')!;
const deployBtn = document.getElementById('deployBtn') as HTMLButtonElement;
const deployOut = document.getElementById('deployOut')!;
const executeBtn = document.getElementById('executeBtn') as HTMLButtonElement;
const executeOut = document.getElementById('executeOut')!;

let passkey: Awaited<ReturnType<typeof createPasskey>> | null = null;
let walletContractId: string | null = null;

async function main() {
  const funder = Keypair.random();
  funderStatus.textContent = `Funder: ${funder.publicKey()} — requesting Friendbot funding...`;

  const res = await fetch(`https://friendbot.stellar.org?addr=${encodeURIComponent(funder.publicKey())}`);
  if (!res.ok) {
    funderStatus.textContent = `Friendbot funding FAILED (${res.status}) for ${funder.publicKey()}`;
    return;
  }
  funderStatus.innerHTML = `Funder funded: <a href="https://stellar.expert/explorer/testnet/account/${funder.publicKey()}" target="_blank">${funder.publicKey()}</a>`;

  const signTransaction: SignTransaction = async (xdr, opts) => {
    const tx = TransactionBuilder.fromXDR(xdr, opts?.networkPassphrase ?? config.networkPassphrase);
    tx.sign(funder);
    return { signedTxXdr: tx.toXDR(), signerAddress: funder.publicKey() };
  };

  createBtn.disabled = false;
  createBtn.onclick = async () => {
    createBtn.disabled = true;
    createOut.textContent = 'Requesting a real passkey from this browser — watch for a prompt...';
    try {
      passkey = await createPasskey('Lumenglide test harness', 'harness-user');
      createOut.textContent = `Real passkey created.\ncredentialIdBase64: ${passkey.credentialIdBase64}\nsec1PublicKeyHex: ${passkey.sec1PublicKeyHex}`;
      deployBtn.disabled = false;
    } catch (err) {
      createOut.textContent = `FAILED: ${(err as Error).message}`;
      createBtn.disabled = false;
    }
  };

  deployBtn.onclick = async () => {
    if (!passkey) return;
    deployBtn.disabled = true;
    deployOut.textContent = 'Deploying a real wallet contract instance and calling init() with the real passkey public key...';
    try {
      walletContractId = await deployPasskeyWallet(config, funder.publicKey(), signTransaction, passkey.sec1PublicKeyHex);
      deployOut.innerHTML = `Deployed and initialized: <a href="https://stellar.expert/explorer/testnet/contract/${walletContractId}" target="_blank">${walletContractId}</a>`;
      executeBtn.disabled = false;
    } catch (err) {
      deployOut.textContent = `FAILED: ${(err as Error).message}\n${(err as Error).stack ?? ''}`;
      deployBtn.disabled = false;
    }
  };

  executeBtn.onclick = async () => {
    if (!passkey || !walletContractId) return;
    executeBtn.disabled = true;
    executeOut.textContent = 'Building a real on-chain execute() call, then asking your passkey to authorize it — watch for a prompt (NOT a wallet extension)...';
    try {
      // Soroban's host forbids a contract calling back into itself ("Contract re-entry is
      // not allowed") -- confirmed via a direct simulation dump when this defaulted to the
      // wallet calling its own get_owner(). Targeting the real native XLM SAC's harmless,
      // no-auth symbol() function instead -- a genuinely different contract, so this
      // actually exercises execute()'s cross-contract call path the way a real dApp
      // integration would, not a self-call Soroban would reject regardless of authorization.
      const NATIVE_XLM_SAC = 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC';
      const { result, txHash } = await executeViaPasskey(config, {
        walletContractId,
        feePayerAddress: funder.publicKey(),
        feePayerSignTransaction: signTransaction,
        credentialIdBuffer: passkey.credentialId,
        targetContractId: NATIVE_XLM_SAC,
        targetFunction: 'symbol',
        targetArgs: [],
      });
      executeOut.innerHTML = `SUCCESS -- authorized ENTIRELY by the passkey.\nnative XLM SAC symbol() returned: ${result}\n<a href="https://stellar.expert/explorer/testnet/tx/${txHash}" target="_blank">view real tx</a>`;
    } catch (err) {
      executeOut.textContent = `FAILED: ${(err as Error).message}\n${(err as Error).stack ?? ''}`;
      executeBtn.disabled = false;
    }
  };
}

main().catch((err) => {
  funderStatus.textContent = `Setup failed: ${err.message}`;
});
