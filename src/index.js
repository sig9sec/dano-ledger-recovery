"use strict";

const readline = require("readline");

const bip39 = require("bip39");

// Initialize ECC-backed libraries for Bitcoin/BIP32
const ecc = require("tiny-secp256k1");
const bitcoin = require("bitcoinjs-lib");
bitcoin.initEccLib(ecc);
const { BIP32Factory } = require("bip32");
const bip32 = BIP32Factory(ecc);

// Ethers v6
const ethers = require("ethers");
const { HDNodeWallet } = ethers;

// Polkadot ed25519 derivation + keyring
const { derivePath: ed25519DerivePath } = require("ed25519-hd-key");
const { Keyring } = require("@polkadot/keyring");
const { cryptoWaitReady } = require("@polkadot/util-crypto");

function deriveBitcoinBech32(mnemonic, account = 0, change = 0, count = 10) {
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const root = bip32.fromSeed(seed);

  const addresses = [];
  for (let i = 0; i < count; i++) {
    const path = `m/84'/0'/${account}'/${change}/${i}`;
    const child = root.derivePath(path);
    const { publicKey } = child;
    const { address } = bitcoin.payments.p2wpkh({ pubkey: publicKey });
    addresses.push({ path, address });
  }

  return addresses;
}

function deriveEthereum(mnemonic, account = 0, change = 0, count = 10) {
  // In ethers v6, HDNodeWallet.fromPhrase/fromMnemonic defaults to a non-root path (depth 5).
  // To avoid "cannot derive root path ... at non-zero depth" and to ensure BIP44 parity with other wallets,
  // construct the wallet at each explicit full path directly.
  const addresses = [];
  for (let i = 0; i < count; i++) {
    const path = `m/44'/60'/${account}'/${change}/${i}`;
    const wallet = HDNodeWallet.fromPhrase(
      mnemonic,
      undefined,
      path
    );
    addresses.push({ path, address: wallet.address });
  }
  return addresses;
}

async function derivePolkadot(
  mnemonic,
  account = 0,
  change = 0,
  count = 10,
  ss58 = 0,
) {
  // Uses SLIP-0010 ed25519 derivation with BIP39 seed
  // Path: m/44'/354'/account'/change'/index' (all hardened, as most wallets do)
  await cryptoWaitReady();

  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const seedHex = seed.toString("hex");

  const keyring = new Keyring({ type: "ed25519", ss58Format: ss58 });

  const addresses = [];
  for (let i = 0; i < count; i++) {
    const path = `m/44'/354'/${account}'/${change}'/${i}'`;
    const derived = ed25519DerivePath(path, seedHex);
    const privateKey = derived.key; // 32-byte Buffer
    const pair = keyring.addFromSeed(privateKey);
    addresses.push({ path, address: pair.address });
  }
  return addresses;
}

async function askMnemonic() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  const answer = await new Promise((resolve) => {
    rl.question("Enter BIP39 mnemonic: ", (ans) => resolve(ans));
  });
  rl.close();
  return answer.trim();
}

async function main() {
  const argv = process.argv.slice(2);
  let mnemonic = argv.join(" ").trim();

  if (!mnemonic) {
    mnemonic = await askMnemonic();
  }

  if (!bip39.validateMnemonic(mnemonic)) {
    console.error(
      "Invalid mnemonic. Make sure it is a valid BIP39 phrase (no extra passphrase).",
    );
    process.exit(2);
  }

  console.log("Deriving addresses (first 10) — this may take a second...");

  const btc = deriveBitcoinBech32(mnemonic);
  const eth = deriveEthereum(mnemonic);
  const dot = await derivePolkadot(mnemonic);

  const out = { bitcoin_bech32: btc, ethereum: eth, polkadot: dot };
  console.log(JSON.stringify(out, null, 2));
}

main().catch((e) => {
  console.error("Fatal error:", e?.stack || e);
  process.exit(3);
});
