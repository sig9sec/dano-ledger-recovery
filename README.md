# dano-ledger-recovery

Derives first 10 addresses from a BIP39 mnemonic for:

- Bitcoin Native Segwit (BIP84): m/84'/0'/account'/change/index
- Ethereum (BIP44): m/44'/60'/account'/change/index
- Polkadot (SLIP-0010/ed25519 via seed): m/44'/354'/account'/change'/index'

### Install dependencies:

```bash
npm install
```

### Run:

```bash
# Interactive. Prompts if no mnemonic argument is provided (recommended, no seed in terminal history)
npm start

# or pass mnemonic on the command line
npm start -- "abandon abandon ..."
```
