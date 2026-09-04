/// <reference types="vite/client" />

// Typed build-time env the wallet reads through `import.meta.env`. Vite inlines any
// `VITE_`-prefixed var at build; only the ones the app actually consumes are declared.
interface ImportMetaEnv {
  /** Override the indexer base URL (e.g. `/indexer` to route via the Vite same-origin
   *  proxy for remote/port-forwarded development). Falls back to the localhost default. */
  readonly VITE_INDEXER_URL?: string;
  /** Deployment posture: set to "false" on a non-testnet build to hide every
   *  testnet-only affordance (faucet/mint UI, Testnet chips). Defaults to testnet. */
  readonly VITE_TESTNET?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
