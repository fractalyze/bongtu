/// <reference types="vite/client" />

// Typed build-time env the wallet reads through `import.meta.env`. Vite inlines any
// `VITE_`-prefixed var at build; only the ones the app actually consumes are declared.
interface ImportMetaEnv {
  /** Override the indexer base URL (e.g. `/indexer` to route via the Vite same-origin
   *  proxy for remote/port-forwarded development). Falls back to the localhost default. */
  readonly VITE_INDEXER_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
