# Committed pool ABI (indexer container asset)

`chain.ts` loads the `BongtuPool` ABI at runtime from
`chains/evm/out/BongtuPool.sol/BongtuPool.json` — a **gitignored** forge build
artifact that only exists on a machine that ran `forge build`. To keep the
indexer container **self-contained** (no foundry toolchain in the image build)
and **reproducible** (identical bytes on every `docker build`), the ABI is
committed here and the Dockerfile copies it into the image at exactly that path.

`BongtuPool.abi.json` is the ABI-only slice (`{ "abi": [...] }`) of the forge
artifact — the ~150 KB of EVM bytecode is stripped since the read-only indexer
never deploys. `chain.ts` reads `JSON.parse(file).abi`, so the shape matches.

## Regenerate (after any change to the pool's events or view functions)

```sh
export PATH=$HOME/.foundry/bin:$PATH
cd chains/evm && forge build                      # writes out/BongtuPool.sol/BongtuPool.json
cd ..
node -e 'const fs=require("fs");const a=JSON.parse(fs.readFileSync("chains/evm/out/BongtuPool.sol/BongtuPool.json","utf8"));fs.writeFileSync("apps/indexer/abi/BongtuPool.abi.json",JSON.stringify({abi:a.abi},null,2)+"\n")'
```

The CI `indexer-units` job runs a real `forge build` and then a **drift gate**:
it regenerates this slice from the fresh artifact with the exact command above
and `git diff --exit-code apps/indexer/abi/BongtuPool.abi.json`. So if the pool's
events or view functions change without this committed file being refreshed, that
job fails — the stale ABI cannot reach the Docker image (whose runtime is never
exercised by hosted CI) unnoticed.
