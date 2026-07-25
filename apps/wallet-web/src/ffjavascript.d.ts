// snarkjs' curve/field dependency. We touch only `buildBn128` (best-effort proof
// pre-warm in prove.ts) and cast the result at the call site, so an opaque module
// declaration is enough — there is no published @types/ffjavascript.
declare module "ffjavascript";
