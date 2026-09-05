// NOTE: this declaration deliberately exists in THREE copies (packages/ui/src
// plus both apps' src): under the raw-source exports model each tsc program
// follows imports into packages/ui/src/prove.ts and needs its own in-program
// ambient module declaration.
// snarkjs' curve/field dependency. We touch only `buildBn128` (best-effort proof
// pre-warm in prove.ts) and cast the result at the call site, so an opaque module
// declaration is enough — there is no published @types/ffjavascript.
declare module "ffjavascript";
