// Pure-JS BabyJubJub (twisted Edwards) scalar multiplication.
//
// This is the ONE elliptic-curve op the witness generator needs so that the
// owner public keys we hash into commitments match the circuit's `BabyPbk()`
// gadget, and so ECDH shared secrets match the circuit's `Ecdh()` gadget. The
// workflow env is offline and forbids Math.random, so we avoid a curve
// dependency and implement the group law directly.
//
// Correctness is self-checked (on-curve invariant + ladder-vs-repeated-add) in
// the test suite, and validated end-to-end by the circom prove pipeline: if the
// derived pubkey were wrong, CheckHashes would reject the commitment and
// generate_witness would abort.
//
// Curve (circomlib convention): a*x^2 + y^2 = 1 + d*x^2*y^2 over F_p, with the
// standard order-8*subgroup generator Base8. Addition is unified (the same
// formula doubles), so scalar mult is a plain double-and-add.

// A field element in a form the module accepts as input (coerced via BigInt).
export type FieldInput = bigint | number | string;

// A curve point: exactly two field-element coordinates [x, y].
export type Point = [bigint, bigint];

// A point in input form (coordinates may arrive as number/string and are coerced).
export type PointInput = readonly [FieldInput, FieldInput];

export const P =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Twisted-Edwards curve constants (circomlib convention). Exported so the point
// (de)compression in pubkey.ts recovers x from y off the SAME curve equation.
export const A = 168700n;
export const D = 168696n;

// Standard BabyJubJub base point (matches circomlib BabyPbk's BASE8).
export const Base8: Point = [
  5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  16950150798460657717958625567821834550301663161624707787222815936182638968203n,
];

// Identity element of the twisted Edwards group.
export const IDENTITY: Point = [0n, 1n];

// BabyJubJub prime-order subgroup order = curve order >> 3 (circomlib `subOrder`).
// Base8·L == identity (self-checked in the SDK test suite). Scalar arithmetic that
// matters (EdDSA in eddsa.ts, the wallet KDF reduction) is mod this L.
export const SUBGROUP_ORDER =
  2736030358979909402780800718157159386076813972158567259200215660948447373041n;

// Base-field arithmetic mod P — exported so curve consumers (pubkey.ts point
// (de)compression) share ONE implementation instead of private copies.
export function mod(x: bigint): bigint {
  const r = x % P;
  return r < 0n ? r + P : r;
}

export function modpow(base: bigint, exp: bigint): bigint {
  if (exp <= 0n) return 1n;
  const b = mod(base);
  // MSB-first square-and-multiply over the exponent's bits — identical result
  // to the LSB ladder, expressed as a fold (const-only convention).
  const r = [...exp.toString(2)].reduce((acc, bit) => {
    const sq = mod(acc * acc);
    return bit === "1" ? mod(sq * b) : sq;
  }, 1n);
  return r;
}

// Modular inverse via Fermat's little theorem (P is prime).
export function inv(x: bigint): bigint {
  return modpow(mod(x), P - 2n);
}

// Twisted Edwards addition (unified — also correct for doubling).
export function addPoint([x1, y1]: Point, [x2, y2]: Point): Point {
  const x1x2 = mod(x1 * x2);
  const y1y2 = mod(y1 * y2);
  const dxy = mod(mod(D * x1x2) * y1y2);
  const x3 = mod(mod(mod(x1 * y2) + mod(y1 * x2)) * inv(mod(1n + dxy)));
  const y3 = mod(mod(y1y2 - mod(A * x1x2)) * inv(mod(1n - dxy)));
  return [x3, y3];
}

// scalar * point via double-and-add (LSB-first, matching Num2Bits LE order).
export function mulPointEscalar(point: PointInput, scalar: FieldInput): Point {
  const e = BigInt(scalar);
  if (e < 0n) {
    throw new Error(`mulPointEscalar: scalar must be non-negative, got ${e}`);
  }
  const start: { result: Point; base: Point } = {
    result: [IDENTITY[0], IDENTITY[1]],
    base: [BigInt(point[0]), BigInt(point[1])],
  };
  return [...e.toString(2)].reverse().reduce(
    (acc, bit) => ({
      result: bit === "1" ? addPoint(acc.result, acc.base) : acc.result,
      base: addPoint(acc.base, acc.base),
    }),
    start,
  ).result;
}

// a*x^2 + y^2 == 1 + d*x^2*y^2 — used by the test suite to self-check point ops.
export function isOnCurve([x, y]: PointInput): boolean {
  const xx = mod(BigInt(x) * BigInt(x));
  const yy = mod(BigInt(y) * BigInt(y));
  const lhs = mod(mod(A * xx) + yy);
  const rhs = mod(1n + mod(mod(D * xx) * yy));
  return lhs === rhs;
}
