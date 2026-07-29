// bongtu-vendored from rabbitsnark-py third_party/circom_circuits/
// circom_runtime.mlir (r1cs-solver runtime, pin d82213fd). ONE deliberate fix,
// not yet upstreamed: circom.lt/gt/leq/geq compared raw i256 UNSIGNED, but
// circom comparison semantics treat x > (p-1)/2 as negative (val(x) = x - p).
// Zeto's 'for (i = 254; i >= 0; i--)' countdown loops rely on geq(-1, 0) being
// false; unsigned compare made it true => the loop never terminated at i = -1,
// read out of bounds and SIGBUSed. Each comparison now normalizes operands
// (x > h ? x - p : x, h = (p-1)/2) and compares SIGNED. Upstream this to
// r1cs-solver, then re-vendor.

// Copyright 2026 The R1CS Solver Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ==============================================================================

// Circom runtime: implementations of @circom.* functions.
//
// Field operations (add, sub, mul, div, neg, pow) are now emitted as direct
// field.* ops by the compiler. This file only contains ops that need integer
// domain (comparisons, bitwise, shifts, integer div/mod) and component mgmt.
//
// All field values are in Montgomery form (!F). Integer-domain ops convert via
// field.from_mont / field.to_mont at boundaries.

// BN254 prime: p = 21888242871839275222246405745257275088548364400416034343698204186575808495617

// ---------------------------------------------------------------------------
// Integer arithmetic (not field — operates on standard-form integers)
// ---------------------------------------------------------------------------

// Integer division: a \ b (truncated, NOT field division)
func.func @"circom.idiv"(%a: !F, %b: !F) -> !F {
  %a_s = field.from_mont %a : !F_std
  %b_s = field.from_mont %b : !F_std
  %a_i = field.bitcast %a_s : !F_std -> i256
  %b_i = field.bitcast %b_s : !F_std -> i256
  %r_i = arith.divui %a_i, %b_i : i256
  %r_s = field.bitcast %r_i : i256 -> !F_std
  %result = field.to_mont %r_s : !F
  return %result : !F
}

// Modulo: a % b
func.func @"circom.mod"(%a: !F, %b: !F) -> !F {
  %a_s = field.from_mont %a : !F_std
  %b_s = field.from_mont %b : !F_std
  %a_i = field.bitcast %a_s : !F_std -> i256
  %b_i = field.bitcast %b_s : !F_std -> i256
  %r_i = arith.remui %a_i, %b_i : i256
  %r_s = field.bitcast %r_i : i256 -> !F_std
  %result = field.to_mont %r_s : !F
  return %result : !F
}

// ---------------------------------------------------------------------------
// Comparison operators (return field 1 or 0)
// ---------------------------------------------------------------------------

// Equality: can compare Montgomery representations directly
func.func @"circom.eq"(%a: !F, %b: !F) -> !F {
  %a_raw = field.bitcast %a : !F -> i256
  %b_raw = field.bitcast %b : !F -> i256
  %cmp = arith.cmpi eq, %a_raw, %b_raw : i256
  %one = field.constant 1 : !F
  %zero = field.constant 0 : !F
  %result = arith.select %cmp, %one, %zero : !F
  return %result : !F
}

func.func @"circom.neq"(%a: !F, %b: !F) -> !F {
  %a_raw = field.bitcast %a : !F -> i256
  %b_raw = field.bitcast %b : !F -> i256
  %cmp = arith.cmpi ne, %a_raw, %b_raw : i256
  %one = field.constant 1 : !F
  %zero = field.constant 0 : !F
  %result = arith.select %cmp, %one, %zero : !F
  return %result : !F
}

// Ordering comparisons: must convert to standard form (Montgomery doesn't
// preserve ordering)
func.func @"circom.lt"(%a: !F, %b: !F) -> !F {
  // circom semantics: values > (p-1)/2 are negative (val(x) = x - p).
  %p = arith.constant 21888242871839275222246405745257275088548364400416034343698204186575808495617 : i256
  %h = arith.constant 10944121435919637611123202872628637544274182200208017171849102093287904247808 : i256
  %a_s = field.from_mont %a : !F_std
  %b_s = field.from_mont %b : !F_std
  %a_i = field.bitcast %a_s : !F_std -> i256
  %b_i = field.bitcast %b_s : !F_std -> i256
  %a_neg = arith.cmpi ugt, %a_i, %h : i256
  %a_sub = arith.subi %a_i, %p : i256
  %a_adj = arith.select %a_neg, %a_sub, %a_i : i256
  %b_neg = arith.cmpi ugt, %b_i, %h : i256
  %b_sub = arith.subi %b_i, %p : i256
  %b_adj = arith.select %b_neg, %b_sub, %b_i : i256
  %cmp = arith.cmpi slt, %a_adj, %b_adj : i256
  %one = field.constant 1 : !F
  %zero = field.constant 0 : !F
  %result = arith.select %cmp, %one, %zero : !F
  return %result : !F
}

func.func @"circom.gt"(%a: !F, %b: !F) -> !F {
  // circom semantics: values > (p-1)/2 are negative (val(x) = x - p).
  %p = arith.constant 21888242871839275222246405745257275088548364400416034343698204186575808495617 : i256
  %h = arith.constant 10944121435919637611123202872628637544274182200208017171849102093287904247808 : i256
  %a_s = field.from_mont %a : !F_std
  %b_s = field.from_mont %b : !F_std
  %a_i = field.bitcast %a_s : !F_std -> i256
  %b_i = field.bitcast %b_s : !F_std -> i256
  %a_neg = arith.cmpi ugt, %a_i, %h : i256
  %a_sub = arith.subi %a_i, %p : i256
  %a_adj = arith.select %a_neg, %a_sub, %a_i : i256
  %b_neg = arith.cmpi ugt, %b_i, %h : i256
  %b_sub = arith.subi %b_i, %p : i256
  %b_adj = arith.select %b_neg, %b_sub, %b_i : i256
  %cmp = arith.cmpi sgt, %a_adj, %b_adj : i256
  %one = field.constant 1 : !F
  %zero = field.constant 0 : !F
  %result = arith.select %cmp, %one, %zero : !F
  return %result : !F
}

func.func @"circom.leq"(%a: !F, %b: !F) -> !F {
  // circom semantics: values > (p-1)/2 are negative (val(x) = x - p).
  %p = arith.constant 21888242871839275222246405745257275088548364400416034343698204186575808495617 : i256
  %h = arith.constant 10944121435919637611123202872628637544274182200208017171849102093287904247808 : i256
  %a_s = field.from_mont %a : !F_std
  %b_s = field.from_mont %b : !F_std
  %a_i = field.bitcast %a_s : !F_std -> i256
  %b_i = field.bitcast %b_s : !F_std -> i256
  %a_neg = arith.cmpi ugt, %a_i, %h : i256
  %a_sub = arith.subi %a_i, %p : i256
  %a_adj = arith.select %a_neg, %a_sub, %a_i : i256
  %b_neg = arith.cmpi ugt, %b_i, %h : i256
  %b_sub = arith.subi %b_i, %p : i256
  %b_adj = arith.select %b_neg, %b_sub, %b_i : i256
  %cmp = arith.cmpi sle, %a_adj, %b_adj : i256
  %one = field.constant 1 : !F
  %zero = field.constant 0 : !F
  %result = arith.select %cmp, %one, %zero : !F
  return %result : !F
}

func.func @"circom.geq"(%a: !F, %b: !F) -> !F {
  // circom semantics: values > (p-1)/2 are negative (val(x) = x - p).
  %p = arith.constant 21888242871839275222246405745257275088548364400416034343698204186575808495617 : i256
  %h = arith.constant 10944121435919637611123202872628637544274182200208017171849102093287904247808 : i256
  %a_s = field.from_mont %a : !F_std
  %b_s = field.from_mont %b : !F_std
  %a_i = field.bitcast %a_s : !F_std -> i256
  %b_i = field.bitcast %b_s : !F_std -> i256
  %a_neg = arith.cmpi ugt, %a_i, %h : i256
  %a_sub = arith.subi %a_i, %p : i256
  %a_adj = arith.select %a_neg, %a_sub, %a_i : i256
  %b_neg = arith.cmpi ugt, %b_i, %h : i256
  %b_sub = arith.subi %b_i, %p : i256
  %b_adj = arith.select %b_neg, %b_sub, %b_i : i256
  %cmp = arith.cmpi sge, %a_adj, %b_adj : i256
  %one = field.constant 1 : !F
  %zero = field.constant 0 : !F
  %result = arith.select %cmp, %one, %zero : !F
  return %result : !F
}

// ---------------------------------------------------------------------------
// Bitwise operators (integer domain)
// ---------------------------------------------------------------------------

func.func @"circom.shl"(%a: !F, %b: !F) -> !F {
  %p = arith.constant 21888242871839275222246405745257275088548364400416034343698204186575808495617 : i256
  %a_s = field.from_mont %a : !F_std
  %b_s = field.from_mont %b : !F_std
  %a_i = field.bitcast %a_s : !F_std -> i256
  %b_i = field.bitcast %b_s : !F_std -> i256
  %shifted = arith.shli %a_i, %b_i : i256
  %reduced = arith.remui %shifted, %p : i256
  %r_s = field.bitcast %reduced : i256 -> !F_std
  %result = field.to_mont %r_s : !F
  return %result : !F
}

func.func @"circom.shr"(%a: !F, %b: !F) -> !F {
  %a_s = field.from_mont %a : !F_std
  %b_s = field.from_mont %b : !F_std
  %a_i = field.bitcast %a_s : !F_std -> i256
  %b_i = field.bitcast %b_s : !F_std -> i256
  %r_i = arith.shrui %a_i, %b_i : i256
  %r_s = field.bitcast %r_i : i256 -> !F_std
  %result = field.to_mont %r_s : !F
  return %result : !F
}

func.func @"circom.band"(%a: !F, %b: !F) -> !F {
  %a_s = field.from_mont %a : !F_std
  %b_s = field.from_mont %b : !F_std
  %a_i = field.bitcast %a_s : !F_std -> i256
  %b_i = field.bitcast %b_s : !F_std -> i256
  %r_i = arith.andi %a_i, %b_i : i256
  %r_s = field.bitcast %r_i : i256 -> !F_std
  %result = field.to_mont %r_s : !F
  return %result : !F
}

func.func @"circom.bor"(%a: !F, %b: !F) -> !F {
  %a_s = field.from_mont %a : !F_std
  %b_s = field.from_mont %b : !F_std
  %a_i = field.bitcast %a_s : !F_std -> i256
  %b_i = field.bitcast %b_s : !F_std -> i256
  %r_i = arith.ori %a_i, %b_i : i256
  %r_s = field.bitcast %r_i : i256 -> !F_std
  %result = field.to_mont %r_s : !F
  return %result : !F
}

func.func @"circom.bxor"(%a: !F, %b: !F) -> !F {
  %a_s = field.from_mont %a : !F_std
  %b_s = field.from_mont %b : !F_std
  %a_i = field.bitcast %a_s : !F_std -> i256
  %b_i = field.bitcast %b_s : !F_std -> i256
  %r_i = arith.xori %a_i, %b_i : i256
  %r_s = field.bitcast %r_i : i256 -> !F_std
  %result = field.to_mont %r_s : !F
  return %result : !F
}

// ---------------------------------------------------------------------------
// Logical operators
// ---------------------------------------------------------------------------

// Zero in Montgomery form is 0 (since 0 * R = 0), so we can check raw bits.
func.func @"circom.lor"(%a: !F, %b: !F) -> !F {
  %a_raw = field.bitcast %a : !F -> i256
  %b_raw = field.bitcast %b : !F -> i256
  %c0 = arith.constant 0 : i256
  %a_nz = arith.cmpi ne, %a_raw, %c0 : i256
  %b_nz = arith.cmpi ne, %b_raw, %c0 : i256
  %or = arith.ori %a_nz, %b_nz : i1
  %one = field.constant 1 : !F
  %zero = field.constant 0 : !F
  %result = arith.select %or, %one, %zero : !F
  return %result : !F
}

func.func @"circom.land"(%a: !F, %b: !F) -> !F {
  %a_raw = field.bitcast %a : !F -> i256
  %b_raw = field.bitcast %b : !F -> i256
  %c0 = arith.constant 0 : i256
  %a_nz = arith.cmpi ne, %a_raw, %c0 : i256
  %b_nz = arith.cmpi ne, %b_raw, %c0 : i256
  %and = arith.andi %a_nz, %b_nz : i1
  %one = field.constant 1 : !F
  %zero = field.constant 0 : !F
  %result = arith.select %and, %one, %zero : !F
  return %result : !F
}

// ---------------------------------------------------------------------------
// Unary operators
// ---------------------------------------------------------------------------

// Logical NOT: 1 if a == 0, else 0
func.func @"circom.lnot"(%a: !F) -> !F {
  %a_raw = field.bitcast %a : !F -> i256
  %c0 = arith.constant 0 : i256
  %is_zero = arith.cmpi eq, %a_raw, %c0 : i256
  %one = field.constant 1 : !F
  %zero = field.constant 0 : !F
  %result = arith.select %is_zero, %one, %zero : !F
  return %result : !F
}

// Bitwise NOT: complement of all 256 bits, then reduce mod p
func.func @"circom.bnot"(%a: !F) -> !F {
  %p = arith.constant 21888242871839275222246405745257275088548364400416034343698204186575808495617 : i256
  %a_s = field.from_mont %a : !F_std
  %a_i = field.bitcast %a_s : !F_std -> i256
  %all_ones = arith.constant -1 : i256
  %complement = arith.xori %a_i, %all_ones : i256
  %reduced = arith.remui %complement, %p : i256
  %r_s = field.bitcast %reduced : i256 -> !F_std
  %result = field.to_mont %r_s : !F
  return %result : !F
}

// Convert field element to boolean (i1): true if non-zero
func.func @"circom.isTrue"(%a: !F) -> i1 {
  %a_raw = field.bitcast %a : !F -> i256
  %c0 = arith.constant 0 : i256
  %result = arith.cmpi ne, %a_raw, %c0 : i256
  return %result : i1
}

// ---------------------------------------------------------------------------
// Component management
//
// subcmps layout: 3 entries per component
//   subcmps[3*idx + 0] = signalStart
//   subcmps[3*idx + 1] = inputCounter
//   subcmps[3*idx + 2] = templateId
// ---------------------------------------------------------------------------

func.func @"circom.initComponent"(%subcmps: memref<?xindex>,
    %componentIdx: index, %signalStart: index, %numInputs: index,
    %templateId: index) {
  %c3 = arith.constant 3 : index
  %c0 = arith.constant 0 : index
  %c1 = arith.constant 1 : index
  %c2 = arith.constant 2 : index
  %base = arith.muli %componentIdx, %c3 : index
  %slot0 = arith.addi %base, %c0 : index
  %slot1 = arith.addi %base, %c1 : index
  %slot2 = arith.addi %base, %c2 : index
  memref.store %signalStart, %subcmps[%slot0] : memref<?xindex>
  memref.store %numInputs, %subcmps[%slot1] : memref<?xindex>
  memref.store %templateId, %subcmps[%slot2] : memref<?xindex>
  return
}

func.func @"circom.getSignalStart"(%subcmps: memref<?xindex>, %ctx_index: index) -> index {
  %c3 = arith.constant 3 : index
  %base = arith.muli %ctx_index, %c3 : index
  %signalStart = memref.load %subcmps[%base] : memref<?xindex>
  return %signalStart : index
}

func.func @"circom.getSubcmpSignalStart"(%subcmps: memref<?xindex>,
    %cmp_index: index) -> index {
  %c3 = arith.constant 3 : index
  %base = arith.muli %cmp_index, %c3 : index
  %signalStart = memref.load %subcmps[%base] : memref<?xindex>
  return %signalStart : index
}

func.func @"circom.decrementInputCounter"(%subcmps: memref<?xindex>, %cmp_index: index) {
  %c3 = arith.constant 3 : index
  %c1 = arith.constant 1 : index
  %base = arith.muli %cmp_index, %c3 : index
  %slot1 = arith.addi %base, %c1 : index
  %counter = memref.load %subcmps[%slot1] : memref<?xindex>
  %new_counter = arith.subi %counter, %c1 : index
  memref.store %new_counter, %subcmps[%slot1] : memref<?xindex>
  return
}

func.func @"circom.decrementInputCounterAndRun"(%subcmps: memref<?xindex>, %cmp_index: index) {
  %c3 = arith.constant 3 : index
  %c1 = arith.constant 1 : index
  %base = arith.muli %cmp_index, %c3 : index
  %slot1 = arith.addi %base, %c1 : index
  %counter = memref.load %subcmps[%slot1] : memref<?xindex>
  %new_counter = arith.subi %counter, %c1 : index
  memref.store %new_counter, %subcmps[%slot1] : memref<?xindex>
  return
}

// ---------------------------------------------------------------------------
// Logging (stubs)
// ---------------------------------------------------------------------------

func.func @"circom.log_field"(%val: !F) {
  return
}

func.func @"circom.log_str"(%str_id: index) {
  return
}

func.func @"circom.log_newline"() {
  return
}
