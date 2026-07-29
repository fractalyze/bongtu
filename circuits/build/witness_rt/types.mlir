// bongtu-vendored from rabbitsnark-py third_party/circom_circuits/types.mlir
// (r1cs-solver runtime, pin d82213fd). ONE deliberate change: the !F_std alias
// drops the explicit ', false' isMontgomery flag — the pinned prime_ir (08220ad)
// parser hard-errors on the literal 'false' (parseModulus only accepts 'true';
// AssemblyFormatUtils.h), and omitting the flag defaults to false, which is
// byte-equivalent. Drop this workaround when prime_ir's parser accepts 'false'.

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

// Type aliases for the circom witness calculator.

// BN254 scalar field (Montgomery form, 256-bit)
!F = !field.pf<21888242871839275222246405745257275088548364400416034343698204186575808495617 : i256, true>
// BN254 scalar field (standard form, for integer-domain operations)
!F_std = !field.pf<21888242871839275222246405745257275088548364400416034343698204186575808495617 : i256>
