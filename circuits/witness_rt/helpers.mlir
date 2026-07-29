// bongtu-vendored VERBATIM from rabbitsnark-py third_party/circom_circuits/
// helpers.mlir (r1cs-solver runtime, pin d82213fd). No changes.

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

// Montgomery conversion helpers for circom witness calculator.
//
// Uses field.from_mont / field.to_mont dialect ops for Montgomery ↔ standard
// form conversion, and field.bitcast for reinterpreting between !F and i256.

// Convert Montgomery field element to standard-form i256.
// from_mont(x_mont) = x_mont * R⁻¹ = x
func.func @from_mont(%x: !F) -> i256 {
  %x_std = field.from_mont %x : !F_std
  %result = field.bitcast %x_std : !F_std -> i256
  return %result : i256
}

// Convert standard-form i256 to Montgomery field element.
// to_mont(x) = x * R
func.func @to_mont(%x: i256) -> !F {
  %x_std = field.bitcast %x : i256 -> !F_std
  %result = field.to_mont %x_std : !F
  return %result : !F
}

// Convert array elements from standard-form to Montgomery in-place.
// Raw bytes are standard-form integers; this converts them to !F Montgomery form.
func.func @to_mont_inplace(%arr: memref<?x!F>, %start: index, %count: index)
    attributes { llvm.emit_c_interface } {
  %c1 = arith.constant 1 : index
  %end = arith.addi %start, %count : index
  scf.for %i = %start to %end step %c1 {
    %raw = memref.load %arr[%i] : memref<?x!F>
    %bits = field.bitcast %raw : !F -> i256
    %mont = func.call @to_mont(%bits) : (i256) -> !F
    memref.store %mont, %arr[%i] : memref<?x!F>
  }
  return
}

// Convert array elements from Montgomery to standard-form in-place.
func.func @from_mont_inplace(%arr: memref<?x!F>, %start: index, %count: index)
    attributes { llvm.emit_c_interface } {
  %c1 = arith.constant 1 : index
  %end = arith.addi %start, %count : index
  scf.for %i = %start to %end step %c1 {
    %val = memref.load %arr[%i] : memref<?x!F>
    %std = func.call @from_mont(%val) : (!F) -> i256
    %back = field.bitcast %std : i256 -> !F
    memref.store %back, %arr[%i] : memref<?x!F>
  }
  return
}
