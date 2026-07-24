// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {BongtuPool} from "../../src/BongtuPool.sol";

/// @notice Trivial UUPS upgrade target for `Upgrade.t.sol`. It simply extends
///         BongtuPool, so the storage layout is identical (no new state is
///         introduced before or among the inherited slots) and every preserved
///         value — root, nextLeafIndex, nullifiers, arbiter epochs — keeps its
///         slot across the upgrade. The added `version()` marker makes a
///         successful `upgradeToAndCall` observable. `_authorizeUpgrade`
///         (onlyOwner) and the initializer lock are inherited unchanged.
contract BongtuPoolV2 is BongtuPool {
    function version() external pure returns (uint256) {
        return 2;
    }
}
