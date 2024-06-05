// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "../samples/HybridAccount.sol";

contract TestCaptcha {
    address payable immutable helperAddr;

    constructor(address payable _helperAddr) {
        helperAddr = _helperAddr;
    }

    function verifycaptcha(string calldata userAddress, string calldata uuid, string calldata captchaInput) public returns (bool) {
        HybridAccount ha = HybridAccount(helperAddr);

        bytes memory req = abi.encodeWithSignature(
            "verifyCaptcha(string,string,string)",
            userAddress,
            uuid,
            captchaInput
        );
        bytes32 userKey = bytes32(abi.encode(msg.sender));
        (uint32 error, bytes memory ret) = ha.CallOffchain(userKey, req);

        if (error != 0) {
            revert(string(ret));
        }

        bool isVerified;
        (isVerified) = abi.decode(ret, (bool));
        return isVerified;
    }
}
