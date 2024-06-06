// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.12;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../samples/HybridAccount.sol";

contract TestCaptcha is Ownable {
    address payable immutable helperAddr;
    IERC20 public token;

    uint256 private constant SAFE_GAS_STIPEND = 6000;

    constructor(address payable _helperAddr) {
        helperAddr = _helperAddr;
    }

    event Withdraw(address receiver, uint256 nativeAmount);

    receive() external payable {}

    function withdraw(uint256 _nativeAmount) public onlyOwner {
        (bool sent, ) = msg.sender.call{
            gas: SAFE_GAS_STIPEND,
            value: _nativeAmount
        }("");
        require(sent, "Failed to send native Ether");

        emit Withdraw(msg.sender, _nativeAmount);
    }

    function verifycaptcha(
        string calldata userAddress,
        string calldata uuid,
        string calldata captchaInput
    ) public returns (bool) {
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

    function getBalances()
        public
        view
        returns (uint256 nativeBalance)
    {
        nativeBalance = address(this).balance;
    }
}
