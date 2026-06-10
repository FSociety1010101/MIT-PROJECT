// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Example {
    address public owner;
    bool private locked;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(msg.value > 0, 'No value');
    }

    function withdraw(uint256 amount) external {
        require(msg.sender == owner, 'Not owner');
        (bool success, ) = msg.sender.call{value: amount}('');
        require(success, 'Transfer failed');
    }

    function unsafeWithdraw(uint256 amount) external {
        (bool success, ) = msg.sender.call{value: amount}('');
    }

    function timestampDependent() external view returns (bool) {
        return block.timestamp % 2 == 0;
    }

    function initialize(address newOwner) public {
        owner = newOwner;
    }
}
