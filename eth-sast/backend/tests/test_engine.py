import pytest

from sast_engine import SoliditySASTEngine


SAMPLE_CODE = '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Test {
    address public owner;

    function initialize(address newOwner) public {
        owner = newOwner;
    }

    function unsafe(uint256 amount) public {
        (bool success, ) = msg.sender.call{value: amount}("");
    }

    function checkTime() public view returns (bool) {
        return block.timestamp > 0;
    }
}
'''


def test_engine_finds_vulnerabilities():
    engine = SoliditySASTEngine(SAMPLE_CODE)
    findings = engine.run_detectors()
    names = {finding.vulnerability for finding in findings}
    assert 'AccessControl' in names
    assert 'TimestampDependence' in names
    assert 'UncheckedReturn' in names
