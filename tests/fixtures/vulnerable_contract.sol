pragma solidity ^0.8.20;

contract VulnerableFixture {
    function usesTxOrigin() public view returns (bool) {
        return tx.origin == msg.sender;
    }
}
