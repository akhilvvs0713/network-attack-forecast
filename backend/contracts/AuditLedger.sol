// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AuditLedger {
    struct SecurityRecord {
        uint256 timestamp;
        string payloadHash;
        uint256 riskScoreX10000;
        string mitreStage;
        bool exists;
    }

    mapping(string => SecurityRecord) public records;

    event SecurityEventLogged(string indexed eventId, string payloadHash, uint256 riskScoreX10000, uint256 timestamp);

    function logEvent(
        string memory eventId,
        string memory payloadHash,
        uint256 riskScoreX10000,
        string memory mitreStage,
        uint256 timestamp
    ) public {
        require(!records[eventId].exists, "Event ID already exists");

        records[eventId] = SecurityRecord({
            timestamp: timestamp,
            payloadHash: payloadHash,
            riskScoreX10000: riskScoreX10000,
            mitreStage: mitreStage,
            exists: true
        });

        emit SecurityEventLogged(eventId, payloadHash, riskScoreX10000, timestamp);
    }
}
