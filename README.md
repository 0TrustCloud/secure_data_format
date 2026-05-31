# Secure Data Format (SDF)

SDF is a high-performance, polymorphic cryptographic token engine designed for zero-trust architectures. It standardizes structured logs, permission grants, and hardware proof-of-possession assertions into a single, unified, and cryptographically verifiable data format.

## Architecture Overview

SDF acts as a universal state machine. It consumes OpenGraph-style scripts, compiles them into structured payloads, hashes them into a deterministic state root, and persists them via the `ultimate_db` transactional storage layer.



## Core Features

- **Polymorphic Execution:** A single engine handles logs (`LOG`), capability grants (`GRANT`), and device authentication (`POP`).
- **Cryptographic State Integrity:** Every token is automatically hashed (`state_root_hash`) and signed (RS256), creating an immutable trail of state transitions.
- **Transactional Persistence:** Integrates directly with `ultimate_db` using 2PL (Two-Phase Locking) to ensure atomicity across World State and Transaction Ledgers.
- **Hardened Parsing:** Includes a recursive, depth-limited parser to mitigate DoS/Stack Overflow vectors in dynamic script evaluation.

## Installation

```bash
go get github.com/0TrustCloud/secure_data_format

```

## Quick Start

### 1. Initialize the Engine

The engine is decoupled from storage via the `ultimate_db.KVStore` and `ultimate_db.LockManager` interfaces.

```go
engine, err := securedataformat.New(myKVStore, myLockMgr, "issuer-id", privateKey)

```

### 2. Compile an Execution Script

SDF uses an OpenGraph-style syntax for dynamic contract definition.

```go
script := `
    grant:access.capability#vault-01(
        scope("read")
        conditions:mfa.required("true")
    )
`

tx := securedataformat.DataInvocation{
    TargetAddress: "vault-manager",
    Caller:        "user-admin",
    Method:        "DELEGATE",
    Profile:       securedataformat.ProfileGrant,
}

token, err := engine.CompileSecureData(script, tx)

```

## Security Design

| Feature | Protection Mechanism |
| --- | --- |
| **Replay Attacks** | Automatic JTI generation & nonce sequencing. |
| **Data Tampering** | Canonical JSON state hashing (SHA-256). |
| **DoS Attacks** | Strict recursive AST depth limiting (max 25). |
| **Concurrency** | 2PL via `LockManager` for ACID-compliant state writes. |

## Storage Integration

SDF commits to `ultimate_db` using a bimodal approach:

1. **World State (`state:<profile>:<address>`):** Current snapshot of the target resource state.
2. **Transaction Ledger (`transaction_ledger:<profile>:<address>:<nonce>`):** Immutable receipt of the execution footprint.

## License

MIT
