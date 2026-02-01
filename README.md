# UDIF: Universal Digital Identity Framework

## Introduction 

[![Build](https://github.com/QRCS-CORP/MCEL/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/MCEL/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/MCEL/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/MCEL/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/mcel/badge)](https://www.codefactor.io/repository/github/qrcs-corp/mcel)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/MCEL/security/policy)
[![License: QRCS License](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/UDIF/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/MCEL/)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/MCEL)](https://github.com/QRCS-CORP/MCEL/releases/tag/2026-02-01)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/MCEL.svg)](https://github.com/QRCS-CORP/MCEL/commits/main)
[![Custom: Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Custom: Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Communications&color=brightgreen)](#)

# Merkle-Chained Event Ledger (MCEL)

MCEL is a cryptographically verifiable, append-only event ledger designed to provide strong, portable guarantees of integrity, ordering, and auditability for digital records. It is intended as a foundational integrity primitive for systems that must be able to prove, with mathematical certainty, what events occurred and in what order, without relying on consensus protocols, blockchains, or trusted third parties.

MCEL is storage-agnostic, transport-agnostic, and governance-neutral. It can be embedded into applications, services, or infrastructure components to provide durable, tamper-evident evidence trails that remain verifiable across system boundaries and over long time horizons.  


[MCEL Help Documentation](https://qrcs-corp.github.io/MCEL/)  
[MCEL Summary Document](https://qrcs-corp.github.io/MCEL/pdf/mcel_summary.pdf)  
[MCEL Protocol Specification](https://qrcs-corp.github.io/MCEL/pdf/mcel_specification.pdf)  
[MCEL Formal Analysis](https://qrcs-corp.github.io/MCEL/pdf/mcel_formal.pdf)  


## Project Status

**Status:** Complete  
**Stability:** Stable core, API frozen  
**Intended Use:** Production systems, research, and standards-aligned deployments  

MCEL is a completed and self-contained ledger construction with a defined API, formal technical specification, operational diagrams, and security analysis. It is suitable for integration into higher-level systems and protocols.


## Motivation

Most modern systems rely on logs, databases, and procedural controls to establish accountability and compliance. These mechanisms were not designed to be adversarially robust. Records can be modified, reordered, or selectively removed, often without detection, undermining both operational assurance and legal evidentiary value.

MCEL replaces procedural trust with cryptographic assurance. Instead of asserting that a process was followed, MCEL allows independent parties to verify that a specific sequence of events occurred exactly as claimed, and that no record has been altered after the fact.


## Design Goals

MCEL was designed with a deliberately narrow and defensible scope:

- Deterministic, append-only event recording
- Cryptographically enforced ordering and immutability
- Independent, third-party verifiability
- Minimal trusted computing assumptions
- Long-term durability, including post-quantum transition readiness

MCEL does not attempt to provide consensus, confidentiality, access control, or application semantics. These concerns are intentionally left to higher layers.


## Architecture Overview

At its core, MCEL is a hash-based state machine.

Each event is canonically serialized and committed as a leaf in a Merkle structure. The evolving Merkle root, combined with a record count, uniquely identifies the ledger state at any point in time. Any modification to historical data results in an immediately detectable change to the ledger state identifier.

To support operational and audit requirements, MCEL defines several derived artifacts:

- **Records**, immutable event entries
- **Checkpoints**, intermediate ledger state snapshots
- **Seals**, cryptographic commitments to specific ledger states
- **Anchors**, optional bindings of ledger state to external systems or references

All structures are deterministically encoded so that independent implementations produce identical commitments for identical inputs.


## Security Model

MCEL’s security guarantees are based on standard cryptographic assumptions, primarily the collision and second-preimage resistance of the underlying hash functions, and the unforgeability of optional digital signatures.

Key security properties include:

- **Immutability**, where any post-hoc modification is detectable
- **Ordered consistency**, where the relative position of each record is provable
- **Independent verification**, without reliance on the ledger operator
- **Cryptographic agility**, supporting future algorithm transitions

MCEL is compatible with post-quantum cryptographic primitives and is designed to preserve the verifiability of historical records across cryptographic migrations.


## API and Implementation

MCEL is implemented as a compact C library with a stable, well-defined API. It is suitable for use in embedded systems, operating system components, backend services, and security appliances.

The implementation does not require networking, consensus, or specialized hardware. Ledger artifacts can be stored locally, replicated, or distributed through untrusted storage without weakening verification guarantees.


## Use Cases

MCEL is applicable wherever integrity and auditability are first-order requirements, including:

- Regulatory and compliance logging
- Digital evidence and chain-of-custody systems
- Software supply chain and build provenance
- Financial and institutional attestations
- Critical infrastructure and industrial control auditing
- Long-term archival records requiring independent verification

MCEL is particularly effective in environments where storage or operators cannot be fully trusted, but verifiers require strong assurance.


### Cryptographic Dependencies

UDIF will use the [QSC cryptographic library](https://github.com/QRCS-CORP/QSC) for hashing, signatures, and KEM operations.  
*QRCS-PL private License. See license file for details. All rights reserved by QRCS Corporation, copyrighted and patents pending.*

## License

INVESTMENT INQUIRIES:
QRCS is currently seeking a corporate investor for this technology.
Parties interested in licensing or investment should connect to us at: contact@qrcscorp.ca  
Visit https://www.qrcscorp.ca for a full inventory of our products and services.    

PATENT NOTICE:  
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.  

License and Use Notice (2025-2026)  
This repository contains cryptographic reference implementations, test code, and supporting materials published by Quantum Resistant Cryptographic Solutions Corporation (QRCS) for the purposes of public review, cryptographic analysis, interoperability testing, and evaluation.  
All source code and materials in this repository are provided under the Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025-2026, unless explicitly stated otherwise.  
This license permits public access and non commercial research, evaluation, and testing use only. It does not permit production deployment, operational use, or incorporation into any commercial product or service without a separate written agreement executed with QRCS.  
The public availability of this repository is intentional and is provided to support cryptographic transparency, independent security assessment, and compliance with applicable cryptographic publication and export regulations.  
Commercial use, production deployment, supported builds, certified implementations, and integration into products or services require a separate commercial license and support agreement.  
For licensing inquiries, supported implementations, or commercial use, contact: licensing@qrcscorp.ca  
Quantum Resistant Cryptographic Solutions Corporation, 2026.  
_All rights reserved by QRCS Corp. 2026._