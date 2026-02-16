/* 2021-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef MCEL_DOXYMAIN_H
#define MCEL_DOXYMAIN_H

/*!
 * \mainpage MCEL: Merkle Chained Event Ledger
 *
 * \section mcel_overview Overview
 * MCEL is a Merkle rooted, append-only event ledger designed for tamper-evident logging and audit.
 * Records are hash-committed, blocks aggregate record commitments into a Merkle root, and checkpoints
 * cryptographically bind block roots into a signed chain suitable for long-term verification.
 *
 * \section mcel_design Design Summary
 * The library exposes a storage abstraction through callbacks, allowing deployment over files,
 * databases, object stores, or custom persistence layers. The ledger provides:
 * - Deterministic record commitment and append
 * - Merkle block sealing and root commitment
 * - Signed checkpoint bundling and checkpoint chain verification
 * - Inclusion proof generation and verification for audit exhibits
 *
 * \section mcel_storage Storage Contract
 * MCEL uses a caller-supplied storage backend via callback functions. The backend must support
 * querying size, reading, writing, and appending objects identified by location keys.
 *
 * \section mcel_security Security Notes
 * MCEL integrity depends on collision resistance of the hash function and unforgeability of the
 * signature scheme used for checkpoints. Implementations should protect signing keys, enforce
 * strict monotonic sequencing where required by policy, and ensure storage callbacks are atomic
 * for append operations.
 *
 * \section mcel_modules API Modules
 * - \ref mcel_core "Core API"
 * - \ref mcel_record "Record API"
 * - \ref mcel_block "Block API"
 * - \ref mcel_checkpoint "Checkpoint API"
 * - \ref mcel_merkle "Merkle and Proof API"
 * - \ref mcel_store "Storage Callback API"
 *
 * \section mcel_build Build Notes
 * MCEL is intended to be built as a static library. Applications should link MCEL and provide a
 * storage backend implementation through the callback interface.
 *
 * \subsection library_dependencies Cryptographic Dependencies
 * MCEL uses the QSC cryptographic library: <a href="https://github.com/QRCS-CORP/QSC">The QSC Library</a>
 * \section conclusion_sec Conclusion
 *
 * QRCS-PL private License. See license file for details.
 * All rights reserved by QRCS Corporation, copyrighted and patents pending.
 *
 * \author John G. Underhill
 * \date 2026-01-31
 */

/*!
 * \defgroup mcel_core Core API
 * \brief Core initialization, teardown, and configuration. 
 */

/*!
 * \defgroup mcel_record Record API
 * \brief Record encoding, commitment, and append operations.
 */

/*!
 * \defgroup mcel_block Block API
 * \brief Block construction, Merkle root calculation, and block sealing.
 */

/*!
 * \defgroup mcel_checkpoint Checkpoint API
 * \brief Checkpoint bundle creation, signing, export, and verification.
 */

/*!
 * \defgroup mcel_merkle Merkle and Proof API
 * \brief Merkle tree utilities, inclusion proof generation, and verification.
 */

/*!
 * \defgroup mcel_store Storage Callback API
 * \brief Storage backend callbacks and location keys.
 */

#endif
