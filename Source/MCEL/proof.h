/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
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

#ifndef MCEL_PROOF_H
#define MCEL_PROOF_H

#include "mcelcommon.h"
#include "mcel.h"
#include "merkle.h"

/**
 * \file mcel_proof.h
 * \brief MCEL Merkle inclusion proof generation and verification
 * 
 * This module extends the base Merkle tree functionality with structured
 * inclusion proof generation and verification. Proofs demonstrate that a
 * specific record exists in a ledger state without revealing other records.
 *
 * Inclusion proofs consist of:
 * - The target record commitment hash
 * - An ordered path of sibling hashes from leaf to root
 * - Direction bits indicating left/right position at each level
 * - Ledger metadata (root, record count, timestamp)
 *
 * Proofs can be serialized for transmission and independently verified
 * against a known Merkle root. This enables selective disclosure scenarios
 * where a party can prove specific records exist without exposing the full
 * ledger history.
 *
 * Typical proof size is ~1KB for ledgers with millions of records.
 */

/*!
 * \def MCEL_PROOF_VERSION
 * \brief The MCEL proof format version.
 */
#define MCEL_PROOF_VERSION 1U

/*!
 * \def MCEL_PROOF_HEADER_SIZE
 * \brief The fixed-size portion of a serialized proof header in bytes.
 */
#define MCEL_PROOF_HEADER_SIZE 50U

/*!
 * \def MCEL_PROOF_MAX_SERIALIZED_SIZE
 * \brief The maximum size of a serialized Merkle proof in bytes.
 */
#define MCEL_PROOF_MAX_SERIALIZED_SIZE (MCEL_PROOF_HEADER_SIZE + (MCEL_MERKLE_PROOF_HASHES_MAX * MCEL_BLOCK_HASH_SIZE) + 4U)

/*!
 * \struct mcel_merkle_proof
 * \brief The MCEL Merkle inclusion proof structure.
 *
 * \details
 * This structure contains all information needed to verify that a specific
 * record exists in a ledger state. The proof includes the sibling hashes
 * needed to reconstruct the path from leaf to root, along with direction
 * bits indicating whether each sibling is on the left or right.
 */
MCEL_EXPORT_API typedef struct mcel_merkle_proof
{
    uint8_t merkleroot[MCEL_BLOCK_HASH_SIZE];   /*!< Ledger Merkle root at proof time */
    uint8_t recordhash[MCEL_BLOCK_HASH_SIZE];   /*!< Target record commitment hash */
    uint8_t** pathhashes;                       /*!< Array of sibling hash pointers */
    uint8_t* pathdirections;                    /*!< Direction bits (0=left, 1=right) */
    uint64_t ledgerrecordcount;                 /*!< Total records in ledger */
    uint64_t recordposition;                    /*!< Position of target record */
    uint64_t prooftimestamp;                    /*!< Proof generation timestamp */
    size_t pathlength;                          /*!< Number of hashes in the path */
    uint8_t version;                            /*!< Proof format version */
} mcel_merkle_proof;

/*!
 * \brief Generate a Merkle inclusion proof for a record at a specific position.
 *
 * \param proof A pointer to the proof structure to populate.
 * \param reccommits [const] Array of all record commitment hashes in the ledger.
 * \param reccount The total number of records in the ledger.
 * \param recposition The position of the target record (0..count-1).
 * \param merkleroot [const] The ledger Merkle root to bind to the proof.
 *
 * \return Returns true if the proof was generated successfully.
 */
MCEL_EXPORT_API bool mcel_proof_generate(mcel_merkle_proof* proof, const uint8_t* reccommits, size_t reccount,
    uint64_t recoposition, const uint8_t* merkleroot);

/*!
 * \brief Verify a Merkle inclusion proof against an expected root.
 *
 * \param proof [const] A pointer to the proof structure to verify.
 * \param exproot [const] The expected Merkle root (32 bytes).
 * \param experecordcount The expected ledger record count.
 *
 * \return Returns true if the proof is valid.
 */
MCEL_EXPORT_API bool mcel_proof_verify(const mcel_merkle_proof* proof, const uint8_t* exproot, uint64_t expreccount);

/*!
 * \brief Serialize a Merkle proof into a canonical byte string.
 *
 * \param output A pointer to the output buffer.
 * \param outlen The length of the output buffer in bytes.
 * \param proof [const] A pointer to the proof structure to serialize.
 * \param written A pointer to receive the number of bytes written.
 *
 * \return Returns true if the proof was serialized successfully.
 */
MCEL_EXPORT_API bool mcel_proof_serialize(uint8_t* output, size_t outlen, const mcel_merkle_proof* proof, size_t* written);

/*!
 * \brief Deserialize a canonical proof byte string into a proof structure.
 *
 * \param proof A pointer to the proof structure to populate.
 * \param input [const] A pointer to the serialized proof bytes.
 * \param inplen The length of the input buffer in bytes.
 *
 * \return Returns true if the proof was deserialized successfully.
 */
MCEL_EXPORT_API bool mcel_proof_deserialize(mcel_merkle_proof* proof, const uint8_t* input, size_t inplen);

/*!
 * \brief Get the required buffer size for a serialized Merkle proof.
 *
 * \param pathlen The number of sibling hashes in the proof path.
 *
 * \return The required buffer size in bytes or 0 on error.
 */
MCEL_EXPORT_API size_t mcel_proof_serialized_size(size_t pathlen);

/*!
 * \brief Free all resources associated with a Merkle proof.
 *
 * \param proof A pointer to the proof structure to dispose.
 */
MCEL_EXPORT_API void mcel_proof_dispose(mcel_merkle_proof* proof);

#endif
