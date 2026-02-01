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
 * Contact: contact\qrcscorp.ca
 */

#ifndef MCEL_MERKLE_H
#define MCEL_MERKLE_H

#include "mcelcommon.h"
#include "domain.h"

/**
 * \file merkle.h
 * \brief MCEL merkle support header
 */

/*!
 * \def MCEL_MERKLE_HASH_SIZE
 * \brief The Merkle hash element size in bytes.
 */
#define MCEL_MERKLE_HASH_SIZE 32U

/*!
 * \def MCEL_MERKLE_NODE_SIZE
 * \brief The Merkle internal node input size in bytes (left hash plus right hash).
 */
#define MCEL_MERKLE_NODE_SIZE (MCEL_MERKLE_HASH_SIZE * 2U)

/*!
* \def MCEL_MERKLE_PROOF_HASHES_MAX
* \brief The maximum number of sibling hashes in a MCEL Merkle membership proof.
*
* \details
* This bound supports up to 2^MCEL_MERKLE_PROOF_HASHES_MAX leaves.
*/
#define MCEL_MERKLE_PROOF_HASHES_MAX 32U

/*!
 * \brief Get the required buffer size for a MCEL Merkle consistency proof.
 *
 * \param oldcount The leaf count of the older tree.
 * \param newcount The leaf count of the newer tree.
 *
 * \return The required proof size in bytes or 0 on error.
 */
MCEL_EXPORT_API size_t mcel_merkle_consistency_proof_size(size_t oldcount, size_t newcount);

/*!
 * \brief Get the required buffer size for a MCEL Merkle membership proof.
 *
 * \param count The number of leaves in the tree.
 *
 * \return The required proof size in bytes, or 0 on error.
 */
MCEL_EXPORT_API size_t mcel_merkle_proof_size(size_t count);

/*!
 * \brief Generate a MCEL Merkle membership proof for a leaf index.
 *
 * \param proof A pointer to the output proof buffer.
 * \param prooflen The length of the output proof buffer in bytes.
 * \param leaves [const] A pointer to the leaf hash array (count * MCEL_BLOCK_HASH_SIZE).
 * \param count The number of leaves in the array.
 * \param index The leaf index to prove (0..count-1).
 *
 * \return Returns true if the proof was generated successfully.
 */
MCEL_EXPORT_API bool mcel_merkle_prove_member(uint8_t* proof, size_t prooflen, const uint8_t* leaves, size_t count, size_t index);

/*!
 * \brief Verify a MCEL Merkle membership proof for a leaf hash.
 *
 * \param root A pointer to the Merkle root array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param leaf [const] A pointer to the leaf hash array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param proof [const] A pointer to the proof buffer containing sibling hashes.
 * \param prooflen The length of the proof buffer in bytes.
 * \param count The number of leaves in the tree.
 * \param index The leaf index being proven (0..count-1).
 *
 * \return Returns true if the proof is valid.
 */
MCEL_EXPORT_API bool mcel_merkle_member_verify(const uint8_t* root, const uint8_t* leaf, const uint8_t* proof, size_t prooflen, size_t count, size_t index);

/*!
 * \brief Compute the MCEL Merkle root from an ordered list of leaf hashes.
 *
 * \param root A pointer to the output root hash array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param leaves [const] A pointer to an array of leaf hashes, each of size \c MCEL_BLOCK_HASH_SIZE.
 * \param count The number of leaves in the array.
 *
 * \return Returns true if the Merkle root was computed successfully.
 */
MCEL_EXPORT_API bool mcel_merkle_root(uint8_t* root, const uint8_t* leaves, size_t count);

/*!
 * \brief Compute the MCEL Merkle root hash.
 *
 * \param output A pointer to the output root hash array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param domain The MCEL domain identifier.
 *
 * \return Returns true if the Merkle root was computed successfully.
 */
MCEL_EXPORT_API bool mcel_merkle_root_hash(uint8_t* output, mcel_domain_types domain);

/*!
 * \brief Compute the MCEL Merkle node hash.
 *
 * \param output A pointer to the output node hash array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param left A pointer to left node hash \c MCEL_BLOCK_HASH_SIZE.
 * \param right A pointer to right node hash \c MCEL_BLOCK_HASH_SIZE.
 *
 * \return Returns true if the Merkle root was computed successfully.
 */
MCEL_EXPORT_API bool mcel_merkle_node_hash(uint8_t* output, const uint8_t* left, const uint8_t* right);

#endif
