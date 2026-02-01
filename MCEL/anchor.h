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

#ifndef MCEL_ANCHOR_H
#define MCEL_ANCHOR_H

#include "mcelcommon.h"

/**
 * \file anchor.h
 * \brief MCEL anchor support header
 */

/*!
* \def MCEL_ANCHOR_HASH_SIZE
* \brief The MCEL anchor hash size.
*/
#define MCEL_ANCHOR_HASH_SIZE 32U

/*!
* \def MCEL_ANCHOR_REFERENCE_VERSION
* \brief The MCEL anchor reference format version.
*/
#define MCEL_ANCHOR_REFERENCE_VERSION 0x01U

/*!
* \def MCEL_ANCHOR_REFERENCE_HEADER_SIZE
* \brief The fixed-size header portion of an encoded MCEL anchor reference in bytes.
*
* \details
* version(1) | flags(1) | type(1) | reserved(1) | chain_len(2) | ref_len(2)
*/
#define MCEL_ANCHOR_REFERENCE_HEADER_SIZE 8U

/*!
* \struct mcel_anchor_reference
* \brief The MCEL anchor reference container.
*
* \details
* This structure describes an external witness reference (e.g. chain id and transaction id).
* The \c chain_id and \c reference fields point to caller-owned memory.
*/
MCEL_EXPORT_API typedef struct mcel_anchor_reference
{
	uint8_t version;						/*!< The anchor reference format version */
	uint8_t flags;							/*!< Anchor reference flags (reserved for future use) */
	uint8_t type;							/*!< Anchor type identifier (application-defined) */
	uint8_t reserved;						/*!< Reserved, must be 0 */
	uint16_t chain_id_len;					/*!< The chain identifier length in bytes */
	uint16_t reference_len;					/*!< The reference length in bytes */
	const uint8_t* chain_id;				/*!< A pointer to the chain identifier bytes */
	const uint8_t* reference;				/*!< A pointer to the reference bytes (txid, witness id, etc.) */
} mcel_anchor_reference;

/*!
 * \brief Compute a MCEL anchor commitment.
 *
 * \details
 * The anchor commitment binds a checkpoint commitment to an opaque external anchor
 * reference that is canonically encoded by the caller.
 *
 * \param output A pointer to the output commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param chkcommit [const] A pointer to the checkpoint commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param anchref [const] A pointer to the serialized anchor reference bytes.
 * \param reflen The length of the anchor reference in bytes.
 *
 * \return Returns true if the commitment was generated successfully, false on failure.
 */
MCEL_EXPORT_API bool mcel_anchor_commit(uint8_t* output, const uint8_t* chkcommit, const uint8_t* anchref, size_t reflen);

/*!
 * \brief Serialize an anchor reference into a canonical byte string.
 *
 * \param output A pointer to the output buffer.
 * \param outlen The length of the output buffer in bytes.
 * \param anchor [const] A pointer to the anchor reference structure.
 *
 * \return Returns true if the reference was encoded successfully, false on failure.
 */
MCEL_EXPORT_API bool mcel_anchor_reference_encode(uint8_t* output, size_t outlen, const mcel_anchor_reference* anchor);

/*!
 * \brief Get the required buffer size for an encoded MCEL anchor reference.
 *
 * \param cidlen The chain identifier length in bytes.
 * \param reflen The reference length in bytes.
 *
 * \return The required encoded size in bytes, or 0 on error.
 */
MCEL_EXPORT_API size_t mcel_anchor_reference_encoded_size(size_t cidlen, size_t reflen);

/*!
 * \brief Verify a serialized MCEL anchor reference encoding.
 *
 * \details
 * This function verifies that an encoded anchor reference is well-formed and canonical.
 * It does not perform any network or chain validation.
 *
 * \param flags A pointer to the returned flags value, can be NULL.
 * \param type A pointer to the returned type value, can be NULL.
 * \param chainid A pointer to the returned chain identifier pointer, can be NULL.
 * \param chainidlen A pointer to the returned chain identifier length, can be NULL.
 * \param reference A pointer to the returned reference pointer, can be NULL.
 * \param reflen A pointer to the returned reference length, can be NULL.
 * \param input [const] A pointer to the encoded anchor reference bytes.
 * \param inlen The length of the encoded anchor reference in bytes.
 *
 * \return Returns true if the encoding is valid and canonical.
 */
MCEL_EXPORT_API bool mcel_anchor_reference_verify(uint8_t* flags, uint8_t* type, const uint8_t** chainid, uint16_t* chainidlen,
	const uint8_t** reference, uint16_t* reflen, const uint8_t* input, size_t inlen);

#endif
