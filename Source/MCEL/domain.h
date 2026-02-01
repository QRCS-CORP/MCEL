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

#ifndef MCEL_DOMAIN_H
#define MCEL_DOMAIN_H

#include "mcelcommon.h"

/**
 * \file domain.h
 * \brief MCEL domain support header
 */

/*!
 * \def MCEL_DOMAIN_HASH_SIZE
 * \brief The size of the domain hash in bytes.
 */
#define MCEL_DOMAIN_HASH_SIZE 32U

/*!
 * \def MCEL_DOMAIN_NAME_STRING
 * \brief The MCEL domain name string used for domain separation.
 */
#define MCEL_DOMAIN_NAME_STRING "MCEL-LEDGER"

/*!
 * \def MCEL_DOMAIN_STRING_DEPTH
 * \brief The depth of the MCEL domain string array
 */
#define MCEL_DOMAIN_STRING_DEPTH 8U

/*!
 * \def MCEL_DOMAIN_STRING_WIDTH
 * \brief The width of each MCEL domain string
 */
#define MCEL_DOMAIN_STRING_WIDTH 17U


/*!
 * \enum mcel_domain_types
 * \brief The MCEL hash domain identifiers used to separate commitment types.
 */
MCEL_EXPORT_API typedef enum mcel_domain_types
{
	mcel_domain_none = 0U,				    /*!< Domain type is none */
    mcel_domain_block = 1U,                 /*!< Block commitment domain */
    mcel_domain_checkpoint = 2U,		    /*!< Checkpoint commitment domain */
	mcel_domain_ciphertext = 3U,			/*!< Ciphertext payload commitment domain */
    mcel_domain_node = 4U,				    /*!< Merkle internal node domain */
    mcel_domain_plaintext = 5U,			    /*!< Plaintext payload commitment domain */
    mcel_domain_record = 6U,			    /*!< Record commitment domain */
	mcel_domain_anchor = 7U,				/*!< Anchor commitment domain */
} mcel_domain_types;

static const char USBL_DOMAIN_NAME_STRINGS[MCEL_DOMAIN_STRING_DEPTH][MCEL_DOMAIN_STRING_WIDTH] =
{
	"MCEL-DOMAIN-NONE",
	"MCEL-DOMAIN-BLCK",
	"MCEL-DOMAIN-CHCK",
	"MCEL-DOMAIN-CTXT",
	"MCEL-DOMAIN-NODE",
	"MCEL-DOMAIN-PTXT",
	"MCEL-DOMAIN-RCRD",
	"MCEL-DOMAIN-ANCR",
};

/*!
 * \brief Returns the string representation of the domain types enumeration.
 *
 * \param domain The domain enumeration member.
 *
 * \return Returns a pointer to the domain name string.
 */
MCEL_EXPORT_API const char* mcel_domain_to_name(mcel_domain_types domain);

/*!
 * \brief Compute a 32-byte MCEL domain-separated digest using cSHAKE-256.
 *
 * \param output A pointer to the output hash array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param domain The MCEL domain identifier.
 * \param msg [const] A pointer to the message bytes.
 * \param msglen The length of the message in bytes.
 *
 * \return Returns true on success.
 */
MCEL_EXPORT_API bool mcel_domain_hash_message(uint8_t* output, mcel_domain_types domain, const uint8_t* msg, size_t msglen);

#endif
