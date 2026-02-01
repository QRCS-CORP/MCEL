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

#ifndef MCEL_TEST_FUNCTIONS_H
#define MCEL_TEST_FUNCTIONS_H

#include "mceltestcommon.h"

/**
 * /file functions_test.h internal MCEL functions test implementation.
 *
 * Internal implementation details.
 * This file is not part of the public API.
 */

/*!
 * \brief Run the MCEL hash self-test.
 *
 * \details
 * This test verifies that mcel_domain_hash_message and mcel_merkle_root_hash are consistent
 * with a direct QSC cSHAKE256 invocation using the MCEL name string and the domain
 * customization string.
 *
 * \return Returns true if the test passed.
 */
bool mceltest_hash(void);

/*!
 * \brief Run the MCEL Merkle self-test.
 *
 * \details
 * This test validates merkle_root, membership proof generation, and membership verification,
 * including correct behavior when the leaf count is odd (duplicate-last pairing rule).
 *
 * \return Returns true if the test passed.
 */
bool mceltest_merkle(void);

/*!
 * \brief Run the MCEL record commitment self-test.
 *
 * \details
 * This test validates payload commitment generation and record commitment generation
 * against direct QSC cSHAKE256 invocations, and checks basic domain separation between
 * plaintext and ciphertext payload commitments.
 *
 * \return Returns true if the test passed, false on failure.
 */
bool mceltest_record_commit(void);

/*!
 * \brief Run the MCEL block seal self-test.
 *
 * \details
 * This test validates merkle-root generation from record commitments, block commitment
 * generation, and canonical block encoding layout.
 *
 * \return Returns true if the test passed, false on failure.
 */
bool mceltest_block_seal(void);

/*!
 * \brief Run the MCEL checkpoint seal and verify self-test.
 *
 * \details
 * This test generates a signature keypair, seals two checkpoints (genesis and next),
 * encodes them as bundles, verifies the bundles, and verifies the chain link between them.
 *
 * \return Returns true if the test passed, false on failure.
 */
bool mceltest_checkpoint_seal_verify(void);

/*!
 * \brief Run an end-to-end MCEL self-test over record, block, and checkpoint sealing and verification.
 *
 * \details
 * This test builds deterministic records, seals a block and checkpoint, verifies the bundle,
 * and validates a Merkle membership proof for a selected record commitment.
 *
 * \return Returns true if the test passed, false on failure.
 */
bool mceltest_end_to_end(void);

/*!
 * \brief Run the MCEL Mtest set.
 *
 * \details
 * This test runs all of the function tests in sequence; hash, merkle, records, .
 *
 * \return Returns true if the test passed.
 */
bool mceltest_functions_run(void);

#endif
