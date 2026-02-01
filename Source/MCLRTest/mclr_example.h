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

#ifndef MCLR_EXAMPLE_H
#define MCLR_EXAMPLE_H

#include "mclr.h"
#include "mcel.h"

/*
 * mclr_example.c
 *
 * A foundation-style MCLR usage harness:
 * - File-backed mcel_store_callbacks (simple adapter)
 * - QSC SecRand + Dilithium keypair (no MCEL keygen)
 * - Append UDIF-like records as payloads (header + compact event body)
 * - Seal block, seal checkpoint, export bundle, verify bundle, inclusion proof
 */

#define MCLR_EXAMPLE_MAX_PATH (QSC_SYSTEM_MAX_PATH)

static const char MCLR_EXAMPLE_APP_PATH[] = "MCLR";

#pragma pack(push, 1)
typedef struct mclr_example_aad_header
{
    uint64_t seq;       /* monotonic sequence */
    uint64_t utctime;   /* UTC seconds */
    uint64_t epoch;     /* ratchet epoch */
    uint8_t flags;      /* flags */
    uint8_t suiteid;    /* compile-time suite guard */
} mclr_example_aad_header;
#pragma pack(pop)

typedef struct mclr_example_signature_keypair
{
    uint8_t sigkey[MCEL_ASYMMETRIC_SIGNING_KEY_SIZE];   /* the signing key */
    uint8_t verkey[MCEL_ASYMMETRIC_VERIFY_KEY_SIZE];    /* the verification key */
} mclr_example_signature_keypair;

typedef struct mclr_example_storage
{
    char basepath[MCLR_EXAMPLE_MAX_PATH];
} mclr_example_storage;

mclr_errors mclr_example_append_record_test();

mclr_errors mclr_example_initialization_test();

mclr_errors mclr_example_block_seal_test(uint8_t blkroot[MCEL_BLOCK_HASH_SIZE], uint8_t reccommits[3U * MCEL_BLOCK_HASH_SIZE]);

mclr_errors mclr_example_checkpoint_seal_test(uint8_t blkroot[MCEL_BLOCK_HASH_SIZE], uint8_t bundle[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE]);

mclr_errors mclr_example_export_checkpoint_test(uint8_t blkroot[MCEL_BLOCK_HASH_SIZE], uint8_t bundle[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE]);

mclr_errors mclr_example_inclusion_proof_test(uint8_t blkroot[MCEL_BLOCK_HASH_SIZE], uint8_t bundle[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE], uint8_t reccommits[3U * MCEL_BLOCK_HASH_SIZE]);

void mclr_example_cleanup();

#endif