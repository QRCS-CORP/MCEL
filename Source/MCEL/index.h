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

#ifndef MCEL_INDEX_H
#define MCEL_INDEX_H

#include "mcelcommon.h"

/**
 * \file mcel_index.h
 * \brief MCEL auxiliary indexing layer
 * 
 * This module provides auxiliary indexing over MCEL records to enable efficient
 * O(1) lookup by key. Indices are derivable artifacts that can be rebuilt from
 * the ledger at any time and are not part of the Merkle commitment.
 *
 * Index integrity can be verified by rebuilding from source records. Indices may
 * be corrupted or lost without affecting ledger integrity, though query performance
 * will degrade to O(n) linear scan.
 *
 * Multiple index types are supported to optimize different query patterns:
 * - Primary indices: Map unique keys to single record positions
 * - Secondary indices: Map non-unique keys to multiple record positions
 * - Composite indices: Multi-field key indexing
 *
 * All indices use hash-table implementation with separate chaining for collision
 * resolution. Load factor is maintained between 0.5 and 0.75 with automatic
 * resizing when thresholds are exceeded.
 */

/*!
 * \def MCEL_INDEX_DEFAULT_BUCKETS
 * \brief The default number of hash table buckets for a new index.
 */
#define MCEL_INDEX_DEFAULT_BUCKETS 1024U

/*!
 * \def MCEL_INDEX_LOAD_FACTOR_MAX
 * \brief The maximum load factor before automatic index resize (0.75 = 75%).
 */
#define MCEL_INDEX_LOAD_FACTOR_MAX 0.75

/*!
 * \def MCEL_INDEX_HASH_SIZE
 * \brief The size of the index integrity hash in bytes.
 */
#define MCEL_INDEX_HASH_SIZE 32U

/*!
 * \enum mcel_index_types
 * \brief The MCEL index type identifiers.
 */
MCEL_EXPORT_API typedef enum mcel_index_types
{
    mcel_index_type_primary = 1U,      /*!< Primary index (unique keys) */
    mcel_index_type_secondary = 2U,    /*!< Secondary index (non-unique keys) */
    mcel_index_type_composite = 3U     /*!< Composite multi-field index */
} mcel_index_types;

/*!
 * \struct mcel_index_entry
 * \brief A single index entry mapping key to record position.
 *
 * \details
 * Entries form collision chains via the next pointer. For secondary indices,
 * multiple entries may exist for the same key value.
 */
MCEL_EXPORT_API typedef struct mcel_index_entry
{
    uint8_t* key;                       /*!< Variable-length key bytes */
    size_t keylen;                      /*!< Key length in bytes */
    uint64_t recordpos;                 /*!< Record position in ledger */
    struct mcel_index_entry* next;      /*!< Next entry in collision chain */
} mcel_index_entry;

/*!
 * \struct mcel_index
 * \brief The MCEL index structure.
 *
 * \details
 * This structure maintains an auxiliary hash-table index over MCEL records.
 * The index is not part of the cryptographic commitment and can be rebuilt
 * from source records at any time.
 */
MCEL_EXPORT_API typedef struct mcel_index
{
    uint8_t indexhash[MCEL_INDEX_HASH_SIZE]; /*!< Index integrity hash */
    mcel_index_entry** buckets;         /*!< Hash table bucket array */
    size_t bucketcount;                 /*!< Number of buckets */
    size_t entrycount;                  /*!< Total number of entries */
    uint64_t buildtimestamp;            /*!< Index build time */
    uint64_t indexedthrough;            /*!< Last indexed record position */
    uint8_t indextype;                  /*!< Index type (mcel_index_types) */
} mcel_index;

/*!
 * \typedef mcel_index_key_extractor
 * \brief Function pointer type for extracting index keys from records.
 *
 * \details
 * This callback is invoked during index building to extract one or more keys
 * from each record. The extractor allocates and returns arrays of keys.
 * Records may produce zero keys (not indexed), one key, or multiple keys
 * (for composite or multi-valued indices).
 *
 * \param record_header [const] A pointer to the record header structure.
 * \param record_payload [const] A pointer to the record payload bytes.
 * \param payload_len The payload length in bytes.
 * \param keys_out A pointer to receive the allocated array of key pointers.
 * \param key_lens_out A pointer to receive the allocated array of key lengths.
 *
 * \return The number of keys extracted (0 if record should not be indexed).
 */
typedef size_t (*mcel_index_key_extractor)
(
    const void* recheader,
    const uint8_t* recpayload,
    size_t payloadlen,
    uint8_t*** keysout,
    size_t** keylensout
);

/*!
 * \brief Create and initialize a new MCEL index.
 *
 * \param index A pointer to the index structure to initialize.
 * \param bucketcount The initial number of hash table buckets (0 for default).
 * \param indextype The index type from \c mcel_index_types.
 *
 * \return Returns true if the index was created successfully.
 */
MCEL_EXPORT_API bool mcel_index_create(mcel_index* index, size_t bucketcount, uint8_t indextype);

/*!
 * \brief Insert a key-position mapping into the index.
 *
 * \param index A pointer to the index structure.
 * \param key [const] A pointer to the key bytes.
 * \param keylen The key length in bytes.
 * \param recordpos The record position to associate with this key.
 *
 * \return Returns true if the entry was inserted successfully.
 */
MCEL_EXPORT_API bool mcel_index_insert(mcel_index* index, const uint8_t* key, size_t keylen, uint64_t recordpos);

/*!
 * \brief Lookup record positions for a given key.
 *
 * \param index [const] A pointer to the index structure.
 * \param key [const] A pointer to the key bytes to search for.
 * \param keylen The key length in bytes.
 * \param positionsout A pointer to receive the allocated array of positions.
 * \param countout A pointer to receive the number of matching positions.
 *
 * \return Returns true if the lookup succeeded (even if no matches found).
 */
MCEL_EXPORT_API bool mcel_index_lookup(const mcel_index* index, const uint8_t* key, size_t keylen, uint64_t** positionsout, size_t* countout);

/*!
 * \brief Rebuild an index from ledger records using a key extractor.
 *
 * \param index A pointer to the index structure (will be cleared first).
 * \param recheaders [const] Array of record header pointers.
 * \param recpayloads [const] Array of record payload pointers.
 * \param payloadlens [const] Array of payload lengths.
 * \param reccount The number of records to index.
 * \param extractor The key extraction callback function.
 *
 * \return Returns true if the index was rebuilt successfully.
 */
MCEL_EXPORT_API bool mcel_index_rebuild(mcel_index* index, const void** recheaders, const uint8_t** recpayloads, const size_t* payloadlens,
    size_t reccount, mcel_index_key_extractor extractor);

/*!
 * \brief Update an index incrementally with new records.
 *
 * \param index A pointer to the index structure.
 * \param recheaders [const] Array of new record header pointers.
 * \param recpayloads [const] Array of new record payload pointers.
 * \param payloadlens [const] Array of payload lengths.
 * \param reccount The number of new records to index.
 * \param extractor The key extraction callback function.
 *
 * \return Returns true if the index was updated successfully.
 */
MCEL_EXPORT_API bool mcel_index_update(mcel_index* index, const void** recheaders, const uint8_t** recpayloads, const size_t* payloadlens,
    size_t reccount, mcel_index_key_extractor extractor);

/*!
 * \brief Compute an integrity hash over the index contents.
 *
 * \param index [const] A pointer to the index structure.
 * \param output A pointer to the output hash array of size \c MCEL_INDEX_HASH_SIZE.
 *
 * \return Returns true if the hash was computed successfully.
 */
MCEL_EXPORT_API bool mcel_index_compute_hash(const mcel_index* index, uint8_t* output);

/*!
 * \brief Verify index integrity against source records.
 *
 * \param index [const] A pointer to the index structure to verify.
 * \param recheaders [const] Array of record header pointers.
 * \param recpayloads [const] Array of record payload pointers.
 * \param payloadlens [const] Array of payload lengths.
 * \param reccount The number of records.
 * \param extractor The key extraction callback function.
 *
 * \return Returns true if the index is consistent with source records.
 */
MCEL_EXPORT_API bool mcel_index_verify(const mcel_index* index, const void** recheaders, const uint8_t** recpayloads,
    const size_t* payloadlens, size_t reccount, mcel_index_key_extractor extractor);

/*!
 * \brief Free all resources associated with an index.
 *
 * \param index A pointer to the index structure to dispose.
 */
MCEL_EXPORT_API void mcel_index_dispose(mcel_index* index);

#endif
