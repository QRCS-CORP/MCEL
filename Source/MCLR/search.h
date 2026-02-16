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

#ifndef MCEL_SEARCH_H
#define MCEL_SEARCH_H

#include "mclr.h"
#include "index.h"
#include "query.h"
#include "proof.h"

/**
 * \file search.h
 * \brief MCLR search and query API using MCEL index/query/proof modules.
 */

/*!
 * \def MCLR_INDEX_SECONDARY_ACTIVE
 * \brief Flag indicating secondary index is active.
 */
#define MCLR_INDEX_SECONDARY_ACTIVE 0x02U

/*!
 * \def MCLR_INDEX_PRIMARY_ACTIVE
 * \brief Flag indicating primary index is active.
 */
#define MCLR_INDEX_PRIMARY_ACTIVE 0x01U

/*!
 * \def MCLR_INDEX_TERTIARY_ACTIVE
 * \brief Flag indicating tertiary index is active.
 */
#define MCLR_INDEX_TERTIARY_ACTIVE 0x04U

/*!
 * \struct mclr_record_proof
 * \brief Merkle inclusion proof for a MCLR record.
 *
 * \details
 * This structure wraps mcel_merkle_proof with MCLR-specific metadata
 * linking the proof to a specific record and block.
 */
typedef struct mclr_record_proof
{
    mcel_merkle_proof mcelproof;                /*!< Underlying MCEL Merkle proof */
    uint64_t recsequence;                       /*!< Record sequence number */
    uint32_t eventtype;                         /*!< Record event type */
} mclr_record_proof;

/*!
 * \struct mclr_search_filter
 * \brief Query filter configuration for MCLR record searches.
 *
 * \details
 * This structure wraps mcel_query_filter with MCLR-specific conveniences
 * and naming. All timestamp, type, and flag filters follow MCEL semantics.
 */
typedef struct mclr_search_filter
{
    mcel_query_filter mcelfilter;               /*!< Underlying MCEL query filter */
    uint32_t eventtype;                         /*!< Filter by specific event type (0 = any) */
    bool useeventtype;                          /*!< Enable event type filtering */
} mclr_search_filter;

/*!
 * \struct mclr_search_index
 * \brief Search index manager for MCLR records.
 *
 * \details
 * This structure manages one or more indices over MCLR records stored in the ledger.
 * Indices are auxiliary data structures that can be rebuilt from the record log
 * and do not affect ledger integrity.
 *
 * The index manager maintains pointers to loaded record headers and payloads
 * that are used during query execution. The caller is responsible for loading
 * records from storage before querying.
 */
typedef struct mclr_search_index
{
    mcel_index primary;                         /*!< Primary index (e.g., by sequence number) */
    mcel_index secondary;                       /*!< Secondary index (e.g., by event type) */
    mcel_index tertiary;                        /*!< Tertiary index (e.g., by keyid) */
    const void** recheaders;                    /*!< Array of record header pointers */
    const uint8_t** recpayloads;                /*!< Array of record payload pointers */
    size_t* payloadlens;                        /*!< Array of payload lengths */
    size_t recordcount;                         /*!< Number of records indexed */
    uint8_t indexflags;                         /*!< Bitfield indicating which indices are active */
} mclr_search_index;

/*!
 * \struct mclr_search_result
 * \brief Query result containing matched record positions.
 *
 * \details
 * This structure wraps mcel_query_result and provides access to the
 * matched record positions. The caller can use these positions to
 * retrieve full records from storage or generate inclusion proofs.
 */
typedef struct mclr_search_result
{
    mcel_query_result mcelresult;               /*!< Underlying MCEL query result */
    const mclr_search_index* sourceindex;       /*!< Source index used for query */
} mclr_search_result;

/*!
 * \brief Deserialize a record proof from bytes.
 *
 * \details
 * Decodes a proof that was previously serialized.
 *
 * \param input [const] A pointer to the input bytes.
 * \param inplen The input buffer size in bytes.
 * \param proof A pointer to the record proof structure to populate.
 *
 * \return Returns mclr_error_none on success, or an error code on failure.
 */
MCLR_EXPORT_API mclr_errors mclr_record_proof_deserialize(const uint8_t* input, size_t inplen, mclr_record_proof* proof);

/*!
 * \brief Dispose of a record proof and free resources.
 *
 * \details
 * Frees memory allocated for the proof path.
 *
 * \param proof A pointer to the record proof structure to dispose.
 */
MCLR_EXPORT_API void mclr_record_proof_dispose(mclr_record_proof* proof);

/*!
 * \brief Serialize a record proof to bytes for transmission or storage.
 *
 * \details
 * Encodes the proof in a canonical binary format that can be transmitted
 * to third parties or stored for later verification.
 *
 * \param proof [const] A pointer to the record proof structure.
 * \param output A pointer to the output buffer.
 * \param outlen The output buffer size in bytes.
 * \param writtenout A pointer to receive the number of bytes written.
 *
 * \return Returns mclr_error_none on success, or an error code on failure.
 */
MCLR_EXPORT_API mclr_errors mclr_record_proof_serialize(const mclr_record_proof* proof, uint8_t* output, size_t outlen, size_t* writtenout);

/*!
 * \brief Calculate the serialized size of a record proof.
 *
 * \details
 * Returns the number of bytes needed to serialize the proof.
 *
 * \param proof [const] A pointer to the record proof structure.
 *
 * \return Returns the serialized size in bytes, or 0 on error.
 */
MCLR_EXPORT_API size_t mclr_record_proof_serialized_size(const mclr_record_proof* proof);

/*!
 * \brief Verify a record inclusion proof.
 *
 * \details
 * Verifies that the proof is valid for the specified record and block root.
 * This function can be used by third parties for independent verification.
 *
 * \param proof [const] A pointer to the record proof structure.
 * \param exproot [const] The expected Merkle root to verify against.
 * \param expreccount The expected total record count in the block.
 *
 * \return Returns mclr_error_none if proof is valid, or an error code on failure.
 */
MCLR_EXPORT_API mclr_errors mclr_record_proof_verify(const mclr_record_proof* proof, const uint8_t* exproot, uint64_t expreccount);

/*!
 * \brief Count matching records without retrieving positions.
 *
 * \details
 * This function counts how many records match the filter criteria without
 * allocating memory for position arrays. Use this for displaying result counts
 * or checking if results exist before executing the full query.
 *
 * \param idx [const] A pointer to the search index structure.
 * \param filter [const] A pointer to the search filter configuration.
 * \param countout A pointer to receive the count of matching records.
 *
 * \return Returns mclr_error_none on success, or an error code on failure.
 */
MCLR_EXPORT_API mclr_errors mclr_search_count(const mclr_search_index* idx, const mclr_search_filter* filter, size_t* countout);

/*!
 * \brief Execute a search query over indexed MCLR records.
 *
 * \details
 * This function executes a filtered search over the indexed records and returns
 * matching record positions. The query automatically selects the optimal strategy
 * based on the filter criteria and available indices.
 *
 * Query strategies:
 * - Index lookup: O(1) for exact key matches using primary index
 * - Index scan: O(k) where k = matching entries in secondary/tertiary indices
 * - Ledger scan: O(n) full record traversal (used when no suitable index exists)
 *
 * \param idx [const] A pointer to the search index structure.
 * \param filter [const] A pointer to the search filter configuration.
 * \param result A pointer to the search result structure to populate.
 *
 * \return Returns mclr_error_none on success, or an error code on failure.
 */
MCLR_EXPORT_API mclr_errors mclr_search_execute(mclr_search_index* idx, const mclr_search_filter* filter, mclr_search_result* result);

/*!
 * \brief Initialize a search filter with default values.
 *
 * \details
 * Sets all filter fields to their default (no filtering) state. After initialization,
 * set specific filter criteria before executing a query.
 *
 * \param filter A pointer to the search filter structure to initialize.
 */
MCLR_EXPORT_API void mclr_search_filter_init(mclr_search_filter* filter);

/*!
 * \brief Set event type filter.
 *
 * \details
 * Filter records by application-defined event type.
 *
 * \param filter A pointer to the search filter structure.
 * \param eventtype The event type to match (0 = match any type, disable filter).
 */
MCLR_EXPORT_API void mclr_search_filter_set_event_type(mclr_search_filter* filter, uint32_t eventtype);

/*!
 * \brief Set record flags filter.
 *
 * \details
 * Filter records by required and excluded flag bits.
 *
 * \param filter A pointer to the search filter structure.
 * \param requiredflags Records must have all these flag bits set.
 * \param excludedflags Records must not have any of these flag bits set.
 */
MCLR_EXPORT_API void mclr_search_filter_set_flags(mclr_search_filter* filter, uint8_t requiredflags, uint8_t excludedflags);

/*!
 * \brief Set keyid filter.
 *
 * \details
 * Filter records by exact keyid match.
 *
 * \param filter A pointer to the search filter structure.
 * \param keyid [const] The keyid to match (size MCEL_RECORD_KEYID_SIZE).
 */
MCLR_EXPORT_API void mclr_search_filter_set_keyid(mclr_search_filter* filter, const uint8_t* keyid);

/*!
 * \brief Set pagination parameters.
 *
 * \details
 * Configure result pagination with offset and limit.
 *
 * \param filter A pointer to the search filter structure.
 * \param offset Skip this many matching records before returning results.
 * \param limit Return at most this many results (0 = no limit).
 */
MCLR_EXPORT_API void mclr_search_filter_set_pagination(mclr_search_filter* filter, size_t offset, size_t limit);

/*!
 * \brief Set result ordering.
 *
 * \details
 * Configure whether results should be returned in chronological or
 * reverse chronological order.
 *
 * \param filter A pointer to the search filter structure.
 * \param revorder If true, return results in reverse chronological order.
 */
MCLR_EXPORT_API void mclr_search_filter_set_ordering(mclr_search_filter* filter, bool revorder);

/*!
 * \brief Set timestamp range filter.
 *
 * \details
 * Filter records within a specific timestamp range (inclusive).
 * Use 0 for after_ts to include all records from the start.
 * Use 0 for before_ts to include all records to the end.
 *
 * \param filter A pointer to the search filter structure.
 * \param afterts Records must have timestamp > after_ts (0 = no lower bound).
 * \param beforets Records must have timestamp < before_ts (0 = no upper bound).
 */
MCLR_EXPORT_API void mclr_search_filter_set_timerange(mclr_search_filter* filter, uint64_t afterts, uint64_t beforets);

/*!
 * \brief Free memory allocated by mclr_search_load_records.
 *
 * \details
 * Frees all arrays allocated by mclr_search_load_records.
 *
 * \param headers A pointer to the header array to free.
 * \param payloads A pointer to the payload array to free.
 * \param payloadlens A pointer to the payload length array to free.
 * \param count The number of elements in each array.
 */
MCLR_EXPORT_API void mclr_search_free_records(void** headers, uint8_t** payloads, size_t* payloadlens, size_t count);

/*!
 * \brief Load a range of MCLR records from storage into memory for indexing/querying.
 *
 * \details
 * This utility function loads records from the MCEL storage backend into
 * memory arrays suitable for passing to mclr_search_index_build. The caller
 * is responsible for freeing the allocated arrays.
 *
 * \param state [const] A pointer to the MCLR logging state.
 * \param startpos The starting storage position to read from.
 * \param count The number of records to load.
 * \param headersout A pointer to receive the allocated header pointer array.
 * \param payloadsout A pointer to receive the allocated payload pointer array.
 * \param payloadlensout A pointer to receive the allocated payload length array.
 *
 * \return Returns mclr_error_none on success, or an error code on failure.
 */
MCLR_EXPORT_API mclr_errors mclr_search_load_records(const mclr_logging_state* state, uint64_t startpos, size_t count, void*** headersout, 
    uint8_t*** payloadsout, size_t** payloadlensout);

/*!
 * \brief Build indices over a range of MCLR records loaded into memory.
 *
 * \details
 * This function builds indices over records that have been loaded from storage.
 * The caller must provide arrays of record headers and payloads. The index
 * structure will store pointers to these arrays, so they must remain valid
 * for the lifetime of the index.
 *
 * Key extractors:
 * - Primary: Extracts sequence number from record header
 * - Secondary: Extracts event type from record header
 * - Tertiary: Extracts keyid from record header
 *
 * \param idx A pointer to the search index structure.
 * \param recheaders [const] Array of pointers to record headers.
 * \param recpayloads [const] Array of pointers to record payloads (can be NULL).
 * \param payloadlens Array of payload lengths (can be NULL if no payloads).
 * \param reccount The number of records to index.
 *
 * \return Returns mclr_error_none on success, or an error code on failure.
 */
MCLR_EXPORT_API mclr_errors mclr_search_index_build(mclr_search_index* idx, const void** recheaders,
    const uint8_t** recpayloads, size_t* payloadlens, size_t reccount);

/*!
 * \brief Create and initialize a MCLR search index.
 *
 * \details
 * Initializes the index structure and creates the specified index types.
 * The primary index is always created and typically indexes by sequence number.
 * Secondary and tertiary indices are optional.
 *
 * \param idx A pointer to the search index structure to initialize.
 * \param createsecondary If true, create a secondary index (e.g., by event type).
 * \param createtertiary If true, create a tertiary index (e.g., by keyid).
 *
 * \return Returns mclr_error_none on success, or an error code on failure.
 */
MCLR_EXPORT_API mclr_errors mclr_search_index_create(mclr_search_index* idx, bool createsecondary, bool createtertiary);

/*!
 * \brief Dispose of search index and free all resources.
 *
 * \details
 * This function frees all memory allocated by the index structures but does
 * not free the record header/payload arrays, which are owned by the caller.
 *
 * \param idx A pointer to the search index structure to dispose.
 */
MCLR_EXPORT_API void mclr_search_index_dispose(mclr_search_index* idx);

/*!
 * \brief Update indices incrementally with newly appended records.
 *
 * \details
 * This function updates existing indices with new records without rebuilding
 * from scratch. Use this after appending new records to the ledger.
 *
 * \param idx A pointer to the search index structure.
 * \param newheaders [const] Array of pointers to new record headers.
 * \param newpayloads [const] Array of pointers to new record payloads (can be NULL).
 * \param newpayloadlens [const] Array of new payload lengths (can be NULL).
 * \param newcount The number of new records to add to indices.
 *
 * \return Returns mclr_error_none on success, or an error code on failure.
 */
MCLR_EXPORT_API mclr_errors mclr_search_index_update(mclr_search_index* idx, const void** newheaders,
    const uint8_t** newpayloads, const size_t* newpayloadlens, size_t newcount);

/*!
 * \brief Verify index integrity by rebuilding and comparing hashes.
 *
 * \details
 * This function rebuilds indices from source records and verifies that the
 * computed index hash matches the stored index. This detects index corruption.
 *
 * \param idx [const] A pointer to the search index structure to verify.
 *
 * \return Returns mclr_error_none if indices are valid, or an error code on failure.
 */
MCLR_EXPORT_API mclr_errors mclr_search_index_verify(const mclr_search_index* idx);

/*!
 * \brief Dispose of search result and free resources.
 *
 * \details
 * Frees memory allocated for the result position array.
 *
 * \param result A pointer to the search result structure to dispose.
 */
MCLR_EXPORT_API void mclr_search_result_dispose(mclr_search_result* result);

/*!
 * \brief Get the record header for a result position.
 *
 * \details
 * Convenience function to retrieve a record header from a search result position.
 *
 * \param result [const] A pointer to the search result structure.
 * \param resindex The index within the result array (0 to result.count-1).
 * \param headerout A pointer to receive the record header pointer.
 *
 * \return Returns mclr_error_none on success, or an error code on failure.
 */
MCLR_EXPORT_API mclr_errors mclr_search_result_get_header(const mclr_search_result* result, size_t resindex, const mcel_record_header** headerout);

/*!
 * \brief Get the record payload for a result position.
 *
 * \details
 * Convenience function to retrieve a record payload from a search result position.
 *
 * \param result [const] A pointer to the search result structure.
 * \param resindex The index within the result array (0 to result.count-1).
 * \param payloadout A pointer to receive the payload pointer.
 * \param payloadlenout A pointer to receive the payload length.
 *
 * \return Returns mclr_error_none on success, or an error code on failure.
 */
MCLR_EXPORT_API mclr_errors mclr_search_result_get_payload(const mclr_search_result* result, size_t resindex, 
    const uint8_t** payloadout, size_t* payloadlenout);

/*!
 * \brief Generate inclusion proofs for all records in a search result.
 *
 * \details
 * Batch proof generation for multiple records. This is more efficient than
 * calling mclr_search_result_generate_proof repeatedly.
 *
 * \param result [const] A pointer to the search result structure.
 * \param reccommits [const] Array of all record commitments in the block.
 * \param commitcount The total number of record commitments.
 * \param blockroot [const] The Merkle root of the block.
 * \param proofs A pointer to an array of proof structures to populate.
 * \param proofscapacity The capacity of the proofs array (must be >= result.count).
 *
 * \return Returns mclr_error_none on success, or an error code on failure.
 */
MCLR_EXPORT_API mclr_errors mclr_search_result_generate_all_proofs(const mclr_search_result* result,
    const uint8_t* reccommits, size_t commitcount, const uint8_t* blockroot,
    mclr_record_proof* proofs, size_t proofscapacity);

/*!
 * \brief Generate a Merkle inclusion proof for a record in a search result.
 *
 * \details
 * This function generates a cryptographic proof that a specific record
 * is included in a Merkle block. The proof can be verified independently
 * by third parties who know only the block root.
 *
 * The proof is compact (approximately 1KB for millions of records) and
 * proves inclusion without revealing other records in the block.
 *
 * \param result [const] A pointer to the search result structure.
 * \param resindex The index within the result array to prove.
 * \param reccommits [const] Array of all record commitments in the block.
 * \param commitcount The total number of record commitments.
 * \param blockroot [const] The Merkle root of the block.
 * \param proof A pointer to the record proof structure to populate.
 *
 * \return Returns mclr_error_none on success, or an error code on failure.
 */
MCLR_EXPORT_API mclr_errors mclr_search_result_generate_proof(const mclr_search_result* result, size_t resindex,
    const uint8_t* reccommits, size_t commitcount, const uint8_t* blockroot, mclr_record_proof* proof);

#endif