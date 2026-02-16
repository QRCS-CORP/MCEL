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

#ifndef MCEL_QUERY_H
#define MCEL_QUERY_H

#include "mcelcommon.h"
#include "index.h"
#include "mcel.h"

/**
 * \file mcel_query.h
 * \brief MCEL query API for filtering and searching records
 * 
 * This module provides rich query capabilities over MCEL records with support
 * for filtering by time range, record type, flags, and indexed keys. Query
 * execution automatically selects the most efficient strategy based on available
 * indices and filter selectivity.
 *
 * Query strategies (selected automatically):
 * - Index lookup: O(1) for unique key queries with primary index
 * - Index scan: O(k) where k is number of index entries matching filter
 * - Ledger scan: O(n) where n is total number of records
 *
 * Pagination is supported through offset and limit parameters. Results are
 * returned as arrays of record positions that can be used to retrieve full
 * record data from storage.
 */

/*!
 * \def MCEL_QUERY_OFFSET_DEFAULT
 * \brief The default query offset (0 = start from beginning).
 */
#define MCEL_QUERY_OFFSET_DEFAULT 0U

/*!
 * \def MCEL_QUERY_LIMIT_DEFAULT
 * \brief The default query result limit (0 = no limit).
 */
#define MCEL_QUERY_LIMIT_DEFAULT 0U

/*!
 * \def MCEL_QUERY_LIMIT_MAX
 * \brief The maximum number of results that can be returned in a single query.
 */
#define MCEL_QUERY_LIMIT_MAX 10000U

/*!
 * \struct mcel_query_filter
 * \brief The MCEL query filter structure.
 *
 * \details
 * This structure defines the filter criteria for a ledger query. Filters are
 * applied with AND logic (all specified conditions must match). Fields set to
 * zero or NULL are ignored.
 */
MCEL_EXPORT_API typedef struct mcel_query_filter
{
    uint8_t keyid[MCEL_RECORD_KEYID_SIZE];  /*!< Record keyid must match (if filter_by_keyid set) */
    uint8_t* searchkey;                     /*!< Index key to search (NULL = no key filter) */
    uint64_t afterts;                       /*!< Include records after this timestamp (0 = no filter) */
    uint64_t beforets;                      /*!< Include records before this timestamp (0 = no filter) */
    uint64_t limit;                         /*!< Return at most this many results (0 = no limit) */
    uint64_t offset;                        /*!< Skip this many matching results (pagination) */
    size_t searchkeylen;                    /*!< Search key length in bytes */
    uint32_t requiredtype;                  /*!< Record type must match (0 = no filter) */
    uint16_t requiredflags;                 /*!< Record flags must have these bits set (0 = no filter) */
    uint16_t excludedflags;                 /*!< Record flags must NOT have these bits set (0 = no filter) */
    uint8_t filterbykeyid;                  /*!< Non-zero to filter by keyid field */
    uint8_t reverseorder;                   /*!< Non-zero for reverse chronological order */
} mcel_query_filter;

/*!
 * \struct mcel_query_result
 * \brief The MCEL query result structure.
 *
 * \details
 * This structure contains the array of matching record positions and metadata
 * about the query execution. The caller is responsible for freeing the positions
 * array using \c mcel_query_result_dispose.
 */
MCEL_EXPORT_API typedef struct mcel_query_result
{
    uint64_t* recpositions;                 /*!< Array of matching record positions */
    uint64_t querytimeus;                   /*!< Query execution time in microseconds */
    uint64_t totalmatches;                  /*!< Total matching records (if counted) */
    size_t count;                           /*!< Number of results returned */
    uint8_t hasmore;                        /*!< Non-zero if more results exist beyond limit */
    uint8_t usedindex;                      /*!< Non-zero if query used an index */
} mcel_query_result;

/*!
 * \enum mcel_query_strategy
 * \brief Internal query execution strategy identifiers.
 */
typedef enum mcel_query_strategy
{
    mcel_query_strategy_index_lookup = 1U,   /*!< Direct index lookup by key */
    mcel_query_strategy_index_scan = 2U,     /*!< Scan index entries */
    mcel_query_strategy_ledger_scan = 3U     /*!< Full ledger scan */
} mcel_query_strategy;

/*!
 * \brief Execute a query against ledger records.
 *
 * \param result A pointer to the result structure to populate.
 * \param recheaders [const] Array of record header pointers.
 * \param recpayloads [const] Array of record payload pointers (may be NULL).
 * \param payloadlens [const] Array of payload lengths (may be NULL if payloads NULL).
 * \param reccount The total number of records in the ledger.
 * \param filter [const] A pointer to the query filter structure.
 * \param index [const] A pointer to an optional index (NULL for no index).
 *
 * \return Returns true if the query executed successfully.
 */
MCEL_EXPORT_API bool mcel_query_execute(mcel_query_result* result, const void** recheaders,  uint8_t** recpayloads, const size_t* payloadlens,
    size_t reccount, const mcel_query_filter* filter, const mcel_index* index);

/*!
 * \brief Count matching records without retrieving positions.
 *
 * \param countout A pointer to receive the count of matching records.
 * \param recheaders [const] Array of record header pointers.
 * \param reccount The total number of records in the ledger.
 * \param filter [const] A pointer to the query filter structure.
 *
 * \return Returns true if the count succeeded.
 */
MCEL_EXPORT_API bool mcel_query_count(size_t* countout, const void** recheaders, size_t reccount, const mcel_query_filter* filter);

/*!
 * \brief Initialize a query filter with default values.
 *
 * \param filter A pointer to the filter structure to initialize.
 */
MCEL_EXPORT_API void mcel_query_filter_init(mcel_query_filter* filter);

/*!
 * \brief Free resources associated with a query result.
 *
 * \param result A pointer to the result structure to dispose.
 */
MCEL_EXPORT_API void mcel_query_result_dispose(mcel_query_result* result);

#endif
