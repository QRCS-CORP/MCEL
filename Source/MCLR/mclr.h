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

#ifndef MCLR_H
#define MCLR_H

#include "mclrcommon.h"
#include "mcel.h"
#include "fileutils.h"

/*!
 * \file mclr.h
 * \brief Merkle-Chained Log Record (MCLR).
 *
 * \details
 * MCLR is a compact evidence and audit logging interface built around a hash-committed
 * append-only record log, periodic Merkle block sealing, and signed checkpoint chaining.
 * The API provides initialization over a caller-supplied storage backend, record append,
 * block and checkpoint sealing, integrity verification, and inclusion proof generation
 * suitable for third-party audit verification.
 *
 * The library is designed to be deployed as a static component and integrated into an
 * application by supplying \c mcel_store_callbacks for persistence, a namespace identifier
 * to partition ledger instances, and a signature keypair for checkpoint signing and
 * verification. Verification-only configurations may omit the signing key.
 *
 * All public functions return \c mclr_errors unless another return type is more natural
 * for the operation (for example \c size_t for encoded size queries, or \c void for teardown).
 * All public symbols are exported with \c MCLR_EXPORT_API, and all internal parameter
 * assertions use \c MCLR_ASSERT.
 */

/*!
 * \def MCLR_HEADBUF_SIZE 
 * \brief The size of the internal checkpoint head buffer used during initialization and integrity verification.
 */
#define MCLR_HEADBUF_SIZE (MCEL_ASYMMETRIC_SIGNATURE_SIZE + MCEL_CHECKPOINT_BUNDLE_FIXED_SIZE + MCEL_BLOCK_HASH_SIZE)

/*!
 * \enum mclr_errors
 * \brief The MCLR error values.
 */
typedef enum mclr_errors
{
    mclr_error_none = 0U,                           /*!< No error, operation completed successfully */
    mclr_error_invalid_input = 1U,                  /*!< Invalid parameter, null pointer, or inconsistent input */
    mclr_error_initialization = 2U,                 /*!< Ledger, storage, or cryptographic initialization failed */
    mclr_error_integrity_failure = 3U,              /*!< Integrity or linkage verification failed */
    mclr_error_storage_failure = 4U,                /*!< Storage backend read, write, or append failure */
    mclr_error_authentication = 5U,                 /*!< Signature or authentication verification failure */
    mclr_error_record_append = 6U,                  /*!< Failed to append record or commit payload */
    mclr_error_chain_seal = 7U                      /*!< Failed to seal block or checkpoint chain */
} mclr_errors;

/*!
 * \enum mclr_startup_mode
 * \brief Startup and initialization behavior for an MCLR instance.
 */
typedef enum mclr_startup_mode
{
    mclr_startup_create_if_missing = 0U,            /*!< Create a new ledger if none exists */
    mclr_startup_verify_existing = 1U,              /*!< Verify existing ledger, fail if missing */
    mclr_startup_verify_or_create = 2U              /*!< Verify existing ledger or create a new one */
} mclr_startup_mode;

/*!
* \def MCLR_ERROR_STRING_DEPTH
* \brief The depth of the MCLR error string array
*/
#define MCLR_ERROR_STRING_DEPTH 9U

/*!
* \def MCLR_ERROR_STRING_WIDTH
* \brief The width of each MCLR error string
*/
#define MCLR_ERROR_STRING_WIDTH 128U

/** \cond */
static const char MCLR_ERROR_STRINGS[MCLR_ERROR_STRING_DEPTH][MCLR_ERROR_STRING_WIDTH] =
{
    "The operation completed succesfully.",
    "invalid input parameter or inconsistent argument state",
    "failed to initialize ledger, storage, or cryptographic context",
    "integrity check failed, ledger state or cryptographic linkage invalid",
    "storage backend error during read, write, or append operation",
    "authentication or signature verification failure",
    "failed to append record to the log or commit payload",
    "failed to seal block or checkpoint chain",
    "unknown or unspecified mclr error",
};
/** \endcond */

/*!
 * \struct mclr_block_builder
 * \brief A block construction helper that accumulates record commitments for sealing.
 */
typedef struct mclr_block_builder
{
    mcel_block_header header;                       /*!< The block header */
    uint8_t* commits;                               /*!< Caller-provided commit buffer: capacity * MCEL_BLOCK_HASH_SIZE */
    size_t capacity;                                /*!< Number of commits capacity */
    size_t count;                                   /*!< Number of commits written */
} mclr_block_builder;

/*!
 * \struct mclr_checkpoint_receipt
 * \brief Receipt returned after a successful checkpoint sealing operation.
 *
 * \details
 * The receipt contains the checkpoint commitment, the storage log position,
 * and a copy of the checkpoint header that was committed.
 */
typedef struct mclr_checkpoint_receipt
{
    uint8_t check_commit[MCEL_BLOCK_HASH_SIZE];     /*!< The checkpoint commitment hash */
    uint64_t chkplogpos;                            /*!< The checkpoint log position */
    mcel_checkpoint_header header;                  /*!< The committed checkpoint header */
    size_t bundlelen;                               /*!< The encoded checkpoint bundle length */
} mclr_checkpoint_receipt;

/*!
 * \struct mclr_inclusion_proof
 * \brief A Merkle inclusion proof for a record commitment.
 *
 * \details
 * This structure contains all data required to verify that a record
 * commitment is included in a Merkle tree with the specified root.
 * The proof buffer is owned by the caller.
 */
typedef struct mclr_inclusion_proof
{
    uint8_t merkle_root[MCEL_BLOCK_HASH_SIZE];      /*!< The Merkle root */
    uint8_t leaf_commit[MCEL_BLOCK_HASH_SIZE];      /*!< The leaf commitment */
    size_t leafcount;                               /*!< The number of leaves in the tree */
    size_t leafindex;                               /*!< The index of the proven leaf */
    uint8_t* proof;                                 /*!< The Merkle proof buffer */
    size_t proof_len;                               /*!< The proof length in bytes */
} mclr_inclusion_proof;

/*!
 * \struct mclr_logging_state
 * \brief The MCLR logging state context.
 *
 * This structure encapsulates all persistent and runtime state required to
 * operate a Merkle-Chained Log Record (MCLR) instance. It binds together the
 * underlying MCEL ledger state, storage callbacks, cryptographic key material,
 * namespace identity, and scratch buffers required for checkpoint and head
 * management.
 *
 * An instance of this structure is initialized by \c mclr_initialize and must remain
 * valid for the lifetime of all MCLR operations performed on it.
 */
typedef struct mclr_logging_state
{
    mcel_ledger_state ledger;                       /*!< Underlying MCEL ledger state */
    mcel_store_callbacks store;                     /*!< Storage backend callbacks and context */
    const uint8_t* pubkey;                          /*!< Public key used to verify checkpoint signatures */
    size_t pubkeylen;                               /*!< Length of the public verification key in bytes */
    const void* sigkey;                             /*!< Private signing key used for checkpoint sealing */
    uint8_t nsid[MCEL_LEDGER_NAMESPACE_ID_MAX];     /*!< Ledger namespace identifier */
    size_t nsidlen;                                 /*!< Length of the namespace identifier in bytes */
    uint8_t headbuf[MCLR_HEADBUF_SIZE];             /*!< Internal scratch buffer for ledger head operations */
} mclr_logging_state;

/*!
 * \struct mclr_receipt
 * \brief Receipt returned after a successful record append operation.
 *
 * \details
 * The receipt contains the cryptographic commitment of the appended record,
 * the storage log position, and the immutable metadata fields that were
 * committed into the record header.
 */
typedef struct mclr_receipt
{
    uint8_t record_commit[MCEL_BLOCK_HASH_SIZE];    /*!< The record commitment hash */
    uint64_t rcrdlogpos;                            /*!< The storage log position */
    uint64_t sequence;                              /*!< The record sequence number */
    uint64_t timestamp;                             /*!< The record timestamp */
    uint32_t type;                                  /*!< The application-defined event type */
    uint8_t flags;                                  /*!< The record flags */
} mclr_receipt;


/*!
 * \brief Add a record commitment to the builder.
 *
 * \param bldr A pointer to the block builder.
 * \param commit [const] A pointer to the record commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_block_add_commit(mclr_block_builder* bldr, const uint8_t* commit);

/*!
 * \brief Initialize a block builder with a caller-provided commitments buffer.
 *
 * \param bldr A pointer to the block builder.
 * \param commits A pointer to the commitment buffer.
 * \param capacity The number of commitments capacity.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_block_begin(mclr_block_builder* bldr, uint8_t* commits, size_t capacity);

/*!
 * \brief Get the number of bytes required to encode a sealed block containing \c reccount record commitments.
 *
 * \param reccount The number of record commitments in the block.
 *
 * \return Returns the required block encoding buffer size in bytes, or 0 on failure.
 */
MCLR_EXPORT_API size_t mclr_block_encoded_size(size_t reccount);

/*!
 * \brief Seal the block described by the builder into the ledger.
 *
 * \param state A pointer to the MCLR logging state.
 * \param bldr A pointer to the block builder.
 * \param blockbuf A pointer to the block encoding buffer.
 * \param blockbuflen The block buffer length in bytes.
 * \param out_blkroot A pointer to the output block root array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param out_blkcommit A pointer to the output block commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param outpos A pointer to the returned storage log position, can be NULL.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_block_finalize(mclr_logging_state* state, const mclr_block_builder* bldr, uint8_t* blockbuf, size_t blockbuflen,
    uint8_t* outblkroot, uint8_t* outblkcommit, uint64_t* outpos);

/*!
 * \brief Seal a block from an array of record commitments and store the encoded block in the ledger.
 *
 * \param state A pointer to the mclr context structure.
 * \param header [const] A pointer to the block header structure.
 * \param reccommits [const] A pointer to an array of record commitments (reccount * MCEL_HASH_SIZE).
 * \param reccount The number of record commitments.
 * \param blockbuf A pointer to a caller-provided buffer used to encode the sealed block.
 * \param blockbuflen The length of the block buffer in bytes.
 * \param outblkroot A pointer to the output block Merkle root array of size \c MCEL_HASH_SIZE.
 * \param outblkcommit A pointer to the output block commitment array of size \c MCEL_HASH_SIZE.
 * \param outpos A pointer to the returned append position offset, can be NULL.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_block_seal(mclr_logging_state* state, const mcel_block_header* header, const uint8_t* reccommits, size_t reccount,
    uint8_t* blockbuf, size_t blockbuflen, uint8_t* outblkroot, uint8_t* outblkcommit, uint64_t* outpos);

/*!
 * \brief Set the block header for the builder.
 *
 * \param bldr A pointer to the block builder.
 * \param header [const] A pointer to the block header.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_block_set_header(mclr_block_builder* bldr, const mcel_block_header* header);

/*!
 * \brief Build a checkpoint audit path from the checkpoint history log in storage.
 *
 * \details
 * MCEL stores checkpoint bundles by appending them to the checkpoint history location
 * (\c MCEL_STORE_LOC_CHECKPOINTS). This function reads the checkpoint history object,
 * slices the requested checkpoint range, and produces a MCEL audit item array that can
 * be passed to \c mcel_ledger_verify_integrity or chain verification utilities.
 *
 * The audit items point into \c bundlebuf. The caller must keep \c bundlebuf alive for
 * as long as the audit items are used.
 *
 * \param state A pointer to the MCLR context structure.
 * \param from_chk_seq The first checkpoint sequence number to include (1-based).
 * \param to_chk_seq The last checkpoint sequence number to include (1-based, inclusive).
 * \param bundlebuf A pointer to a caller-provided buffer that receives the checkpoint log bytes.
 * \param bundlebuflen The bundle buffer length in bytes, must be large enough for the stored log.
 * \param items A pointer to a caller-provided audit item array.
 * \param itemcount [in,out] On input, the capacity of \c items. On output, the number of items written.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_checkpoint_build_audit_path(mclr_logging_state* state, uint64_t fromchkseq, uint64_t tochkseq, uint8_t* bundlebuf,
    size_t bundlebuflen, mcel_checkpoint_audit_item* items, size_t* itemcount);

/*!
 * \brief Get the number of bytes required to encode a checkpoint bundle containing a signature of \c siglen bytes.
 *
 * \param siglen The signature length in bytes.
 *
 * \return Returns the required checkpoint bundle encoding buffer size in bytes, or 0 on failure.
 */
MCLR_EXPORT_API size_t mclr_checkpoint_bundle_encoded_size(size_t siglen);

/*!
 * \brief Export a checkpoint bundle to a file.
 *
 * \param filepath [const] A pointer to the output file path string.
 * \param bundle [const] A pointer to the bundle bytes.
 * \param bundlelen The bundle length in bytes.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_checkpoint_export_bundle(const char* filepath, const uint8_t* bundle, size_t bundlelen);

/*!
 * \brief Export the checkpoint history log object to a file.
 *
 * \details
 * Reads the full checkpoint history object from \c MCEL_STORE_LOC_CHECKPOINTS and writes it
 * to \c filepath. The caller supplies an I/O buffer that must be large enough to hold the
 * entire checkpoint log.
 *
 * \param state A pointer to the MCLR logging state.
 * \param filepath [const] A pointer to the output file path string.
 * \param iobuf A pointer to the caller-provided I/O buffer.
 * \param iobuflen The length of the I/O buffer in bytes.
 * \param outlen A pointer to the returned number of bytes written.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_checkpoint_export_log(mclr_logging_state* state, const char* filepath, uint8_t* iobuf, size_t iobuflen, size_t* outlen);

/*!
 * \brief Get the current checkpoint head from the ledger state.
 *
 * \param state A pointer to the mclr context structure.
 * \param commit A pointer to the output head checkpoint commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param header A pointer to the output head checkpoint header structure.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_checkpoint_get_head(mclr_logging_state* state, uint8_t* commit, mcel_checkpoint_header* header);

/*!
 * \brief Get the current checkpoint head commitment only.
 *
 * \param state A pointer to the MCLR logging state.
 * \param outcommit A pointer to the output commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_checkpoint_get_head_commit(mclr_logging_state* state, uint8_t* outcommit);

/*!
 * \brief Import a checkpoint bundle from a file path.
 *
 * \details
 * This function loads a serialized MCEL checkpoint bundle from disk into a caller-provided
 * buffer. The caller owns the buffer. This is intended for audits, court exhibits, and
 * offline verification workflows.
 *
 * \param filepath [const] A pointer to the input file path string.
 * \param outbuf A pointer to the output buffer that receives the bundle bytes.
 * \param outbuflen The output buffer length in bytes.
 * \param outlen A pointer to the returned number of bytes read.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_checkpoint_import_bundle(const char* filepath, uint8_t* outbuf, size_t outbuflen, size_t* outlen);

/*!
 * \brief Seal a checkpoint bundle for the current ledger state and store the checkpoint in the checkpoint log.
 *
 * \param state A pointer to the mclr context structure.
 * \param chkeyid [const] A pointer to the checkpoint key identifier array of size \c MCEL_CHECKPOINT_KEYID_SIZE.
 * \param chksequence The checkpoint sequence number.
 * \param firstrecseq The first record sequence number covered by this checkpoint.
 * \param timestamp The checkpoint timestamp value.
 * \param reccount The number of records included in the referenced block.
 * \param chkflags The checkpoint flags.
 * \param blkroot [const] A pointer to the block Merkle root array of size \c MCEL_HASH_SIZE.
 * \param bundlebuf A pointer to the output bundle encoding buffer.
 * \param bundlebuflen The output bundle buffer size in bytes.
 * \param outchk A pointer to the returned checkpoint receipt structure.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_checkpoint_seal(mclr_logging_state* state, const uint8_t* chkeyid, uint64_t chksequence, uint64_t firstrecseq, uint64_t timestamp,
    uint32_t reccount, uint8_t chkflags, const uint8_t* blkroot, uint8_t* bundlebuf, size_t bundlebuflen, mclr_checkpoint_receipt* outchk);

/*!
 * \brief Verify a checkpoint bundle and extract its components.
 *
 * \param bundle [const] A pointer to the checkpoint bundle bytes.
 * \param bundlelen The bundle length in bytes.
 * \param sigpubkey [const] A pointer to the signature verification public key.
 * \param sigpubkeylen The public key length in bytes.
 * \param outchkcommit A pointer to the output checkpoint commitment array of size \c MCEL_HASH_SIZE.
 * \param outhdr A pointer to the output checkpoint header structure.
 * \param outblkroot A pointer to the output block root array of size \c MCEL_HASH_SIZE.
 * \param outprev_commit A pointer to the output previous checkpoint commitment array of size \c MCEL_HASH_SIZE.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_checkpoint_verify_bundle(const uint8_t* bundle, size_t bundlelen, const uint8_t* sigpubkey, size_t sigpubkeylen,
    uint8_t* outchkcommit, mcel_checkpoint_header* outhdr, uint8_t* outblkroot, uint8_t* outprevcommit);

/*!
 * \brief Verify an ordered checkpoint chain represented by checkpoint audit items.
 *
 * \param items [const] A pointer to an array of checkpoint audit items.
 * \param itemcount The number of items in the array.
 * \param sigpubkey [const] A pointer to the signature verification public key.
 * \param sigpubkeylen The public key length in bytes.
 * \param outheadcommit A pointer to the output head checkpoint commitment array of size \c MCEL_HASH_SIZE.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_checkpoint_verify_chain(const mcel_checkpoint_audit_item* items, size_t itemcount,
    const uint8_t* sigpubkey, size_t sigpubkeylen, uint8_t* outheadcommit);

/*!
 * \brief Convert an mclr error code to a constant string.
 *
 * \param err The mclr error code.
 *
 * \return Returns a constant string describing the error.
 */
MCLR_EXPORT_API const char* mclr_error_to_string(mclr_errors err);

/*!
 * \brief Append an evidence or audit event record to the ledger record log.
 *
 * \param state A pointer to the mclr context structure.
 * \param reckeyid [const] A pointer to the record key identifier array of size \c MCEL_RECORD_KEYID_SIZE.
 * \param sequence The record sequence number.
 * \param timestamp The record timestamp value.
 * \param eventtype The application-defined event type identifier.
 * \param flags The record flags.
 * \param payload [const] A pointer to the payload bytes, can be NULL if \c payloadlen is 0.
 * \param payloadlen The payload length in bytes.
 * \param outreceipt A pointer to the returned append receipt structure.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_event_append(mclr_logging_state* state, const uint8_t* reckeyid, uint64_t sequence, uint64_t timestamp, uint32_t eventtype,
    uint8_t flags, const uint8_t* payload, size_t payloadlen, mclr_receipt* outreceipt);

/*!
 * \brief Get the number of bytes required for an inclusion proof for \c leafcount leaves.
 *
 * \param leafcount The number of leaves in the Merkle tree.
 *
 * \return Returns the required proof length in bytes, or 0 on failure.
 */
MCLR_EXPORT_API size_t mclr_inclusion_proof_size(size_t leafcount);

/*!
 * \brief Produce an inclusion proof for a leaf commitment within a Merkle root.
 *
 * \param merkleroot [const] A pointer to the Merkle root array of size \c MCEL_HASH_SIZE.
 * \param leaves [const] A pointer to the leaf commitment array (count * MCEL_HASH_SIZE).
 * \param count The number of leaves.
 * \param index The leaf index to prove.
 * \param proofbuf A pointer to a caller-provided proof buffer.
 * \param proofbuflen The proof buffer length in bytes.
 * \param outproof A pointer to the returned inclusion proof structure.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_inclusion_prove(const uint8_t* merkleroot, const uint8_t* leaves, size_t count,
    size_t index, uint8_t* proofbuf, size_t proofbuflen, mclr_inclusion_proof* outproof);

/*!
 * \brief Verify an inclusion proof structure.
 *
 * \param proof [const] A pointer to the inclusion proof structure.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_inclusion_verify(const mclr_inclusion_proof* proof);

/*!
 * \brief Close and clear an mclr context.
 *
 * \param state A pointer to the mclr context structure.
 */
MCLR_EXPORT_API void mclr_ledger_close(mclr_logging_state* state);

/*!
 * \brief Initialize (open) an mclr ledger namespace and load the checkpoint head if present.
 *
 * \param state A pointer to the mclr context structure.
 * \param store [const] A pointer to an initialized MCEL storage callback table.
 * \param nsid [const] A pointer to the namespace identifier bytes.
 * \param nsidlen The namespace identifier length in bytes.
 * \param pubkey [const] A pointer to the signature verification public key.
 * \param pubkeylen The public key length in bytes.
 * \param sigkey [const] A pointer to the signature signing key, required to seal checkpoints.
 * \param mode The startup mode behavior.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_ledger_initialize(mclr_logging_state* state, const mcel_store_callbacks* store, const uint8_t* nsid, size_t nsidlen,
    const uint8_t* pubkey, size_t pubkeylen, const void* sigkey, mclr_startup_mode mode);

/*!
 * \brief Rotate the signing key and optionally update the public verification key.
 *
 * \details
 * This updates the state key pointers used for sealing and verification. It does not modify
 * existing ledger contents. Applications can keep a key registry for historical verification.
 *
 * \param state A pointer to the MCLR logging state.
 * \param sigkey [const] A pointer to the new signing key object.
 * \param pubkey [const] A pointer to the new public verify key bytes.
 * \param pubkeylen The new public key length in bytes.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_ledger_rotate_signing_key(mclr_logging_state* state, const void* sigkey, const uint8_t* pubkey, size_t pubkeylen);

/*!
 * \brief Verify the cryptographic integrity of the ledger state.
 *
 * \details
 * This function is a thin wrapper over mcel_ledger_verify_integrity, using the mclr context head buffer.
 *
 * \param state A pointer to the mclr context structure.
 * \param audit [const] An optional pointer to an audit path item array, can be NULL.
 * \param auditcount The number of audit items in the array, can be 0.
 *
 * \return Returns the returned mclr error value.
 */
MCLR_EXPORT_API mclr_errors mclr_ledger_verify_integrity(mclr_logging_state* state, const mcel_checkpoint_audit_item* audit, size_t auditcount);

#endif
