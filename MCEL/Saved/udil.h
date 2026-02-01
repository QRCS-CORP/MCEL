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

#ifndef UDIL_H
#define UDIL_H

#include "udilcommon.h"

 /**
  * \file udil.h
  *
  * \brief UDIL Evidence Ledger API
  *
  * This header defines the public API for the UDIL evidence ledger subsystem.
  * The ledger implements a local, append only, cryptographically verifiable
  * logging structure intended for audit, non-repudiation, and regulatory
  * evidence purposes.
  *
  * The UDIL ledger is designed as a foundational substrate for higher-level
  * systems, including secure financial messaging, asset transfer workflows,
  * and globally anchored provenance systems. It is not a consensus blockchain
  * and does not perform settlement, balance tracking, or global ordering.
  *
  * Core properties provided by this API include:
  *  - Append only record storage with hash chaining
  *  - Deterministic record commitments using Keccak-based hashing
  *  - Cryptographic signatures over records and checkpoints using UDIF keys
  *  - Merkle tree batching and checkpointing for scalable audit
  *  - Inclusion proofs for selective disclosure and sampled verification
  *  - External anchoring references for third-party attestation
  *  - Explicit epoch management for key rotation and administrative resets
  *
  * Records stored in the ledger are opaque to the ledger itself. The ledger
  * does not interpret message semantics, payload formats, or application-level
  * meaning. Its sole responsibility is to provide verifiable evidence of
  * existence, ordering, and authorization.
  *
  * Typical usage flow:
  *  1. Initialize a ledger instance with a stable ledger identifier, epoch,
  *     signing key, and append-only storage backend.
  *  2. Append records representing messages, acknowledgments, or administrative
  *     actions, each producing a signed record commitment.
  *  3. Periodically batch records into checkpoints, producing signed Merkle
  *     roots that summarize ledger state over a sequence range.
  *  4. Optionally anchor checkpoint commitments to an external witness system.
  *  5. Provide inclusion proofs and checkpoint artifacts to auditors,
  *     counterparties, or regulators as required.
  *
  * All cryptographic operations are domain separated and deterministic.
  * Verification of records and checkpoints can be performed independently
  * by third parties without access to private keys or plaintext payloads.
  *
  * This API is intended to be stable and forward compatible. Extensions
  * such as global provenance pillars, cross-ledger anchoring, or asset-level
  * semantics can be layered above this interface without breaking existing
  * evidence guarantees.
  */

//#define UDIL_HASHLEN 32
//#define MAX_DEPTH 64
//
//static const uint8_t TAG_CHK[] = "UDIL/CHK";
//static const uint8_t TAG_ENV[] = "UDIL/ENV";
//static const uint8_t TAG_ID[] = "UDIL/ID";
//static const uint8_t TAG_LEAF[] = "UDIL/LEAF";
//static const uint8_t TAG_NODE[] = "UDIL/NODE";
//static const uint8_t TAG_PAY[] = "UDIL/PAY";
//static const uint8_t TAG_REC[] = "UDIL/REC";
//static const uint8_t TAG_SIG_CHK[] = "UDIL/SIG/CHK";
//static const uint8_t TAG_SIG_REC[] = "UDIL/SIG/REC";
//
//UDIL_EXPORT_API typedef enum
//{
//    RTYPE_MESSAGE = 0x0001,
//    RTYPE_ACK = 0x0002,
//    RTYPE_NACK = 0x0003,
//    RTYPE_RECEIPT = 0x0004,
//    RTYPE_ADMIN = 0x0005,
//    RTYPE_CHECKPOINT = 0x0006,
//    RTYPE_ANCHOR_REF = 0x0007
//} udil_record_type;
//
//UDIL_EXPORT_API typedef struct udil_anchor_ref
//{
//    uint16_t version;
//    uint8_t  chk_commit[UDIL_HASHLEN];
//    uint16_t anchor_type;     // 1=consortium, 2=regulator, 3=provenance-pillar
//    uint8_t  anchor_id[32];   // for example txid hash, receipt id hash
//    uint64_t anchored_time;
//    uint8_t  reserved[16];
//} udil_anchor_ref;
//
//UDIL_EXPORT_API typedef struct udil_merkle_proof
//{
//    uint8_t siblings[MAX_DEPTH][UDIL_HASHLEN];
//    uint8_t directions[MAX_DEPTH];
//    size_t depth;
//} udil_merkle_proof;
//
//UDIL_EXPORT_API typedef struct udil_envelope
//{
//    uint16_t version;
//    uint16_t msg_type;
//    uint8_t  sender_id[UDIL_HASHLEN];
//    uint8_t  receiver_id[UDIL_HASHLEN];
//    uint8_t  corr_id[16];
//    uint64_t time;
//    uint64_t valid_until;
//} udil_envelope;
//
//UDIL_EXPORT_API typedef struct udil_record_hdr
//{
//    uint16_t version;
//    uint16_t rtype;
//    uint8_t  ledger_id[UDIL_HASHLEN];
//    uint32_t epoch;
//    uint64_t seq;
//    uint64_t time;
//    uint8_t  prev_hash[UDIL_HASHLEN];
//    uint8_t  env_hash[UDIL_HASHLEN];
//    uint8_t  pay_hash[UDIL_HASHLEN];
//    uint8_t  corr_id[16];
//    uint32_t flags;
//} udil_record_hdr;
//
//UDIL_EXPORT_API typedef struct udil_checkpoint_body
//{
//    uint16_t body_version;
//    uint8_t  ledger_id[UDIL_HASHLEN];
//    uint32_t epoch;
//    uint64_t start_seq;
//    uint64_t end_seq;
//    uint32_t record_count;
//    uint8_t  batch_root[UDIL_HASHLEN];
//    uint8_t  prev_checkpoint_commit[UDIL_HASHLEN];
//    uint64_t created_time;
//    uint32_t flags;
//    uint8_t  reserved[16];
//} udil_checkpoint_body;
//
//UDIL_EXPORT_API typedef struct udil_ledger_state
//{
//    uint8_t  ledger_id[UDIL_HASHLEN];
//    uint32_t epoch;
//    uint64_t head_seq;
//    uint8_t  head_hash[UDIL_HASHLEN];
//    uint64_t last_checkpoint_end_seq;
//    uint8_t  last_checkpoint_commit[UDIL_HASHLEN];
//    void* udif_signing_key;
//    void* store;
//} udil_ledger_state;
//
//
//int32_t store_append(void* store, const uint8_t* bytes, size_t len);
//int32_t store_read_by_seq(void* store, uint64_t seq, uint8_t** out_bytes, size_t* out_len);
//int32_t store_read_range(void* store, uint64_t start_seq, uint64_t end_seq,
//    uint8_t*** out_records, size_t** out_lens, size_t* out_count);
//int32_t store_get_head(void* store, uint64_t* out_head_seq, uint8_t out_head_hash[UDIL_HASHLEN]);
//int32_t store_set_head(void* store, uint64_t head_seq, const uint8_t head_hash[UDIL_HASHLEN]);
//int32_t store_find_last_checkpoint(void* store, uint8_t out_chk_commit[UDIL_HASHLEN], uint64_t* out_end_seq);
//
//
///**
// * Detect equivocation between two checkpoints (same ledger/epoch, overlapping
// * range, different roots or commitments).
// *
// * Returns:
// *   1 if equivocation is detected, 0 otherwise.
// */
//UDIL_EXPORT_API int32_t udil_audit_detect_equivocation(const udil_checkpoint_body* a, const uint8_t a_commit[UDIL_HASHLEN],
//    const udil_checkpoint_body* b, const uint8_t b_commit[UDIL_HASHLEN]);
//
///**
// * \brief Verify that a record commitment is included in a checkpoint Merkle root (sample audit).
// *
// * This function is used by auditors and counterparties to validate that a given
// * record commitment was incorporated into a checkpointed batch without requiring
// * access to the full ledger or plaintext message content.
// *
// * The verifier recomputes the Merkle root from the provided record commitment
// * and Merkle proof, then compares it to the expected checkpoint root.
// *
// * \param checkpoint_root  The expected 32-byte Merkle root committed by a checkpoint.
// * \param rec_commit       The 32-byte record commitment being proven included.
// * \param proof            The Merkle inclusion proof for rec_commit under checkpoint_root.
// *
// * \return 0 on success (proof verifies and matches checkpoint_root), otherwise a negative error code.
// */
//UDIL_EXPORT_API int32_t udil_audit_sample_inclusion(const uint8_t checkpoint_root[UDIL_HASHLEN], const uint8_t rec_commit[UDIL_HASHLEN], const udil_merkle_proof* proof);
//
// /**
//  * Compute the checkpoint commitment from a checkpoint body.
//  *
//  * chk_commit = SHAKE256("UDIL/CHK" || SER(checkpoint_body), 32)
//  *
//  * out  : [out] 32-byte checkpoint commitment.
//  * body : [in]  checkpoint body.
//  */
//UDIL_EXPORT_API void udil_compute_checkpoint_commit(uint8_t out[UDIL_HASHLEN], const udil_checkpoint_body* body);
//
///**
// * Compute the domain-separated envelope hash.
// *
// * The envelope hash commits to the canonical envelope bytes (message metadata).
// * This is used to prove message identity without storing full payload content.
// *
// * out    : [out] 32-byte hash output.
// * env    : [in]  canonical envelope bytes.
// * envlen : [in]  number of envelope bytes.
// */
//UDIL_EXPORT_API void udil_compute_env_hash(uint8_t out[UDIL_HASHLEN], const uint8_t* env, size_t envlen);
//
///**
// * Compute the domain-separated payload hash.
// *
// * The payload hash commits to the payload bytes or ciphertext bytes (if encrypted).
// *
// * out    : [out] 32-byte hash output.
// * pay    : [in]  payload bytes.
// * paylen : [in]  number of payload bytes.
// */
//UDIL_EXPORT_API void udil_compute_payload_hash(uint8_t out[UDIL_HASHLEN], const uint8_t* pay, size_t paylen);
//
///**
// * Compute the record commitment for a record header.
// *
// * rec_commit = SHAKE256("UDIL/REC" || SER(record_hdr), 32)
// *
// * out : [out] 32-byte record commitment.
// * hdr : [in]  record header fields.
// */
//UDIL_EXPORT_API void udil_compute_record_commit(uint8_t out[UDIL_HASHLEN], const udil_record_hdr* hdr);
//
///**
// * \brief Append an administrative reset record and transition the ledger to a new epoch.
// *
// * This function is used to record and justify a ledger reset event (for example,
// * storage corruption, disaster recovery, or operator-directed reinitialization)
// * while preserving audit continuity.
// *
// * A compliant implementation must:
// *  - Append an ADMIN record containing the reset reason and sufficient metadata
// *    to link the new epoch to the prior ledger state (for example, last checkpoint
// *    commitment and/or head commitment).
// *  - Increment the ledger epoch (or require the caller to do so explicitly, per spec).
// *  - Ensure that future checkpoints chain from the last known checkpoint commitment,
// *    preventing silent history deletion.
// *
// * \param st               Ledger state object.
// * \param reset_reason     UTF-8 or opaque bytes describing the reset reason.
// * \param reason_len       Length of reset_reason in bytes.
// *
// * \return 0 on success, otherwise a negative error code.
// */
//int32_t udil_ledger_admin_reset(udil_ledger_state* st, const uint8_t* reset_reason, size_t reason_len);
//
///**
// * \brief Append a new record to the local evidence ledger.
// *
// * This function appends a new ledger record of the specified type, binding it to:
// *  - The current ledger head (via prev_hash),
// *  - A monotonically increasing sequence number,
// *  - Optional envelope and payload commitments,
// *  - Optional correlation identifier,
// *  - Optional record body bytes.
// *
// * The record commitment is computed over the canonical serialized header fields
// * and is then signed using the UDIF signing key carried in the ledger state.
// * The storage backend is append-only, and the ledger head is updated on success.
// *
// * The function does not interpret message semantics. It stores evidence artifacts.
// *
// * \param st               Ledger state object.
// * \param rtype            Record type (message, ack, receipt, admin, etc.).
// * \param env_hash         Optional 32-byte envelope hash, may be NULL if unused by rtype.
// * \param pay_hash         Optional 32-byte payload hash, may be NULL if unused by rtype.
// * \param corr_id          Optional 16-byte correlation id, may be NULL if unused.
// * \param body             Optional record body bytes (opaque), may be NULL.
// * \param body_len         Length of body in bytes, may be 0.
// * \param out_rec_commit   Optional 32-byte output buffer receiving the computed record commitment.
// *
// * \return 0 on success, otherwise a negative error code.
// */
//UDIL_EXPORT_API int32_t udil_ledger_append(udil_ledger_state* st, udil_record_type rtype, const uint8_t env_hash[UDIL_HASHLEN], const uint8_t pay_hash[UDIL_HASHLEN],
//    const uint8_t corr_id[16], const uint8_t* body, size_t body_len, uint8_t* out_rec_commit);
//
///**
// * \brief Append an external anchoring reference for a checkpoint commitment.
// *
// * This function records that a specific checkpoint commitment has been anchored
// * to an external witness system (for example, a regulator-operated anchor, a
// * consortium witness, or later a global provenance pillar).
// *
// * The anchor reference is evidence that a checkpoint existed at or before some
// * externally attested point in time. The anchor mechanism itself is out of scope
// * for the local ledger and is represented here only by an identifier (receipt id,
// * transaction id hash, or equivalent).
// *
// * \param st   Ledger state object.
// * \param a    Anchor reference structure containing checkpoint commitment and witness identifier.
// *
// * \return 0 on success, otherwise a negative error code.
// */
//UDIL_EXPORT_API int32_t udil_ledger_append_anchor_reference(udil_ledger_state* st, const udil_anchor_ref* a);
//
///**
// * \brief Construct a checkpoint body for a contiguous record range.
// *
// * This function computes the Merkle root over the sequence of record commitments
// * for records in the inclusive range [start_seq, end_seq]. It then populates a
// * checkpoint body that binds:
// *  - ledger_id and epoch,
// *  - the sequence range,
// *  - the record count,
// *  - the computed batch root,
// *  - the previous checkpoint commitment (for checkpoint chaining),
// *  - the checkpoint creation time.
// *
// * This function builds the checkpoint body only. Signing and appending the
// * checkpoint is performed by udil_ledger_issue_checkpoint().
// *
// * \param st         Ledger state object.
// * \param start_seq  First record sequence number in the checkpoint batch (inclusive).
// * \param end_seq    Last record sequence number in the checkpoint batch (inclusive).
// * \param out_body   Output checkpoint body structure.
// *
// * \return 0 on success, otherwise a negative error code.
// */
//UDIL_EXPORT_API int32_t udil_ledger_build_checkpoint_body(udil_ledger_state* st, uint64_t start_seq, uint64_t end_seq, udil_checkpoint_body* out_body);
//
///**
// * \brief Build a Merkle inclusion proof for a target record within a checkpoint range.
// *
// * This function produces an inclusion proof showing that the record at target_seq
// * is included in the Merkle root computed for the inclusive range [start_seq, end_seq].
// *
// * The proof contains sibling hashes and direction bits sufficient for an independent
// * verifier to recompute the Merkle root from out_rec_commit and the proof, and compare
// * it to out_root (or to a checkpoint’s batch_root).
// *
// * \param st             Ledger state object.
// * \param start_seq      First record sequence number in the proof batch (inclusive).
// * \param end_seq        Last record sequence number in the proof batch (inclusive).
// * \param target_seq     Sequence number of the record to prove included.
// * \param out_proof      Output Merkle proof structure.
// * \param out_rec_commit Output 32-byte record commitment for target_seq.
// * \param out_root       Output 32-byte Merkle root for [start_seq, end_seq].
// *
// * \return 0 on success, otherwise a negative error code.
// */
//UDIL_EXPORT_API int32_t udil_ledger_build_inclusion_proof(udil_ledger_state* st, uint64_t start_seq, uint64_t end_seq, uint64_t target_seq,
//    udil_merkle_proof* out_proof, uint8_t out_rec_commit[UDIL_HASHLEN], uint8_t out_root[UDIL_HASHLEN]);
//
///**
// * \brief Initialize a ledger state and load persistent head and checkpoint state from storage.
// *
// * This function initializes the in-memory ledger state with its fixed identity and
// * operational parameters, then synchronizes it with the persistent storage backend.
// *
// * A compliant implementation should:
// *  - Set ledger_id and epoch.
// *  - Associate the UDIF signing key used for signing new records and checkpoints.
// *  - Associate the append-only storage backend.
// *  - Load the current head sequence and head commitment from storage, or set a
// *    genesis head if storage is empty.
// *  - Load the last checkpoint commitment and its end sequence if available.
// *
// * \param st               Ledger state object to initialize.
// * \param ledger_id        Stable 32-byte identifier for this ledger instance.
// * \param epoch            Epoch number (incremented on reset or signing-key rollover).
// * \param udif_signing_key Opaque handle to the UDIF signing key for this ledger.
// * \param store            Opaque handle to the storage backend.
// *
// * \return 0 on success, otherwise a negative error code.
// */
//UDIL_EXPORT_API int32_t udil_ledger_initialize(udil_ledger_state* st, const uint8_t ledger_id[UDIL_HASHLEN], uint32_t epoch, void* udif_signing_key, void* store);
//
///**
// * \brief Issue, sign, and append a checkpoint record to the ledger.
// *
// * This function creates a checkpoint for records in the inclusive range
// * [start_seq, end_seq] and appends it as a checkpoint record to the ledger.
// *
// * A compliant implementation must:
// *  - Build the checkpoint body (udil_ledger_build_checkpoint_body()).
// *  - Compute the checkpoint commitment over the canonical body.
// *  - Sign the checkpoint commitment using the ledger’s UDIF signing key.
// *  - Append a CHECKPOINT record that contains the body and checkpoint signature.
// *  - Update the ledger state’s last checkpoint tracking values.
// *
// * The returned out_chk_commit is intended for external anchoring and for
// * audit exchange.
// *
// * \param st             Ledger state object.
// * \param start_seq      First record sequence number in the checkpoint batch (inclusive).
// * \param end_seq        Last record sequence number in the checkpoint batch (inclusive).
// * \param out_chk_commit Output 32-byte checkpoint commitment.
// *
// * \return 0 on success, otherwise a negative error code.
// */
//UDIL_EXPORT_API int32_t udil_ledger_issue_checkpoint(udil_ledger_state* st, uint64_t start_seq, uint64_t end_seq, uint8_t out_chk_commit[UDIL_HASHLEN]);
//
///**
// * \brief Parse a stored record blob into header, body, and signature components.
// *
// * This function decodes the record container format produced by udil_ledger_append()
// * and returns:
// *  - the committed header fields,
// *  - the optional opaque body bytes,
// *  - the signature bytes.
// *
// * The caller owns the returned out_body and out_sig buffers and must free them
// * using the allocator compatible with the implementation.
// *
// * This function does not verify signatures. Use udil_ledger_verify_record_blob()
// * for verification.
// *
// * \param blob         Raw stored record blob bytes.
// * \param blob_len     Length of blob in bytes.
// * \param out_hdr      Output parsed record header.
// * \param out_body     Output pointer to allocated body bytes (may be NULL if no body).
// * \param out_body_len Output body length (0 if no body).
// * \param out_sig      Output pointer to allocated signature bytes.
// * \param out_sig_len  Output signature length.
// *
// * \return 0 on success, otherwise a negative error code.
// */
//UDIL_EXPORT_API int32_t udil_ledger_parse_record(const uint8_t* blob, size_t blob_len, udil_record_hdr* out_hdr, uint8_t** out_body,
//    size_t* out_body_len, uint8_t** out_sig, size_t* out_sig_len);
//
///**
// * \brief Rotate the UDIF signing key used by the ledger and transition to a new epoch.
// *
// * This function updates the ledger’s signing key to a new UDIF key and increments
// * the epoch to explicitly mark the key transition in the evidentiary record.
// *
// * A compliant implementation should:
// *  - Update st->udif_signing_key to new_udif_signing_key.
// *  - Increment st->epoch.
// *  - Preserve continuity by issuing a checkpoint over any uncheckpointed records
// *    prior to completing the rollover (policy dependent, but recommended).
// *
// * \param st                  Ledger state object.
// * \param new_udif_signing_key Opaque handle to the new UDIF signing key.
// *
// * \return 0 on success, otherwise a negative error code.
// */
//UDIL_EXPORT_API int32_t udil_ledger_rotate_key(udil_ledger_state* st, void* new_udif_signing_key);
//
///**
// * \brief Verify a stored record blob signature and recompute its record commitment.
// *
// * This function parses the record blob, recomputes the record commitment from the
// * committed header fields, and verifies that the signature over the record commitment
// * is valid under the supplied signer certificate.
// *
// * The output record commitment can be used as an input leaf to checkpoint Merkle trees
// * and as an evidentiary identifier for the record.
// *
// * \param blob           Raw stored record blob bytes.
// * \param blob_len       Length of blob in bytes.
// * \param signer_cert    The signer’s UDIF certificate bytes used for verification.
// * \param cert_len       Length of signer_cert in bytes.
// * \param out_rec_commit Output 32-byte record commitment.
// *
// * \return 0 on success (signature valid), otherwise a negative error code.
// */
//UDIL_EXPORT_API int32_t udil_ledger_verify_record_blob(const uint8_t* blob, size_t blob_len, const uint8_t* signer_cert, size_t cert_len, uint8_t out_rec_commit[UDIL_HASHLEN]);
//
///**
// * Compute the Merkle leaf node hash from a record commitment.
// *
// * leaf = SHAKE256("UDIL/LEAF" || rec_commit, 32)
// *
// * out        : [out] 32-byte leaf hash.
// * rec_commit : [in]  32-byte record commitment.
// */
//UDIL_EXPORT_API void udil_merkle_leaf(uint8_t out[UDIL_HASHLEN], const uint8_t rec_commit[UDIL_HASHLEN]);
//
///**
// * Compute the Merkle parent node hash.
// *
// * parent = SHAKE256("UDIL/NODE" || left || right, 32)
// *
// * out   : [out] 32-byte parent hash.
// * left  : [in]  32-byte left child.
// * right : [in]  32-byte right child.
// */
//UDIL_EXPORT_API void udil_merkle_parent(uint8_t out[UDIL_HASHLEN], const uint8_t left[UDIL_HASHLEN], const uint8_t right[UDIL_HASHLEN]);
//
///**
// * Verify a Merkle inclusion proof and recompute the root.
// *
// * out_root   : [out] computed Merkle root from the proof.
// * rec_commit : [in]  record commitment being proven.
// * proof      : [in]  inclusion proof (siblings + directions).
// */
//UDIL_EXPORT_API void udil_merkle_verify(uint8_t out_root[UDIL_HASHLEN], const uint8_t rec_commit[UDIL_HASHLEN], const udil_merkle_proof* proof);
//
///**
// * \brief Compute the Merkle root over a contiguous set of record commitments.
// *
// * This function computes a deterministic Merkle root using the UDIL Merkle
// * construction rules:
// *  - Each record commitment is first transformed into a Merkle leaf.
// *  - Parent nodes are computed pairwise from left and right children.
// *  - If a level has an odd number of nodes, the final node is duplicated.
// *
// * The resulting root is suitable for inclusion in a checkpoint body and
// * for later audit verification using Merkle inclusion proofs.
// *
// * \param root        Output buffer receiving the computed Merkle root.
// * \param rec_commits Pointer to a flat array of record commitments
// *                    (count * UDIL_HASHLEN bytes).
// * \param count       Number of record commitments in the array.
// */
//UDIL_EXPORT_API void udil_merkle_root(uint8_t root[UDIL_HASHLEN], const uint8_t* rec_commits, size_t count);
//
///**
// * \brief Serialize an anchor reference into canonical byte form.
// *
// * This function serializes an \c udil_anchor_ref structure into its canonical
// * binary representation. The serialized output is suitable for inclusion as
// * the body of an ANCHOR_REFERENCE ledger record.
// *
// * The caller owns the returned buffer and must free it using the allocator
// * compatible with the implementation.
// *
// * \param a        Anchor reference structure to serialize.
// * \param out_len Output parameter receiving the serialized length in bytes.
// *
// * \return Pointer to a newly allocated buffer containing the serialized
// *         anchor reference, or NULL on failure.
// */
//UDIL_EXPORT_API uint8_t* udil_serialize_anchor_reference(const udil_anchor_ref* a, size_t* out_len);
//
///**
// * \brief Serialize a checkpoint body into canonical byte form.
// *
// * This function serializes an \c udil_checkpoint_body structure into the exact
// * canonical format used for computing checkpoint commitments and signatures.
// * The serialization includes all committed fields in fixed order and
// * big-endian encoding for multi-byte integers.
// *
// * The returned buffer is used as input to the checkpoint commitment hash
// * function.
// *
// * The caller owns the returned buffer and must free it when no longer needed.
// *
// * \param c        Checkpoint body structure to serialize.
// * \param out_len Output parameter receiving the serialized length in bytes.
// *
// * \return Pointer to a newly allocated buffer containing the serialized
// *         checkpoint body, or NULL on failure.
// */
//UDIL_EXPORT_API uint8_t* udil_serialize_checkpoint_body(const udil_checkpoint_body* c, size_t* out_len);
//
///**
// * \brief Serialize a record header into canonical byte form.
// *
// * This function serializes the committed fields of an \c udil_record_hdr into
// * a canonical binary representation. The output is used exclusively for
// * computing the record commitment hash.
// *
// * Signature bytes, variable-length bodies, and container framing are not
// * included in this serialization.
// *
// * The caller owns the returned buffer and must free it when finished.
// *
// * \param h        Record header structure to serialize.
// * \param out_len Output parameter receiving the serialized length in bytes.
// *
// * \return Pointer to a newly allocated buffer containing the serialized
// *         record header, or NULL on failure.
// */
//UDIL_EXPORT_API uint8_t* udil_serialize_record_header(const udil_record_hdr* h, size_t* out_len);
//
///**
// * \brief Sign a checkpoint commitment using a UDIF signing key.
// *
// * This function produces a cryptographic signature over a checkpoint
// * commitment. The commitment must already have been computed from a canonical
// * checkpoint body.
// *
// * The signature binds the issuing authority, the checkpoint content, and the
// * signing context, providing non-repudiable evidence that the checkpoint was
// * issued by the holder of the UDIF key.
// *
// * \param out_sig     Output buffer receiving the signature bytes.
// * \param out_siglen  Output parameter receiving the signature length in bytes.
// * \param udif_key    Opaque handle to the UDIF signing key.
// * \param chk_commit  32-byte checkpoint commitment to be signed.
// */
//UDIL_EXPORT_API void udil_sign_checkpoint(uint8_t* out_sig, size_t* out_siglen, void* udif_key, const uint8_t chk_commit[UDIL_HASHLEN]);
//
///**
// * \brief Sign a record commitment using a UDIF signing key.
// *
// * This function produces a cryptographic signature over a record commitment.
// * The record commitment must already have been computed from the canonical
// * record header serialization.
// *
// * The resulting signature provides non-repudiation for the existence and
// * ordering of the record within the ledger.
// *
// * \param out_sig     Output buffer receiving the signature bytes.
// * \param out_siglen  Output parameter receiving the signature length in bytes.
// * \param udif_key    Opaque handle to the UDIF signing key.
// * \param rec_commit  32-byte record commitment to be signed.
// */
//UDIL_EXPORT_API void udil_sign_record(uint8_t out_sig[], size_t* out_siglen, void* udif_key, const uint8_t rec_commit[UDIL_HASHLEN]);
//
///**
// * \brief Verify a checkpoint signature against a checkpoint commitment.
// *
// * This function verifies that a provided signature is a valid signature over
// * the given checkpoint commitment under the supplied UDIF certificate.
// *
// * This verification step is required for:
// *  - Audit acceptance of a checkpoint.
// *  - Detection of forged or unauthorized checkpoints.
// *  - Establishing evidentiary validity of ledger checkpoints.
// *
// * \param cert        UDIF certificate bytes of the purported signer.
// * \param cert_len    Length of the certificate in bytes.
// * \param chk_commit  32-byte checkpoint commitment that was signed.
// * \param sig         Signature bytes to verify.
// * \param siglen      Length of the signature in bytes.
// *
// * \return 0 if the signature is valid, otherwise a negative error code.
// */
//int32_t udil_verify_checkpoint_signature(const uint8_t* cert, size_t cert_len, const uint8_t chk_commit[UDIL_HASHLEN], const uint8_t* sig, size_t siglen);
//
///**
// * \brief Verify a record signature against a record commitment.
// *
// * This function verifies that a provided signature is a valid signature over
// * the given record commitment under the supplied UDIF certificate.
// *
// * Successful verification proves that the record was authorized by the
// * certificate holder and that the committed record header has not been
// * altered.
// *
// * \param cert        UDIF certificate bytes of the purported signer.
// * \param cert_len    Length of the certificate in bytes.
// * \param rec_commit  32-byte record commitment that was signed.
// * \param sig         Signature bytes to verify.
// * \param siglen      Length of the signature in bytes.
// *
// * \return 0 if the signature is valid, otherwise a negative error code.
// */
//UDIL_EXPORT_API int32_t udil_verify_record_signature(const uint8_t* cert, size_t cert_len, const uint8_t rec_commit[UDIL_HASHLEN], const uint8_t* sig, size_t siglen);
//
///*
// * Simple UDIL Ledger Smoke Test
// *
// * This function performs a minimal end to end validation of the ledger:
// *  - initialize ledger
// *  - append a record
// *  - read the record back
// *  - recompute and verify the record commitment and signature
// *
// * This is intended as a basic sanity test, not a full audit test.
// * It assumes that the storage backend and UDIF sign/verify primitives
// * are already wired and functional.
// */
//UDIL_EXPORT_API int32_t udil_ledger_basic_selftest(udil_ledger_state* st, const uint8_t ledger_id[UDIL_HASHLEN], void* udif_signing_key, void* store, const uint8_t* signer_cert, size_t cert_len);
//
//UDIL_EXPORT_API bool udil_ledger_selftest();

#endif
