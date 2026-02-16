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

/*
 * \file mcel.h
 * \brief MCEL support header
 * 
 * Merkle Chained Event Ledger (MCEL)
 *
 * MCEL implements an append-only, cryptographically verifiable event ledger
 * designed for long-lived audit, provenance, and integrity assurance.
 * The ledger records discrete events as immutable records, batches records
 * into Merkle trees, and chains those batches using signed checkpoint
 * commitments to form a tamper-evident history.
 *
 * MCEL is optimized for environments with a bounded set of writers and a
 * potentially unbounded set of verifiers. It provides strong integrity,
 * ordering, and non-repudiation guarantees without requiring distributed
 * consensus, peer-to-peer networking, or economic mechanisms.
 *
 * Core properties:
 * - Append-only event records with canonical serialization
 * - Domain-separated cryptographic commitments for all object types
 * - Merkle tree batching for scalable inclusion proofs
 * - Hash-chained checkpoints with asymmetric signatures
 * - Portable checkpoint bundles for independent verification
 * - Support for audit paths, integrity verification, and key rotation
 *
 * MCEL is intended to serve as an integrity spine for higher-level systems
 * such as digital identity frameworks, compliance and evidence ledgers,
 * authorization workflows, and regulated institutional records.
 * Payload semantics are intentionally opaque to the ledger, allowing
 * application-specific object models to evolve independently.
 *
 * The implementation assumes a trusted storage backend providing append
 * semantics and optional overwrite support for the current ledger head.
 * All security guarantees derive from cryptographic verification rather
 * than trust in storage correctness.
 */

#ifndef MCEL_H
#define MCEL_H

#include "mcelcommon.h"

#if (!defined(MCEL_CONFIG_DILITHIUM) && !defined(MCEL_CONFIG_SPHINCSPLUS))
/*!
 * \def MCEL_CONFIG_DILITHIUM
 * \brief The Dilithium MCEL parameter set.
 */
#	define MCEL_CONFIG_DILITHIUM
#endif

#if defined(MCEL_CONFIG_DILITHIUM)
#	include "dilithium.h"
#elif defined(MCEL_CONFIG_SPHINCSPLUS)
#	include "sphincsplus.h"
#else
#	error Invalid parameter set!
#endif

/*!
 * \def MCEL_USE_RCS_ENCRYPTION
 * \brief If the RCS encryption option is chosen SKDP uses the more modern RCS stream cipher with KMAC/QMAC authentication.
 * The default symmetric cipher/authenticator is AES-256/GCM (GMAC Counter Mode) NIST standardized per SP800-38a.
 */
#define MCEL_USE_RCS_ENCRYPTION

 /** \cond DOXYGEN_IGNORE */
#if defined(MCEL_USE_RCS_ENCRYPTION)
#	include "rcs.h"
#	define mcel_cipher_state qsc_rcs_state
#	define mcel_cipher_dispose qsc_rcs_dispose
#	define mcel_cipher_initialize qsc_rcs_initialize
#	define mcel_cipher_keyparams qsc_rcs_keyparams
#	define mcel_cipher_set_associated qsc_rcs_set_associated
#	define mcel_cipher_transform qsc_rcs_transform
#else
#	include "aes.h"
#	define mcel_cipher_state qsc_aes_gcm256_state
#	define mcel_cipher_dispose qsc_aes_gcm256_dispose
#	define mcel_cipher_initialize qsc_aes_gcm256_initialize
#	define mcel_cipher_keyparams qsc_aes_keyparams
#	define mcel_cipher_set_associated qsc_aes_gcm256_set_associated
#	define mcel_cipher_transform qsc_aes_gcm256_transform
#endif
 /** \endcond DOXYGEN_IGNORE */

/**
 * \file mcel.h
 *
 * \brief Merkle-Chained Evidence Ledger (MCEL)
 *
 * This header defines the public API for the MCEL evidence ledger subsystem.
 * The ledger implements a local, append only, cryptographically verifiable
 * logging structure intended for audit, non-repudiation, and regulatory
 * evidence purposes.
 *
 * The MCEL ledger is designed as a foundational substrate for higher-level
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

#if defined(MCEL_CONFIG_DILITHIUM)
	/*!
	 * \def MCEL_ASYMMETRIC_SIGNING_KEY_SIZE
	 * \brief The byte size of the secret private-key array.
	 */
#	define MCEL_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

	/*!
	 * \def MCEL_ASYMMETRIC_VERIFY_KEY_SIZE
	 * \brief The byte size of the public-key array.
	 */
#	define MCEL_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

	/*!
	 * \def MCEL_ASYMMETRIC_SIGNATURE_SIZE
	 * \brief The byte size of the signature array.
	 */
#	define MCEL_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

#	if defined(QSC_DILITHIUM_S1P44)
	 /*!
	  * \def MCEL_PARAMETER_SET
	  * \brief The MCEL parameter set.
	  */
#		define MCEL_PARAMETER_SET 1U
#	elif defined(QSC_DILITHIUM_S3P65)
	 /*!
	  * \def MCEL_PARAMETER_SET
	  * \brief The MCEL parameter set.
	  */
#		define MCEL_PARAMETER_SET 2U
#	elif defined(QSC_DILITHIUM_S5P87)
	 /*!
	  * \def MCEL_PARAMETER_SET
	  * \brief The MCEL parameter set.
	  */
#		define MCEL_PARAMETER_SET 3U
#	else
#		error "The parameter set is not supported!"
#	endif
	 /*!
	  * \def mcel_signature_generate_keypair
	  * \brief Generate an asymmetric signature key-pair
	  */
#	define mcel_signature_generate_keypair qsc_dilithium_generate_keypair
	  /*!
	   * \def mcel_signature_sign
	   * \brief Sign a message with the asymmetric signature scheme
	   */
#	define mcel_signature_sign qsc_dilithium_sign
	   /*!
		* \def mcel_signature_verify
		* \brief Verify a message with the asymmetric signature scheme
		*/
#	define mcel_signature_verify qsc_dilithium_verify
#else
	/*!
	 * \def MCEL_ASYMMETRIC_SIGNING_KEY_SIZE
	 * \brief The byte size of the secret private-key array.
	 */
#	define MCEL_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_SPHINCSPLUS_PRIVATEKEY_SIZE)

	/*!
	 * \def MCEL_ASYMMETRIC_VERIFY_KEY_SIZE
	 * \brief The byte size of the public-key array.
	 */
#	define MCEL_ASYMMETRIC_VERIFY_KEY_SIZE (QSC_SPHINCSPLUS_PUBLICKEY_SIZE)

	/*!
	 * \def MCEL_ASYMMETRIC_SIGNATURE_SIZE
	 * \brief The byte size of the signature array.
	 */
#	define MCEL_ASYMMETRIC_SIGNATURE_SIZE (QSC_SPHINCSPLUS_SIGNATURE_SIZE)

	/*!
	 * \def MCEL_PARAMETER_SET
	 * \brief The MCEL parameter set.
	 */
#	if defined(QSC_SPHINCSPLUS_S1S128SHAKERS)
#		define MCEL_PARAMETER_SET 4U
#	elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS)
#		define MCEL_PARAMETER_SET 5U
#	elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
#		define MCEL_PARAMETER_SET 6U
#	elif defined(QSC_SPHINCSPLUS_S6S512SHAKERS)
#		define MCEL_PARAMETER_SET 7U
#	else
#		error "The parameter set is not supported!"
#	endif

	 /*!
	  * \def udif_signature_generate_keypair
	  * \brief Generate an asymmetric signature key-pair
	  */
#	define udif_signature_generate_keypair qsc_sphincsplus_generate_keypair
	  /*!
	   * \def udif_signature_sign
	   * \brief Sign a message with the asymmetric signature scheme
	   */
#	define udif_signature_sign qsc_sphincsplus_sign
	   /*!
		* \def udif_signature_verify
		* \brief Verify a message with the asymmetric signature scheme
		*/
#	define udif_signature_verify qsc_sphincsplus_verify
#endif

/*!
 * \def MCEL_BLOCK_HASH_SIZE
 * \brief The MCEL 256-bit digest size in bytes.
 */
#define MCEL_BLOCK_HASH_SIZE 32U

/*!
 * \def MCEL_BLOCK_HEADER_ENCODED_SIZE
 * \brief The canonical encoded block header size in bytes.
 */
#define MCEL_BLOCK_HEADER_ENCODED_SIZE 62U

/*!
* \def MCEL_BLOCK_ENCODED_FIXED_SIZE
* \brief The fixed-size portion of an encoded MCEL block in bytes.
*/
#define MCEL_BLOCK_ENCODED_FIXED_SIZE ((size_t)MCEL_BLOCK_HEADER_ENCODED_SIZE + ((size_t)MCEL_BLOCK_HASH_SIZE * 2U))

/*!
 * \def MCEL_BLOCK_KEYID_SIZE
 * \brief The MCEL block key identifier size in bytes.
 */
#define MCEL_BLOCK_KEYID_SIZE 32U

/*!
 * \def MCEL_BLOCK_VERSION
 * \brief The MCEL version number.
 */
#define MCEL_BLOCK_VERSION 1U

/*!
 * \def MCEL_CHECKPOINT_HEADER_ENCODED_SIZE
 * \brief The canonical encoded checkpoint header size in bytes.
 */
#define MCEL_CHECKPOINT_HEADER_ENCODED_SIZE 62U

/*!
* \def MCEL_CHECKPOINT_BUNDLE_FIXED_SIZE
* \brief The fixed-size portion of an encoded MCEL checkpoint bundle in bytes.
*/
#define MCEL_CHECKPOINT_BUNDLE_FIXED_SIZE (MCEL_CHECKPOINT_HEADER_ENCODED_SIZE + (MCEL_BLOCK_HASH_SIZE * 2U))

/*!
* \def MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE
* \brief The encoded-size portion of an encoded MCEL checkpoint bundle in bytes.
*/
#define MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE (MCEL_ASYMMETRIC_SIGNATURE_SIZE + MCEL_BLOCK_HASH_SIZE + MCEL_CHECKPOINT_BUNDLE_FIXED_SIZE)

/*!
 * \def MCEL_CHECKPOINT_KEYID_SIZE
 * \brief The checkpoint key identifier size in bytes.
 */
#define MCEL_CHECKPOINT_KEYID_SIZE 32U

/*!
 * \def MCEL_CHECKPOINT_SIGNED_COMMIT_SIZE
 * \brief The size in bytes of a Dilithium signed checkpoint commitment message.
 */
#define MCEL_CHECKPOINT_SIGNED_COMMIT_SIZE (MCEL_ASYMMETRIC_SIGNATURE_SIZE + MCEL_BLOCK_HASH_SIZE)

/*!
 * \def MCEL_CHECKPOINT_VERSION
 * \brief The MCEL checkpoint format version.
 */
#define MCEL_CHECKPOINT_VERSION 1U

/*!
* \def MCEL_KEYROTATE_PAYLOAD_VERSION
* \brief The key rotation payload format version.
*/
#define MCEL_KEYROTATE_PAYLOAD_VERSION 0x01U

/*!
* \def MCEL_KEYROTATE_PAYLOAD_FIXED_SIZE
* \brief The fixed-size portion of the key rotation payload in bytes.
*/
#define MCEL_KEYROTATE_PAYLOAD_FIXED_SIZE (1U + 1U + (uint32_t)MCEL_CHECKPOINT_KEYID_SIZE + 2U)

/*!
* \def MCEL_KEYROTATE_PAYLOAD_KEY_SIZE
* \brief The rotation payload and signature verification key size.
*/
#define MCEL_KEYROTATE_PAYLOAD_KEY_SIZE (MCEL_KEYROTATE_PAYLOAD_FIXED_SIZE + MCEL_ASYMMETRIC_VERIFY_KEY_SIZE)

/*!
* \def MCEL_LEDGER_NAMESPACE_ID_MAX
* \brief The maximum namespace identifier size in bytes.
*/
#define MCEL_LEDGER_NAMESPACE_ID_MAX 64U

/*!
 * \def MCEL_PAYLOAD_MAX_SIZE
 * \brief The maximum supported payload length in bytes (0 for unlimited).
 */
#define MCEL_PAYLOAD_MAX_SIZE 0xFFFFFFFFUL

/*!
* \def MCEL_RCS256_KEY_SIZE
* \brief The size in bytes of the RCS-256 cipher key.
*/
#define MCEL_RCS256_KEY_SIZE 32U

/*!
* \def MCEL_RCS256_MAC_SIZE
* \brief The size in bytes of the RCS-256 authentication tag.
*/
#define MCEL_RCS256_MAC_SIZE 32U

/*!
* \def MCEL_RCS_NONCE_SIZE
* \brief The size in bytes of the RCS nonce.
*/
#define MCEL_RCS_NONCE_SIZE 32U

/*!
* \def MCEL_RCS_INFO_SIZE
* \brief The maximum size in bytes of the RCS info string.
*/
#define MCEL_RCS_INFO_SIZE 48U

/*!
* \def MCEL_RECORD_FLAG_ENCRYPTED
* \brief The record payload is encrypted (ciphertext) rather than plaintext.
*/
#define MCEL_RECORD_FLAG_ENCRYPTED 0x01U

/*!
 * \def MCEL_RECORD_VERSION
 * \brief The MCEL record format version.
 */
#define MCEL_RECORD_VERSION 1U

/*!
 * \def MCEL_RECORD_KEYID_SIZE
 * \brief The record signer or policy key identifier size in bytes.
 */
#define MCEL_RECORD_KEYID_SIZE 32U

/*!
 * \def MCEL_RECORD_HEADER_ENCODED_SIZE
 * \brief The canonical encoded record header size in bytes.
 */
#define MCEL_RECORD_HEADER_ENCODED_SIZE 58U

/*!
* \def MCEL_RECORD_TYPE_KEYROTATE
* \brief The record type code for a key rotation control record.
*/
#define MCEL_RECORD_TYPE_KEYROTATE 0x3U

/*!
* \def MCEL_SIGNED_HASH_SIZE
* \brief The byte size of the signed message.
*/
#define MCEL_SIGNED_HASH_SIZE (MCEL_ASYMMETRIC_SIGNATURE_SIZE + MCEL_BLOCK_HASH_SIZE)

/*!
* \def MCEL_STORE_LOC_BLOCKS
* \brief The logical storage location used to write serialized sealed blocks.
*/
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	define MCEL_STORE_LOC_BLOCKS "mcel\\blocks"
#else
#	define MCEL_STORE_LOC_BLOCKS "mcel/blocks"
#endif

/*!
* \def MCEL_STORE_LOC_CHECKPOINTS
* \brief The logical storage location used to append serialized checkpoint bundles.
*/
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	define MCEL_STORE_LOC_CHECKPOINTS "mcel\\checkpoints"
#else
#	define MCEL_STORE_LOC_CHECKPOINTS "mcel/checkpoints"
#endif

/*!
* \def MCEL_STORE_LOC_HEAD
* \brief The logical storage location used to store the current checkpoint head bundle.
*/
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	define MCEL_STORE_LOC_HEAD "mcel\\head"
#else
#	define MCEL_STORE_LOC_HEAD "mcel/head"
#endif

/*!
* \def MCEL_STORE_LOC_RECORDS
* \brief The logical storage location used to append serialized records.
*/
#if defined(QSC_SYSTEM_OS_WINDOWS)
#	define MCEL_STORE_LOC_RECORDS "mcel\\records"
#else
#	define MCEL_STORE_LOC_RECORDS "mcel/records"
#endif

/*!
 * \enum mcel_record_types
 * \brief The MCEL record type identifiers.
 */
MCEL_EXPORT_API typedef enum mcel_record_types
{
    mcel_record_type_none = 0U,             /*!< Record type is none */
    mcel_record_type_checkpoint = 1U,       /*!< A checkpoint reference record (extension hook) */
    mcel_record_type_event = 2U,            /*!< A general event record */
    mcel_record_type_key_rotate = 3U,       /*!< A key rotation event record */
    mcel_record_type_policy = 4U           /*!< A policy or configuration record */
} mcel_record_types;

/*!
* \enum mcel_policy_ops
* \brief The MCEL policy operation identifiers.
*/
MCEL_EXPORT_API typedef enum mcel_policy_ops
{
	mcel_policyop_append_record = 1U,		/*!< Authorize appending a record */
	mcel_policyop_seal_checkpoint = 2U		/*!< Authorize sealing a checkpoint */
} mcel_policy_ops;

/*!
* \enum mcel_policy_errors
* \brief The MCEL policy error values.
*/
MCEL_EXPORT_API typedef enum mcel_policy_errors
{
	mcel_policyerr_none = 0U,				/*!< No policy error is set */
	mcel_policyerr_invalid_parameter = 1U,	/*!< Policy error invalid parameter */
	mcel_policyerr_record_type_denied = 2U,	/*!< Policy error record type denied */
	mcel_policyerr_payload_too_large = 3U,	/*!< Policy error payload too large */
	mcel_policyerr_plaintext_denied = 4U,	/*!< Policy error plaintext denied */
	mcel_policyerr_sequence_invalid = 5U,	/*!< Policy error sequence invalid */
	mcel_policyerr_timestamp_invalid = 6U,	/*!< Policy error timestampinvalid */
	mcel_policyerr_keyid_mismatch = 7U		/*!< Policy error keyid mismatch */
} mcel_policy_errors;

/*!
* \struct mcel_store_callbacks
* \brief The MCEL storage callback table.
*
* \details
* The hosting application owns persistence. MCEL calls these functions to read and write
* opaque byte strings (blocks, checkpoint bundles, records, indexes).
*/
MCEL_EXPORT_API typedef struct mcel_store_callbacks
{
	void* context; /*!< The host-defined storage context pointer */

	/*!
	* \brief Write a complete object at a logical location.
	*
	* \param context The storage context.
	* \param loc [const] A pointer to an application-defined location identifier.
	* \param loclen The length of the location identifier in bytes.
	* \param data [const] A pointer to the data buffer.
	* \param datalen The data length in bytes.
	*
	* \return Returns true on success.
	*/
	bool (*write)(void* context, const uint8_t* loc, size_t loclen, const uint8_t* data, size_t datalen);

	/*!
	* \brief Read a complete object from a logical location.
	*
	* \param context The storage context.
	* \param loc [const] A pointer to an application-defined location identifier.
	* \param loclen The length of the location identifier in bytes.
	* \param data A pointer to the output buffer.
	* \param datalen The output buffer length in bytes.
	* \param outread A pointer to the returned number of bytes read.
	*
	* \return Returns true on success.
	*/
	bool (*read)(void* context, const uint8_t* loc, size_t loclen, uint8_t* data, size_t datalen, size_t* outread);

	/*!
	* \brief Append bytes to an append-only object.
	*
	* \param context The storage context.
	* \param loc [const] A pointer to an application-defined location identifier.
	* \param loclen The length of the location identifier in bytes.
	* \param data [const] A pointer to the data buffer.
	* \param datalen The data length in bytes.
	* \param outpos A pointer to the returned append position offset, can be NULL.
	*
	* \return Returns true on success.
	*/
	bool (*append)(void* context, const uint8_t* loc, size_t loclen, const uint8_t* data, size_t datalen, uint64_t* outpos);

	/*!
	* \brief Get the size of an object at a logical location.
	*
	* \param context The storage context.
	* \param loc [const] A pointer to an application-defined location identifier.
	* \param loclen The length of the location identifier in bytes.
	* \param outlen A pointer to the returned size in bytes.
	*
	* \return Returns true on success.
	*/
	bool (*size)(void* context, const uint8_t* loc, size_t loclen, uint64_t* outlen);

	/*!
	* \brief Flush any buffered data for a logical location.
	*
	* \param context The storage context.
	* \param loc [const] A pointer to an application-defined location identifier.
	* \param loclen The length of the location identifier in bytes.
	*
	* \return Returns true on success.
	*/
	bool (*flush)(void* context, const uint8_t* loc, size_t loclen);
} mcel_store_callbacks;

/*!
* \struct mcel_block_header
* \brief The MCEL block header structure.
*
* \details
* This structure is canonically encoded using \c mcel_encode_block_header.
* The block commitment binds this header to the Merkle root of record commitments.
*/
MCEL_EXPORT_API typedef struct mcel_block_header
{
    uint8_t keyid[MCEL_BLOCK_KEYID_SIZE];	/*!< The signer or policy identifier */
    uint64_t block_sequence;				/*!< The block sequence number within the ledger */
    uint64_t first_record_seq;				/*!< The sequence number of the first record in this block */
    uint64_t timestamp;						/*!< Advisory UTC timestamp or monotonic time value */
    uint32_t record_count;					/*!< The number of records committed by the Merkle root */
    uint8_t flags;							/*!< Block flags (reserved for future use) */
    uint8_t version;						/*!< The block format version (MCEL_BLOCK_VERSION) */
} mcel_block_header;

/*!
* \struct mcel_checkpoint_audit_item
* \brief The MCEL audit path item container.
*/
MCEL_EXPORT_API typedef struct mcel_checkpoint_audit_item
{
    const uint8_t* bundle;                  /*!< The serialized checkpoint bundle */
    size_t bundlelen;						/*!< The bundle length in bytes */
} mcel_checkpoint_audit_item;

/*!
* \struct mcel_checkpoint_header
* \brief The MCEL checkpoint header structure.
*
* \details
* This structure is canonically encoded using \c mcel_encode_checkpoint_header.
* The checkpoint commitment additionally binds the block root and previous checkpoint commitment.
*/
MCEL_EXPORT_API typedef struct mcel_checkpoint_header
{
    uint8_t keyid[MCEL_CHECKPOINT_KEYID_SIZE]; /*!< The signer or policy identifier */
    uint64_t chk_sequence;                  /*!< The checkpoint sequence number within the ledger */
    uint64_t first_record_seq;              /*!< The sequence number of the first record in this block */
    uint64_t timestamp;                     /*!< Advisory UTC timestamp or monotonic time value */
    uint32_t record_count;                  /*!< The number of records committed by the block root */
    uint8_t flags;                          /*!< Checkpoint flags (reserved for future use) */
    uint8_t version;                        /*!< The checkpoint format version (MCEL_CHECKPOINT_VERSION) */
} mcel_checkpoint_header;

/*!
* \struct mcel_ledger_state
* \brief The MCEL ledger instance state.
*/
MCEL_EXPORT_API typedef struct mcel_ledger_state
{
	mcel_store_callbacks store;				/*!< The host storage callbacks */
	uint8_t nsid[MCEL_LEDGER_NAMESPACE_ID_MAX]; /*!< The namespace identifier */
	size_t nsidlen;                         /*!< The namespace identifier length */
	const uint8_t* publickey;               /*!< The Dilithium public key used for checkpoint verification */
	uint8_t head_commit[MCEL_BLOCK_HASH_SIZE]; /*!< The current head checkpoint commitment */
	mcel_checkpoint_header head_header;     /*!< The current head checkpoint header */
	uint8_t have_head;                      /*!< Non-zero if a head checkpoint is loaded */
} mcel_ledger_state;

/*!
* \struct mcel_policy
* \brief The MCEL namespace policy container.
*/
MCEL_EXPORT_API typedef struct mcel_policy
{
	size_t max_payload_size;				/*!< Maximum allowed record payload size (0 for unlimited) */
	uint32_t allowed_record_mask;			/*!< Bitmask of allowed record types (bit[type] == 1 allows) */
	uint8_t require_encryption;				/*!< Non-zero if plaintext payloads are disallowed */
	uint8_t enforce_monotonic_time;			/*!< Non-zero if timestamps must be non-decreasing */
	uint8_t enforce_monotonic_seq;			/*!< Non-zero if sequences must be strictly increasing */
	uint8_t enforce_keyid_link;				/*!< Non-zero if checkpoint keyid must match the previous checkpoint keyid */
} mcel_policy;

/*!
* \struct mcel_policy_context
* \brief The MCEL policy context (caller-maintained).
*
* \details
* This structure is updated by the hosting application (or the higher-level ledger API).
* It provides the minimum state required to apply monotonic and linkage rules.
*/
MCEL_EXPORT_API typedef struct mcel_policy_context
{
	uint8_t have_checkpoint;				/*!< Non-zero if a prior checkpoint header is present */
	mcel_checkpoint_header checkpoint;		/*!< The prior (head) checkpoint header */
	uint64_t last_record_sequence;			/*!< The last accepted record sequence (0 if unknown) */
	uint64_t last_record_timestamp;			/*!< The last accepted record timestamp (0 if unknown) */
} mcel_policy_context;

/*!
* \struct mcel_record_header
* \brief The MCEL record header structure.
*
* \details
* This structure is canonically encoded using \c mcel_encode_record_header.
* The \c keyid field identifies the signing authority, policy, or key context.
*/
MCEL_EXPORT_API typedef struct mcel_record_header
{
    uint8_t keyid[MCEL_RECORD_KEYID_SIZE];   /*!< The key or policy identifier */
    uint64_t sequence;                       /*!< The record sequence number within the ledger */
    uint64_t timestamp;                      /*!< Advisory UTC timestamp or monotonic time value */
    uint32_t payload_len;                    /*!< The payload length in bytes */
    uint32_t type;                           /*!< A \c mcel_record_type value or application-defined type */
    uint8_t flags;                           /*!< Record flags (encryption, reserved bits, etc.) */
    uint8_t version;                         /*!< The record format version (MCEL_RECORD_VERSION) */
} mcel_record_header;

/*!
 * \brief Compute a MCEL block commitment from a block header and Merkle root.
 *
 * \param output A pointer to the output commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param header [const] A pointer to the block header structure.
 * \param blkroot [const] A pointer to the block Merkle root array of size \c MCEL_BLOCK_HASH_SIZE.
 *
 * \return Returns true if the commitment was generated successfully.
 */
MCEL_EXPORT_API bool mcel_block_commit(uint8_t* output, const mcel_block_header* header, const uint8_t* blkroot);

/*!
 * \brief Serialize a sealed MCEL block into a canonical byte string.
 *
 * \param output A pointer to the encoded block buffer.
 * \param outlen The length of the output buffer.
 * \param header [const] A pointer to the block header structure.
 * \param blkroot [const] A pointer to the block Merkle root array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param blkcommit [const] A pointer to the block commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param reccommits [const] A pointer to an array of record commitments, each of size \c MCEL_BLOCK_HASH_SIZE.
 * \param reccount The number of record commitments in the array.
 *
 * \return Returns true if the block was serialized successfully.
 */
MCEL_EXPORT_API bool mcel_block_encode(uint8_t* output, size_t outlen, const mcel_block_header* header, const uint8_t* blkroot, 
	const uint8_t* blkcommit, const uint8_t* reccommits, size_t reccount);

/*!
 * \brief Get the required buffer size for an encoded MCEL block.
 *
 * \param reccount The number of record commitments in the block.
 *
 * \return The required buffer size in bytes for \c mcel_encode_block or 0 on error.
 */
MCEL_EXPORT_API size_t mcel_block_encoded_size(size_t reccount);

/*!
 * \brief Encode a MCEL block header using canonical fixed-size encoding.
 *
 * \param output A pointer to the output byte array of size \c MCEL_BLOCK_HEADER_ENCODED_SIZE.
 * \param header [const] A pointer to the block header structure.
 *
 * \return Returns true if the header was encoded successfully.
 */
MCEL_EXPORT_API bool mcel_block_encode_header(uint8_t* output, const mcel_block_header* header);

/*!
 * \brief Seal a MCEL block by computing the Merkle root and block commitment.
 *
 * \param blkroot A pointer to the output Merkle root array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param blkcommit A pointer to the output block commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param header [const] A pointer to the block header structure.
 * \param reccommits [const] A pointer to an array of record commitments, each of size \c MCEL_BLOCK_HASH_SIZE.
 * \param reccount The number of record commitments in the array.
 *
 * \return Returns true if the block was sealed successfully.
 */
MCEL_EXPORT_API bool mcel_block_seal(uint8_t* blkroot, uint8_t* blkcommit, const mcel_block_header* header, const uint8_t* reccommits, size_t reccount);

/*!
 * \brief Verify an ordered audit path of MCEL checkpoint bundles.
 *
 * \param outheadcommit A pointer to the output last (head) checkpoint commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param items [const] A pointer to the ordered audit item array (oldest to newest).
 * \param itemcount The number of audit items in the array.
 * \param publickey [const] A pointer to the Dilithium public key array.
 *
 * \return Returns true if the audit path was verified successfully.
 */
MCEL_EXPORT_API bool mcel_checkpoint_audit_path_verify(uint8_t* outheadcommit, const mcel_checkpoint_audit_item* items, 
	size_t itemcount, const uint8_t* publickey);

/*!
 * \brief Serialize a MCEL checkpoint bundle into a canonical byte string.
 *
 * \param output A pointer to the output buffer.
 * \param outlen The length of the output buffer in bytes.
 * \param header [const] A pointer to the checkpoint header structure.
 * \param blkroot [const] A pointer to the sealed block Merkle root array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param prevcommit [const] A pointer to the previous checkpoint commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param sigcommit [const] A pointer to the signed commitment message.
 * \param siglen The length of the signed commitment message in bytes.
 *
 * \return Returns true if the bundle was serialized successfully.
 */
MCEL_EXPORT_API bool mcel_checkpoint_bundle_encode(uint8_t* output, size_t outlen, const mcel_checkpoint_header* header, const uint8_t* blkroot, 
    const uint8_t* prevcommit, const uint8_t* sigcommit, size_t siglen);

/*!
 * \brief Get the required buffer size for an encoded MCEL checkpoint bundle.
 *
 * \param siglen The length of the signed commitment message in bytes.
 *
 * \return The required buffer size in bytes for \c mcel_encode_checkpoint_bundle or 0 on error.
 */
MCEL_EXPORT_API size_t mcel_checkpoint_bundle_encoded_size(size_t siglen);

/*!
 * \brief Verify a serialized MCEL checkpoint bundle.
 *
 * \param chkcommit A pointer to the output checkpoint commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param header A pointer to the output checkpoint header structure.
 * \param blkroot A pointer to the output block Merkle root array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param prevcommit A pointer to the output previous checkpoint commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param bundle [const] A pointer to the serialized checkpoint bundle.
 * \param bundlelen The length of the serialized bundle in bytes.
 * \param publickey [const] A pointer to the Dilithium public key array.
 *
 * \return Returns true if the bundle was verified successfully.
 */
MCEL_EXPORT_API bool mcel_checkpoint_bundle_verify(uint8_t* chkcommit, mcel_checkpoint_header* header, uint8_t* blkroot, uint8_t* prevcommit, 
    const uint8_t* bundle, size_t bundlelen, const uint8_t* publickey);

/*!
 * \brief Verify the chain linkage between two verified checkpoints.
 *
 * \param prevcommit [const] The previous checkpoint commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param curprevcommit [const] The current checkpoints embedded previous-commit array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param prevhdr [const] A pointer to the previous checkpoint header structure.
 * \param curhdr [const] A pointer to the current checkpoint header structure.
 *
 * \return Returns true if the chain link is valid.
 */
MCEL_EXPORT_API bool mcel_checkpoint_chain_link_verify(const uint8_t* prevcommit, const uint8_t* curprevcommit, 
	const mcel_checkpoint_header* prevhdr, const mcel_checkpoint_header* curhdr);

/*!
 * \brief Compute a MCEL checkpoint commitment from a checkpoint header, block root, and previous checkpoint commitment.
 *
 * \param output A pointer to the output commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param header [const] A pointer to the checkpoint header structure.
 * \param blkroot [const] A pointer to the block Merkle root array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param pldcommit [const] A pointer to the previous checkpoint commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 *
 * \return Returns true if the commitment was generated successfully.
 */
MCEL_EXPORT_API bool mcel_checkpoint_commit(uint8_t* output, const mcel_checkpoint_header* header, const uint8_t* blkroot, const uint8_t* pldcommit);

/*!
 * \brief Verify a MCEL Merkle consistency proof between two tree roots.
 *
 * \param firstroot [const] The older tree root hash.
 * \param secondroot [const] The newer tree root hash.
 * \param first The older tree size (leaf count), must be > 0 and < second.
 * \param second The newer tree size (leaf count), must be > first.
 * \param proof [const] The consistency proof buffer (concatenated hashes).
 * \param prooflen The length of the proof buffer in bytes.
 *
 * \return Returns true if the consistency proof is valid.
 */
MCEL_EXPORT_API bool mcel_checkpoint_consistency_verify(const uint8_t* firstroot, const uint8_t* secondroot, size_t first, 
	size_t second, const uint8_t* proof, size_t prooflen);

/*!
 * \brief Decode a MCEL checkpoint header from its canonical encoding.
 *
 * \param header A pointer to the receiving checkpoint header structure.
 * \param input [const] A pointer to the encoded header bytes.
 *
 * \return Returns true on success.
 */
MCEL_EXPORT_API bool mcel_checkpoint_decode_header(mcel_checkpoint_header* header, const uint8_t* input);

/*!
 * \brief Encode a MCEL checkpoint header using canonical fixed-size encoding.
 *
 * \param output A pointer to the output byte array of size \c MCEL_CHECKPOINT_HEADER_ENCODED_SIZE.
 * \param header [const] A pointer to the checkpoint header structure.
 *
 * \return Returns true if the header was encoded successfully.
 */
MCEL_EXPORT_API bool mcel_checkpoint_encode_header(uint8_t* output, const mcel_checkpoint_header* header);

/*!
 * \brief Generate a MCEL Merkle consistency proof between two tree sizes.
 *
 * \param proof A pointer to the output proof buffer.
 * \param prooflen The length of the output proof buffer in bytes.
 * \param leaves [const] A pointer to the leaf hash array (new_count * MCEL_BLOCK_HASH_SIZE).
 * \param oldcount The leaf count of the older tree (must be <= new_count).
 * \param newcount The leaf count of the newer tree.
 *
 * \return Returns true if the proof was generated successfully.
 */
MCEL_EXPORT_API bool mcel_checkpoint_prove_consistency(uint8_t* proof, size_t prooflen, const uint8_t* leaves, size_t oldcount, size_t newcount);

/*!
 * \brief Seal a MCEL checkpoint from a sealed block by generating the checkpoint commitment and signing it.
 *
 * \param chkcommit A pointer to the output checkpoint commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param sigcommit A pointer to the signed commitment output buffer of size \c MCEL_CHECKPOINT_SIGNED_COMMIT_SIZE.
 * \param siglen A pointer to the returned signed message length in bytes.
 * \param header [const] A pointer to the checkpoint header structure.
 * \param blkroot [const] A pointer to the sealed block Merkle root array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param prevcommit [const] A pointer to the previous checkpoint commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param privatekey [const] A pointer to the Dilithium private key array.
 * \param rng_generate A pointer to a secure RNG function.
 *
 * \return Returns true if the checkpoint was sealed successfully.
 */
MCEL_EXPORT_API bool mcel_checkpoint_seal(uint8_t* chkcommit, uint8_t* sigcommit, size_t* siglen, const mcel_checkpoint_header* header,
    const uint8_t* blkroot, const uint8_t* prevcommit, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/*!
 * \brief Sign a MCEL checkpoint commitment using Dilithium.
 *
 * \param sigcommit A pointer to the signed commitment output buffer of size \c MCEL_CHECKPOINT_SIGNED_COMMIT_SIZE.
 * \param siglen A pointer to the returned signed message length in bytes.
 * \param chkcommit [const] A pointer to the checkpoint commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param privatekey [const] A pointer to the Dilithium private key array.
 * \param rng_generate A pointer to a secure RNG function.
 *
 * \return Returns true if the commitment was signed successfully.
 */
MCEL_EXPORT_API bool mcel_checkpoint_sign(uint8_t* sigcommit, size_t* siglen, const uint8_t* chkcommit, 
	const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/*!
 * \brief Verify a MCEL signed checkpoint commitment using Dilithium.
 *
 * \param chkcommit A pointer to the output checkpoint commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param commitlen A pointer to the returned commitment length in bytes.
 * \param sigcommit [const] A pointer to the signed commitment message.
 * \param siglen The signed message length in bytes.
 * \param publickey [const] A pointer to the Dilithium public key array.
 *
 * \return Returns true if the signature was verified successfully.
 */
MCEL_EXPORT_API bool mcel_checkpoint_verify(uint8_t* chkcommit, size_t* commitlen, const uint8_t* sigcommit,
	size_t siglen, const uint8_t* publickey);

/*!
 * \brief Generate a signature keypair
 *
 * \param sigkey Signing key
 * \param verkey Verification key
 */
MCEL_EXPORT_API void mcel_generate_keypair(uint8_t* sigkey, uint8_t* verkey);

/*!
 * \brief Get the required buffer size for a key rotation record payload.
 *
 * \param pubkeylen The new public key length in bytes.
 *
 * \return The required payload size in bytes.
 */
MCEL_EXPORT_API size_t mcel_keyrotate_payload_size(size_t pubkeylen);

/*!
 * \brief Create a key rotation record header and payload.
 *
 * \param header A pointer to the receiving record header structure.
 * \param payload A pointer to the output payload buffer.
 * \param payload_len The length of the output payload buffer in bytes.
 * \param sequence The record sequence number.
 * \param flags The record flags.
 * \param newkeyid [const] The new signer or policy identifier.
 * \param newpubkey [const] The new public key bytes.
 * \param pubkeylen The new public key length in bytes.
 *
 * \return Returns the payload length in bytes.
 */
MCEL_EXPORT_API size_t mcel_keyrotate_record_create(mcel_record_header* header, uint8_t* payload, size_t payload_len, 
	uint64_t sequence, uint8_t flags, const uint8_t* newkeyid, const uint8_t* newpubkey, size_t pubkeylen);

/*!
 * \brief Append a record to the ledger record log and return its commitment.
 *
 * \param state A pointer to the ledger state structure.
 * \param reccommit A pointer to the output record commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param outpos A pointer to the returned append position offset, can be NULL.
 * \param header [const] A pointer to the record header structure.
 * \param payload [const] A pointer to the record payload bytes.
 * \param paylen The payload length in bytes.
 *
 * \return Returns true if the record was committed and appended successfully.
 */
MCEL_EXPORT_API bool mcel_ledger_append_record(mcel_ledger_state* state, uint8_t* reccommit, uint64_t* outpos, 
	const mcel_record_header* header, const uint8_t* payload, size_t paylen);

/*!
 * \brief Get the current checkpoint head from the ledger state.
 *
 * \param state A pointer to the ledger state structure.
 * \param head_commit A pointer to the output head checkpoint commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param head_header A pointer to the output head checkpoint header structure.
 *
 * \return Returns true if the head is available, false if no head is loaded.
 */
MCEL_EXPORT_API bool mcel_ledger_get_checkpoint_head(mcel_ledger_state* state, uint8_t* head_commit, mcel_checkpoint_header* head_header);

/*!
 * \brief Initialize (open) a MCEL ledger namespace and load the checkpoint head if present.
 *
 * \param state A pointer to the ledger state structure.
 * \param store [const] A pointer to an initialized storage callback table.
 * \param nsid [const] A pointer to the namespace identifier bytes.
 * \param nsidlen The namespace identifier length in bytes.
 * \param publickey [const] A pointer to the Dilithium public key.
 * \param headbuf A pointer to a caller-provided buffer used to read the head checkpoint bundle.
 * \param headbuflen The length of the head buffer in bytes.
 *
 * \return Returns true if the ledger was initialized successfully.
 */
MCEL_EXPORT_API bool mcel_ledger_initialize(mcel_ledger_state* state, const mcel_store_callbacks* store, const uint8_t* nsid, size_t nsidlen,
	const uint8_t* publickey, uint8_t* headbuf, size_t headbuflen);

/*!
 * \brief Seal a block from record commitments and write the sealed block through the storage callbacks.
 *
 * \param state A pointer to the ledger state structure.
 * \param blkroot A pointer to the output block Merkle root array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param blkcommit A pointer to the output block commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param header [const] A pointer to the block header structure.
 * \param reccommits [const] A pointer to an array of record commitments (reccount * MCEL_BLOCK_HASH_SIZE).
 * \param reccount The number of record commitments.
 * \param blockbuf A pointer to a caller-provided buffer used to encode the sealed block.
 * \param blockbuflen The length of the block buffer in bytes.
 * \param outpos A pointer to the returned append position offset, can be NULL.
 *
 * \return Returns true if the block was sealed and stored successfully.
 */
MCEL_EXPORT_API bool mcel_ledger_seal_block(mcel_ledger_state* state, uint8_t* blkroot, uint8_t* blkcommit, const mcel_block_header* header,
	const uint8_t* reccommits, size_t reccount, uint8_t* blockbuf, size_t blockbuflen, uint64_t* outpos);

/*!
 * \brief Seal a checkpoint from a sealed block root and update the ledger head.
 *
 * \param state A pointer to the ledger state structure.
 * \param chkcommit A pointer to the output checkpoint commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param header [const] A pointer to the checkpoint header structure.
 * \param blkroot [const] A pointer to the sealed block Merkle root array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param sigkey [const] A pointer to the Dilithium private signing key.
 * \param bundlebuf A pointer to a caller-provided buffer used to encode the checkpoint bundle.
 * \param bundlebuflen The length of the bundle buffer in bytes.
 * \param outpos A pointer to the returned append position offset, can be NULL.
 *
 * \return Returns true if the checkpoint was sealed and stored successfully.
 */
MCEL_EXPORT_API bool mcel_ledger_seal_checkpoint(mcel_ledger_state* state, uint8_t* chkcommit, const mcel_checkpoint_header* header, 
	const uint8_t* blkroot, const void* sigkey, uint8_t* bundlebuf, size_t bundlebuflen, uint64_t* outpos);

/*!
 * \brief Verify the cryptographic integrity of the ledger state.
 *
 * \details
 * This function verifies the stored head checkpoint bundle (if present) by reading
 * it from the storage backend and validating its signature and commitment.
 * Optionally, an audit path may be provided to verify a sequence of checkpoint
 * bundles and their chain links.
 *
 * \param state A pointer to the ledger state structure.
 * \param headbuf A pointer to a caller-provided buffer used to read the head bundle.
 * \param headbuflen The length of the head buffer in bytes.
 * \param audit [const] An optional pointer to an audit path item array, can be NULL.
 * \param auditcount The number of audit items in the array, can be 0.
 *
 * \return Returns true if integrity checks succeeded, false on failure.
 */
MCEL_EXPORT_API bool mcel_ledger_verify_integrity(mcel_ledger_state* state, uint8_t* headbuf, size_t headbuflen, 
	const mcel_checkpoint_audit_item* audit, size_t auditcount);

/*!
 * \brief Compute a MCEL payload commitment.
 *
 * \param output A pointer to the output hash array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param encrypted Set to true if the payload is encrypted, false if plaintext.
 * \param payload [const] A pointer to the payload bytes.
 * \param paylen The length of the payload in bytes.
 *
 * \return Returns true on success.
 */
MCEL_EXPORT_API bool mcel_payload_commit(uint8_t* output, bool encrypted, const uint8_t* payload, size_t paylen);

/*!
 * \brief Apply namespace policy rules to a MCEL operation.
 *
 * \param perr A pointer to the returned policy error value.
 * \param policy [const] A pointer to the policy container.
 * \param state [const] A pointer to the policy context.
 * \param op The operation being authorized.
 * \param recordhdr [const] A pointer to the record header (append op), can be NULL otherwise.
 * \param checkpointhdr [const] A pointer to the checkpoint header (seal op), can be NULL otherwise.
 *
 * \return Returns true if the operation is allowed.
 */
MCEL_EXPORT_API bool mcel_policy_apply(mcel_policy_errors* perr, const mcel_policy* policy, const mcel_policy_context* state, mcel_policy_ops op,
	const mcel_record_header* recordhdr, const mcel_checkpoint_header* checkpointhdr);

/*!
 * \brief Decrypt a record payload using the AEAD cipher.
 *
 * \param output A pointer to the plaintext output buffer.
 * \param ciphertext [const] A pointer to the ciphertext input buffer (includes tag).
 * \param ctlen The length of the ciphertext in bytes.
 * \param ad [const] A pointer to associated data, can be NULL if \c adlen is 0.
 * \param adlen The associated data length in bytes.
 * \param key [const] A pointer to the cipher key.
 * \param nonce A pointer to the nonce array of size \c MCEL_RCS_NONCE_SIZE.
 *
 * \return Returns true if the transform completed, false on parameter or length failure.
 */
MCEL_EXPORT_API bool mcel_record_decrypt_payload(uint8_t* output, const uint8_t* ciphertext, size_t ctlen, 
    const uint8_t* ad, size_t adlen, const uint8_t* key, uint8_t* nonce);

/*!
 * \brief Encrypt a record payload using the AEAD cipher.
 *
 * \param output A pointer to the ciphertext output buffer.
 * \param plaintext [const] A pointer to the plaintext input buffer.
 * \param ptlen The length of the plaintext in bytes.
 * \param ad [const] A pointer to associated data, can be NULL if \c adlen is 0.
 * \param adlen The associated data length in bytes.
 * \param key [const] A pointer to the cipher key.
 * \param nonce A pointer to the nonce array of size \c MCEL_RCS_NONCE_SIZE.
 */
MCEL_EXPORT_API void mcel_record_encrypt_payload(uint8_t* output, const uint8_t* plaintext, size_t ptlen,
    const uint8_t* ad, size_t adlen, const uint8_t* key, uint8_t* nonce);

/*!
 * \brief Encode a MCEL record header using canonical fixed-size encoding.
 *
 * \param output A pointer to the output byte array of size \c MCEL_RECORD_HEADER_ENCODED_SIZE.
 * \param header [const] A pointer to the record header structure.
 *
 * \return Returns true if the header was encoded successfully.
 */
MCEL_EXPORT_API bool mcel_record_encode_header(uint8_t* output, const mcel_record_header* header);

/*!
 * \brief Compute a MCEL record commitment from a record header and payload commitment.
 *
 * \param output A pointer to the output hash array of size \c MCEL_BLOCK_HASH_SIZE.
 * \param header [const] A pointer to the record header structure.
 * \param pldcommit [const] A pointer to the payload commitment array of size \c MCEL_BLOCK_HASH_SIZE.
 *
 * \return Returns true if the record commitment was generated successfully.
 */
MCEL_EXPORT_API bool mcel_record_commit(uint8_t* output, const mcel_record_header* header, const uint8_t* pldcommit);

/*!
 * \brief Initialize and validate the MCEL storage callback table.
 *
 * \param output A pointer to the receiving callback table.
 * \param input [const] A pointer to the caller-supplied callback table.
 * \param context A pointer to the host-defined storage context.
 *
 * \return Returns true if the callback table is valid and initialized, false on failure.
 */
MCEL_EXPORT_API bool mcel_store_callbacks_initialize(mcel_store_callbacks* output, const mcel_store_callbacks* input, void* context);

#endif
