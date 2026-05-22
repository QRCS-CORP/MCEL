#include "functions_test.h"
#include "anchor.h"
#include "domain.h"
#include "index.h"
#include "merkle.h"
#include "mcel.h"
#include "proof.h"
#include "query.h"
#include "acp.h"
#include "consoleutils.h"
#include "dilithium.h"
#include "intutils.h"
#include "memutils.h"

static void create_test_records(mcel_record_header** headers, size_t count)
{
    for (size_t i = 0U; i < count; ++i)
    {
        headers[i] = (mcel_record_header*)qsc_memutils_malloc(sizeof(mcel_record_header));

        if (headers[i] != NULL)
        {
            qsc_memutils_clear((uint8_t*)headers[i], sizeof(mcel_record_header));
            headers[i]->sequence = i;
            /* 2024-01-01 + i hours */
            headers[i]->timestamp = 1704067200U + (i * 3600U);
            /* types 1, 2, 3 */
            headers[i]->type = (i % 3U) + 1U;
            /* flags 0, 1, 2, 3 */
            headers[i]->flags = (uint8_t)(i % 4U);
            headers[i]->version = MCEL_RECORD_VERSION;

            /* set keyid to deterministic value */
            for (size_t j = 0U; j < MCEL_RECORD_KEYID_SIZE; ++j)
            {
                headers[i]->keyid[j] = (uint8_t)((i + j) & 0xFFU);
            }
        }
    }
}

static void free_test_records(mcel_record_header** headers, size_t count)
{
    for (size_t i = 0U; i < count; ++i)
    {
        if (headers[i] != NULL)
        {
            qsc_memutils_alloc_free(headers[i]);
        }
    }
}

static size_t test_key_extractor_sequence(const void* recheader, const uint8_t* recpayload, size_t payloadlen, uint8_t*** keysout, size_t** keylensout)
{
    const mcel_record_header* header;
    uint8_t** keys;
    size_t* lens;
    size_t res;

    (void)recpayload;
    (void)payloadlen;
    res = 0U;

    if (recheader != NULL && keysout != NULL && keylensout != NULL)
    {
        header = (const mcel_record_header*)recheader;
        keys = (uint8_t**)qsc_memutils_malloc(sizeof(uint8_t*));
        lens = (size_t*)qsc_memutils_malloc(sizeof(size_t));

        if (keys != NULL)
        {
            if (lens != NULL)
            {
                keys[0] = (uint8_t*)qsc_memutils_malloc(8U);

                if (keys[0] != NULL)
                {
                    qsc_intutils_be64to8(keys[0], header->sequence);
                    lens[0] = 8U;
                    *keysout = keys;
                    *keylensout = lens;
                    res = 1U;
                }

                if (res == 0U)
                {
                    qsc_memutils_alloc_free(lens);
                }
            }

            if (res == 0U)
            {
                qsc_memutils_alloc_free(keys);
            }
        }
    }

    return res;
}

static size_t test_key_extractor_type(const void* recheader, const uint8_t* recpayload, size_t payloadlen, uint8_t*** keysout, size_t** keylensout)
{
    const mcel_record_header* header;
    uint8_t** keys;
    size_t* lens;
    size_t res;

    (void)recpayload;
    (void)payloadlen;
    res = 0U;

    if (recheader != NULL && keysout != NULL && keylensout != NULL)
    {
        header = (const mcel_record_header*)recheader;
        keys = (uint8_t**)qsc_memutils_malloc(sizeof(uint8_t*));
        lens = (size_t*)qsc_memutils_malloc(sizeof(size_t));

        if (keys != NULL)
        {
            if (lens != NULL)
            {
                keys[0U] = (uint8_t*)qsc_memutils_malloc(4U);

                if (keys[0U] != NULL)
                {
                    qsc_intutils_be32to8(keys[0], header->type);
                    lens[0U] = 4U;
                    *keysout = keys;
                    *keylensout = lens;
                    res = 1U;
                }

                if (res == 0U)
                {
                    qsc_memutils_alloc_free(lens);
                }
            }

            if (res == 0U)
            {
                qsc_memutils_alloc_free(keys);
            }
        }
    }

    return res;
}

bool mceltest_hash(void)
{
    static const uint8_t msg[4U] = { 0x61U, 0x62U, 0x63U, 0x64U };
    uint8_t h1[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t h2[MCEL_BLOCK_HASH_SIZE] = { 0U };
    const uint8_t* crec;
    const uint8_t* cnde;
    bool res;

    res = false;
    crec = (const uint8_t*)mcel_domain_to_name(mcel_domain_record);
    cnde = (const uint8_t*)mcel_domain_to_name(mcel_domain_node);
    res = mcel_domain_hash_message(h1, mcel_domain_record, msg, sizeof(msg));

    if (res == true)
    {
        qsc_cshake256_compute(h2, MCEL_BLOCK_HASH_SIZE, msg, sizeof(msg), (const uint8_t*)MCEL_DOMAIN_NAME_STRING, sizeof(MCEL_DOMAIN_NAME_STRING) - 1U, 
            crec, MCEL_DOMAIN_STRING_WIDTH - 1U);

        res = (qsc_intutils_are_equal8(h1, h2, MCEL_BLOCK_HASH_SIZE) == true);
    }

    if (res == true)
    {
        qsc_memutils_clear(h1, sizeof(h1));
        qsc_memutils_clear(h2, sizeof(h2));

        res = mcel_merkle_root_hash(h1, mcel_domain_record);

        if (res == true)
        {
            qsc_cshake256_compute(h2, MCEL_BLOCK_HASH_SIZE, (const uint8_t*)MCEL_DOMAIN_NAME_STRING, sizeof(MCEL_DOMAIN_NAME_STRING) - 1U, 
                NULL, 0U, crec, MCEL_DOMAIN_STRING_WIDTH - 1U);

            res = (qsc_intutils_are_equal8(h1, h2, MCEL_BLOCK_HASH_SIZE) == true);
        }
    }

    if (res == true)
    {
        qsc_memutils_clear(h1, sizeof(h1));
        qsc_memutils_clear(h2, sizeof(h2));

        qsc_cshake256_compute(h1, MCEL_BLOCK_HASH_SIZE, msg, sizeof(msg), (const uint8_t*)MCEL_DOMAIN_NAME_STRING, sizeof(MCEL_DOMAIN_NAME_STRING) - 1U, crec, MCEL_DOMAIN_STRING_WIDTH - 1U);

        qsc_cshake256_compute(h2, MCEL_BLOCK_HASH_SIZE, msg, sizeof(msg), (const uint8_t*)MCEL_DOMAIN_NAME_STRING, sizeof(MCEL_DOMAIN_NAME_STRING) - 1U, cnde, MCEL_DOMAIN_STRING_WIDTH - 1U);

        res = (qsc_intutils_are_equal8(h1, h2, MCEL_BLOCK_HASH_SIZE) == false);
    }

    return res;
}

bool mceltest_merkle(void)
{
    uint8_t leaves4[(size_t)MCEL_BLOCK_HASH_SIZE * 4U] = { 0U };
    uint8_t leaves5[(size_t)MCEL_BLOCK_HASH_SIZE * 5U] = { 0U };
    uint8_t proof[(size_t)MCEL_BLOCK_HASH_SIZE * 8U] = { 0U };
    uint8_t root4a[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t root4b[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t root5a[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t root5b[MCEL_BLOCK_HASH_SIZE] = { 0U };
    size_t prooflen;
    size_t req;
    bool res;

    res = false;

    /* fill leaves with simple structured data */
    for (size_t i = 0; i < 5U; ++i)
    {
        /* leaf i = H_record( "leaf" || i ) is overkill, use deterministic bytes */
        for (size_t j = 0; j < (size_t)MCEL_BLOCK_HASH_SIZE; ++j)
        {
            leaves5[(i * (size_t)MCEL_BLOCK_HASH_SIZE) + j] = (uint8_t)(0xA0U + (uint8_t)i);
        }
    }

    for (size_t i = 0; i < 4U; ++i)
    {
        for (size_t j = 0; j < (size_t)MCEL_BLOCK_HASH_SIZE; ++j)
        {
            leaves4[(i * (size_t)MCEL_BLOCK_HASH_SIZE) + j] = (uint8_t)(0xB0U + (uint8_t)i);
        }
    }

    /* root computation must succeed and be deterministic */
    res = mcel_merkle_root(root5a, leaves5, 5U);

    if (res == true)
    {
        res = mcel_merkle_root(root5b, leaves5, 5U);

        if (res == true)
        {
            res = (qsc_intutils_are_equal8(root5a, root5b, MCEL_BLOCK_HASH_SIZE) == true);

            if (res == true)
            {
                res = mcel_merkle_root(root4a, leaves4, 4U);

                if (res == true)
                {
                    res = mcel_merkle_root(root4b, leaves4, 4U);

                    if (res == true)
                    {
                        res = (qsc_intutils_are_equal8(root4a, root4b, MCEL_BLOCK_HASH_SIZE) == true);
                    }
                }
            }
        }
    }

    /* odd-leaf rule sanity: changing last leaf should change root (most of the time) */
    if (res == true)
    {
        uint8_t tmp[(size_t)MCEL_BLOCK_HASH_SIZE * 5U];
        uint8_t root5c[MCEL_BLOCK_HASH_SIZE] = { 0U };

        qsc_memutils_copy(tmp, leaves5, sizeof(tmp));
        tmp[(4U * (size_t)MCEL_BLOCK_HASH_SIZE)] ^= 0x01U;

        res = mcel_merkle_root(root5c, tmp, 5U);

        if (res == true)
        {
            res = (qsc_intutils_are_equal8(root5a, root5c, MCEL_BLOCK_HASH_SIZE) == false);
        }
    }

    /* membership proof: index 3 of 5 leaves */
    if (res == true)
    {
        req = mcel_merkle_proof_size(5U);
        prooflen = req;

        if (req != 0U || req <= sizeof(proof))
        {
            qsc_memutils_clear(proof, sizeof(proof));

            res = mcel_merkle_prove_member(proof, prooflen, leaves5, 5U, 3U);

            if (res == true)
            {
                res = mcel_merkle_member_verify(root5a, leaves5 + (3U * (size_t)MCEL_BLOCK_HASH_SIZE), proof, prooflen, 5U, 3U);
            }

            /* tamper proof and verify must fail */
            if (res == true)
            {
                proof[0] ^= 0x01U;

                res = (mcel_merkle_member_verify(root5a, leaves5 + (3U * (size_t)MCEL_BLOCK_HASH_SIZE), proof, prooflen, 5U, 3U) == false);
            }
        }
        else
        {
            res = false;
        }
    }

    /* membership proof: index 1 of 4 leaves */
    if (res == true)
    {
        req = mcel_merkle_proof_size(4U);
        prooflen = req;

        if (req != 0U || req <= sizeof(proof))
        {
            qsc_memutils_clear(proof, sizeof(proof));

            res = mcel_merkle_prove_member(proof, prooflen, leaves4, 4U, 1U);

            if (res == true)
            {
                res = mcel_merkle_member_verify(root4a, leaves4 + (1U * (size_t)MCEL_BLOCK_HASH_SIZE), proof, prooflen, 4U, 1U);
            }
        }
        else
        {
            res = false;
        }
    }

    return res;
}

bool mceltest_record_commit(void)
{
    uint8_t henc[MCEL_RECORD_HEADER_ENCODED_SIZE] = { 0U };
    uint8_t msg[(size_t)MCEL_RECORD_HEADER_ENCODED_SIZE + (size_t)MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t pldptxt[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t recptxt[MCEL_BLOCK_HASH_SIZE] = { 0U };
    bool res;

    static const uint8_t payload[16U] =
    {
        0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U,
        0x08U, 0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU
    };

    res = false;

    /* build a deterministic record header */
    mcel_record_header hdr = { 
        .keyid[0] = 0xA5U,
        .sequence = 1U,
        .timestamp = 2U,
        .payload_len = (uint32_t)sizeof(payload),
        .type = (uint32_t)mcel_record_type_event,
        .flags = 0U,
        .version = (uint8_t)MCEL_RECORD_VERSION,
    };

    qsc_memutils_clear(hdr.keyid + 1U, MCEL_RECORD_KEYID_SIZE - 1U);

    /* payload commitments check */
    res = mcel_payload_commit(pldptxt, false, payload, sizeof(payload));

    if (res == true)
    {
        uint8_t pctxta[MCEL_BLOCK_HASH_SIZE] = { 0U };
        uint8_t pctxtb[MCEL_BLOCK_HASH_SIZE] = { 0U };
        uint8_t ptxtr[MCEL_BLOCK_HASH_SIZE] = { 0U };

        res = mcel_payload_commit(pctxta, true, payload, sizeof(payload));

        /* direct reference: plaintext */
        if (res == true)
        {
            const uint8_t* custptxt = (const uint8_t*)mcel_domain_to_name(mcel_domain_plaintext);

            qsc_cshake256_compute(ptxtr, MCEL_BLOCK_HASH_SIZE, payload, sizeof(payload),
                (const uint8_t*)MCEL_DOMAIN_NAME_STRING, sizeof(MCEL_DOMAIN_NAME_STRING) - 1U,
                custptxt, MCEL_DOMAIN_STRING_WIDTH - 1U);

            res = (qsc_intutils_are_equal8(pldptxt, ptxtr, MCEL_BLOCK_HASH_SIZE) == true);

            /* direct reference: ciphertext */
            if (res == true)
            {
                const uint8_t* custctxt = (const uint8_t*)mcel_domain_to_name(mcel_domain_ciphertext);

                qsc_cshake256_compute(pctxtb, MCEL_BLOCK_HASH_SIZE, payload, sizeof(payload),
                    (const uint8_t*)MCEL_DOMAIN_NAME_STRING, sizeof(MCEL_DOMAIN_NAME_STRING) - 1U,
                    custctxt, MCEL_DOMAIN_STRING_WIDTH - 1U);

                res = (qsc_intutils_are_equal8(pctxta, pctxtb, MCEL_BLOCK_HASH_SIZE) == true);

                /* plaintext vs ciphertext domain separation */
                if (res == true)
                {
                    res = (qsc_intutils_are_equal8(pldptxt, pctxta, MCEL_BLOCK_HASH_SIZE) == false);
                }
            }
        }
    }

    /* record commitment */
    if (res == true)
    {
        res = mcel_record_encode_header(henc, &hdr);

        if (res == true)
        {
            res = mcel_record_commit(recptxt, &hdr, pldptxt);

            /* direct reference: H_record( enc(hdr) || pldcommit ) */
            if (res == true)
            {
                uint8_t recptxtr[MCEL_BLOCK_HASH_SIZE] = { 0U };
                const uint8_t* custrecd = (const uint8_t*)mcel_domain_to_name(mcel_domain_record);

                qsc_memutils_copy(msg, henc, (size_t)MCEL_RECORD_HEADER_ENCODED_SIZE);
                qsc_memutils_copy(msg + (size_t)MCEL_RECORD_HEADER_ENCODED_SIZE, pldptxt, MCEL_BLOCK_HASH_SIZE);

                qsc_cshake256_compute(recptxtr, MCEL_BLOCK_HASH_SIZE, msg, sizeof(msg),
                    (const uint8_t*)MCEL_DOMAIN_NAME_STRING, sizeof(MCEL_DOMAIN_NAME_STRING) - 1U,
                    custrecd, MCEL_DOMAIN_STRING_WIDTH - 1U);

                res = (qsc_intutils_are_equal8(recptxt, recptxtr, MCEL_BLOCK_HASH_SIZE) == true);
            }
        }
    }

    /* sensitivity checks */
    if (res == true)
    {
        uint8_t payload2[16U];
        uint8_t pld2[MCEL_BLOCK_HASH_SIZE] = { 0U };
        uint8_t rec2[MCEL_BLOCK_HASH_SIZE] = { 0U };

        qsc_memutils_copy(payload2, payload, sizeof(payload2));
        payload2[0] ^= 0x01U;

        res = mcel_payload_commit(pld2, false, payload2, sizeof(payload2));

        if (res == true)
        {
            /* payload change must change plaintext payload commitment */
            res = (qsc_intutils_are_equal8(pldptxt, pld2, MCEL_BLOCK_HASH_SIZE) == false);

            if (res == true)
            {
                res = mcel_record_commit(rec2, &hdr, pld2);

                if (res == true)
                {
                    /* payload change must change record commitment */
                    res = (qsc_intutils_are_equal8(recptxt, rec2, MCEL_BLOCK_HASH_SIZE) == false);
                }
            }
        }
    }

    return res;
}

bool mceltest_block_seal(void)
{
    uint8_t blkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t blkroot2[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t blkcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t blkcommit2[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t enc[(size_t)MCEL_BLOCK_HEADER_ENCODED_SIZE + ((size_t)MCEL_BLOCK_HASH_SIZE * 2U) + ((size_t)MCEL_BLOCK_HASH_SIZE * 5U)] = { 0U };
    uint8_t reccommits[(size_t)MCEL_BLOCK_HASH_SIZE * 5U] = { 0U };
    size_t encsz;
    size_t pos;
    bool res;

    res = false;
    encsz = 0U;

    /* fill deterministic commitments */
    for (size_t i = 0; i < 5U; ++i)
    {
        for (size_t j = 0; j < (size_t)MCEL_BLOCK_HASH_SIZE; ++j)
        {
            reccommits[(i * (size_t)MCEL_BLOCK_HASH_SIZE) + j] = (uint8_t)(0xC0U + (uint8_t)i);
        }
    }

    /* deterministic block header */

    mcel_block_header hdr = {
        .version = (uint8_t)MCEL_BLOCK_VERSION,
        .flags = 0U,
        .block_sequence = 7U,
        .first_record_seq = 100U,
        .record_count = 5U,
        .timestamp = 123456U,

        .keyid[0] = 0xA5U,
    };

    qsc_memutils_clear(hdr.keyid + 1, MCEL_BLOCK_KEYID_SIZE - 1U),

    /* merkle root */
    res = mcel_merkle_root(blkroot, reccommits, 5U);

    /* block commitment */
    if (res == true)
    {
        res = mcel_block_commit(blkcommit, &hdr, blkroot);
    }

    /* encoded size must match and fit */
    if (res == true)
    {
        encsz = mcel_block_encoded_size(5U);

        if (encsz == 0U || encsz > sizeof(enc))
        {
            return false;
        }

        qsc_memutils_clear(enc, sizeof(enc));

        res = mcel_block_encode(enc, encsz, &hdr, blkroot, blkcommit, reccommits, 5U);
    }

    /* verify canonical encoding layout */
    if (res == true)
    {
        pos = 0;
        pos += (size_t)MCEL_BLOCK_HEADER_ENCODED_SIZE;
        res = (qsc_intutils_are_equal8(enc + pos, blkroot, MCEL_BLOCK_HASH_SIZE) == true);
        pos += (size_t)MCEL_BLOCK_HASH_SIZE;

        if (res == true)
        {
            res = (qsc_intutils_are_equal8(enc + pos, blkcommit, MCEL_BLOCK_HASH_SIZE) == true);
        }

        pos += (size_t)MCEL_BLOCK_HASH_SIZE;

        if (res == true)
        {
            res = (qsc_intutils_are_equal8(enc + pos, reccommits, (size_t)MCEL_BLOCK_HASH_SIZE * 5U) == true);
        }

        pos += (size_t)MCEL_BLOCK_HASH_SIZE * 5U;

        if (res == true)
        {
            res = (pos == encsz);
        }
    }

    /* recompute from same inputs, must match */
    if (res == true)
    {
        res = mcel_merkle_root(blkroot2, reccommits, 5U);

        if (res == true)
        {
            res = (qsc_intutils_are_equal8(blkroot, blkroot2, MCEL_BLOCK_HASH_SIZE) == true);
        }

        if (res == true)
        {
            res = mcel_block_commit(blkcommit2, &hdr, blkroot2);
        }

        if (res == true)
        {
            res = (qsc_intutils_are_equal8(blkcommit, blkcommit2, MCEL_BLOCK_HASH_SIZE) == true);
        }
    }

    /* tamper a record commitment, root must change and commit must change */
    if (res == true)
    {
        uint8_t tampered[(size_t)MCEL_BLOCK_HASH_SIZE * 5U];
        uint8_t troot[MCEL_BLOCK_HASH_SIZE] = { 0U };
        uint8_t tcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };

        qsc_memutils_copy(tampered, reccommits, sizeof(tampered));
        tampered[2U * (size_t)MCEL_BLOCK_HASH_SIZE] ^= 0x01U;

        res = mcel_merkle_root(troot, tampered, 5U);

        if (res == true)
        {
            res = (qsc_intutils_are_equal8(blkroot, troot, MCEL_BLOCK_HASH_SIZE) == false);
        }

        if (res == true)
        {
            res = mcel_block_commit(tcommit, &hdr, troot);
        }

        if (res == true)
        {
            res = (qsc_intutils_are_equal8(blkcommit, tcommit, MCEL_BLOCK_HASH_SIZE) == false);
        }
    }

    return res;
}

bool mceltest_checkpoint_seal_verify(void)
{
    mcel_checkpoint_header hdr0 = { 0U };
    mcel_checkpoint_header hdr1 = { 0U };
    mcel_checkpoint_header vhdr = { 0U };
    uint8_t blkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t bundle0[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE] = { 0U };
    uint8_t bundle1[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE] = { 0U };
    uint8_t chkcommit0[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t chkcommit1[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t prevcommit0[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t prevcommit1[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t sig0[MCEL_CHECKPOINT_SIGNED_COMMIT_SIZE] = { 0U };
    uint8_t sig1[MCEL_CHECKPOINT_SIGNED_COMMIT_SIZE] = { 0U };
    uint8_t sigpk[MCEL_ASYMMETRIC_VERIFY_KEY_SIZE] = { 0U };
    uint8_t sigsk[MCEL_ASYMMETRIC_SIGNING_KEY_SIZE] = { 0U };
    uint8_t vblkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t vcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t vprev[MCEL_BLOCK_HASH_SIZE] = { 0U };
    size_t sig0len;
    size_t sig1len;
    bool res;

    res = false;
    sig0len = 0U;
    sig1len = 0U;

    for (size_t i = 0; i < (size_t)MCEL_BLOCK_HASH_SIZE; ++i)
    {
        blkroot[i] = (uint8_t)(0x11U + (uint8_t)i);
    }

    qsc_dilithium_generate_keypair(sigpk, sigsk, qsc_acp_generate);

    hdr0.keyid[0] = 0xA5U;
    hdr0.chk_sequence = 1U;
    hdr0.first_record_seq = 100U;
    hdr0.timestamp = 200U;
    hdr0.record_count = 5U;
    hdr0.version = (uint8_t)MCEL_CHECKPOINT_VERSION;
    hdr0.flags = 0U;

    /* compute commitment and sign */
    res = mcel_checkpoint_commit(chkcommit0, &hdr0, blkroot, prevcommit0);

    if (res == true)
    {
        sig0len = 0U;
        res = mcel_checkpoint_sign(sig0, &sig0len, chkcommit0, sigsk, qsc_acp_generate);
    }

    if (res == true)
    {
        res = mcel_checkpoint_bundle_encode(bundle0, sizeof(bundle0), &hdr0, blkroot, prevcommit0, sig0, sig0len);

        if (res == true)
        {
            qsc_memutils_clear(&vhdr, sizeof(vhdr));
            qsc_memutils_clear(vcommit, MCEL_BLOCK_HASH_SIZE);
            qsc_memutils_clear(vblkroot, MCEL_BLOCK_HASH_SIZE);
            qsc_memutils_clear(vprev, MCEL_BLOCK_HASH_SIZE);

            res = mcel_checkpoint_bundle_verify(vcommit, &vhdr, vblkroot, vprev, bundle0, sizeof(bundle0), sigpk);

            if (res == true)
            {
                res = (qsc_intutils_are_equal8(vcommit, chkcommit0, MCEL_BLOCK_HASH_SIZE) == true);

                if (res == true)
                {
                    res = (qsc_intutils_are_equal8(vblkroot, blkroot, MCEL_BLOCK_HASH_SIZE) == true);

                    if (res == true)
                    {
                        res = (qsc_intutils_are_equal8(vprev, prevcommit0, MCEL_BLOCK_HASH_SIZE) == true);

                        if (res == true)
                        {
                            res = (vhdr.chk_sequence == hdr0.chk_sequence) &&
                                (vhdr.first_record_seq == hdr0.first_record_seq) &&
                                (vhdr.record_count == hdr0.record_count) &&
                                (vhdr.timestamp == hdr0.timestamp) &&
                                (vhdr.version == hdr0.version) &&
                                (vhdr.flags == hdr0.flags) &&
                                (qsc_intutils_are_equal8(vhdr.keyid, hdr0.keyid, MCEL_CHECKPOINT_KEYID_SIZE) == true);
                        }
                    }
                }
            }
        }
    }

    /* build hdr1, prevcommit = chkcommit0 */
    if (res == true)
    {
        qsc_memutils_copy(prevcommit1, chkcommit0, MCEL_BLOCK_HASH_SIZE);

        hdr1.chk_sequence = 2U;
        hdr1.first_record_seq = 105U;
        hdr1.timestamp = 250U;
        hdr1.record_count = 3U;
        hdr1.version = (uint8_t)MCEL_CHECKPOINT_VERSION;
        hdr1.flags = 0U;

        qsc_memutils_copy(hdr1.keyid, hdr0.keyid, MCEL_CHECKPOINT_KEYID_SIZE);

        res = mcel_checkpoint_commit(chkcommit1, &hdr1, blkroot, prevcommit1);

        if (res == true)
        {
            sig1len = 0U;
            res = mcel_checkpoint_sign(sig1, &sig1len, chkcommit1, sigsk, qsc_acp_generate);

            if (res == true)
            {
                if (res == true)
                {
                    res = mcel_checkpoint_bundle_encode(bundle1, sizeof(bundle1), &hdr1, blkroot, prevcommit1, sig1, sig1len);
                }
            }
        }
    }

    /* verify bundle1 */
    if (res == true)
    {
        qsc_memutils_clear(&vhdr, sizeof(vhdr));
        qsc_memutils_clear(vcommit, MCEL_BLOCK_HASH_SIZE);
        qsc_memutils_clear(vblkroot, MCEL_BLOCK_HASH_SIZE);
        qsc_memutils_clear(vprev, MCEL_BLOCK_HASH_SIZE);

        res = mcel_checkpoint_bundle_verify(vcommit, &vhdr, vblkroot, vprev, bundle1, sizeof(bundle1), sigpk);

        if (res == true)
        {
            res = (qsc_intutils_are_equal8(vcommit, chkcommit1, MCEL_BLOCK_HASH_SIZE) == true);
        }

        if (res == true)
        {
            res = (qsc_intutils_are_equal8(vprev, chkcommit0, MCEL_BLOCK_HASH_SIZE) == true);
        }
    }

    /* verify chain link between checkpoint 0 and 1 */
    if (res == true)
    {
        res = mcel_checkpoint_chain_link_verify(chkcommit0, prevcommit1, &hdr0, &hdr1);
    }

    /* negative: tamper prevcommit, chain link must fail */
    if (res == true)
    {
        uint8_t badprev[MCEL_BLOCK_HASH_SIZE];

        qsc_memutils_copy(badprev, prevcommit1, MCEL_BLOCK_HASH_SIZE);
        badprev[0] ^= 0x01U;

        res = (mcel_checkpoint_chain_link_verify(chkcommit0, badprev, &hdr0, &hdr1) == false);
    }

    return res;
}

bool mceltest_index(void)
{
    mcel_index idx = { 0U };
    mcel_record_header* headers[100U] = { 0U };
    const void* header_ptrs[100U] = { 0U };
    uint8_t key[8U] = { 0U };
    uint64_t* positions;
    size_t count;
    bool res;

    res = false;

    /* create primary index */
    if (mcel_index_create(&idx, 16U, mcel_index_type_primary) == true)
    {
        res = true;

        /* insert keys */
        for (size_t i = 0U; i < 10U && res == true; ++i)
        {
            qsc_intutils_be64to8(key, i);

            if (mcel_index_insert(&idx, key, sizeof(key), i) == false)
            {
                res = false;
            }
        }

        /* lookup existing key */
        if (res == true)
        {
            qsc_intutils_be64to8(key, 5U);

            if (mcel_index_lookup(&idx, key, sizeof(key), &positions, &count) == true)
            {
                res = (count == 1U && positions[0U] == 5U);

                if (positions != NULL)
                {
                    qsc_memutils_alloc_free(positions);
                }
            }
            else
            {
                res = false;
            }
        }

        /* lookup non-existent key */
        if (res == true)
        {
            qsc_intutils_be64to8(key, 99U);

            if (mcel_index_lookup(&idx, key, sizeof(key), &positions, &count) == true)
            {
                res = (count == 0U);
            }
            else
            {
                res = false;
            }
        }

        /* primary index rejects duplicate keys */
        if (res == true)
        {
            qsc_intutils_be64to8(key, 5U);

            /* Inserting duplicate should fail for primary index */
            res = (mcel_index_insert(&idx, key, sizeof(key), 100U) == false);
        }

        mcel_index_dispose(&idx);
    }

    /* secondary index allows duplicates */
    if (res == true)
    {
        if (mcel_index_create(&idx, 16U, mcel_index_type_secondary) == true)
        {
            qsc_intutils_be64to8(key, 42U);

            /* insert same key multiple times */
            res = mcel_index_insert(&idx, key, sizeof(key), 10U);

            if (res == true)
            {
                res = mcel_index_insert(&idx, key, sizeof(key), 20U);
            }

            if (res == true)
            {
                res = mcel_index_insert(&idx, key, sizeof(key), 30U);
            }

            /* lookup should return all three positions */
            if (res == true)
            {
                if (mcel_index_lookup(&idx, key, sizeof(key), &positions, &count) == true)
                {
                    res = (count == 3U);

                    if (res == true)
                    {
                        /* verify all positions are present (order may vary) */
                        bool found10;
                        bool found20;
                        bool found30;

                        found10 = false;
                        found20 = false;
                        found30 = false;

                        for (size_t i = 0; i < count; ++i)
                        {
                            if (positions[i] == 10U)
                            {
                                found10 = true;
                            }
                            else if (positions[i] == 20U)
                            {
                                found20 = true;
                            }
                            else if (positions[i] == 30U)
                            {
                                found30 = true;
                            }
                        }

                        res = (found10 == true && found20 == true && found30 == true);
                    }

                    if (positions != NULL)
                    {
                        qsc_memutils_alloc_free(positions);
                    }
                }
                else
                {
                    res = false;
                }
            }

            mcel_index_dispose(&idx);
        }
        else
        {
            res = false;
        }
    }

    /* rebuild and verify */
    if (res == true)
    {
        create_test_records(headers, 50U);

        for (size_t i = 0U; i < 50U; ++i)
        {
            header_ptrs[i] = headers[i];
        }

        if (mcel_index_create(&idx, 0U, mcel_index_type_primary) == true)
        {
            res = mcel_index_rebuild(&idx, header_ptrs, NULL, NULL, 50U, test_key_extractor_sequence);

            if (res == true)
            {
                /* verify rebuild worked, lookup a key */
                qsc_intutils_be64to8(key, 25U);

                if (mcel_index_lookup(&idx, key, sizeof(key), &positions, &count) == true)
                {
                    res = (count == 1U && positions[0U] == 25U);

                    if (positions != NULL)
                    {
                        qsc_memutils_alloc_free(positions);
                    }
                }
                else
                {
                    res = false;
                }
            }

            /* verify index integrity */
            if (res == true)
            {
                res = mcel_index_verify(&idx, header_ptrs, NULL, NULL, 50U, test_key_extractor_sequence);
            }

            mcel_index_dispose(&idx);
        }
        else
        {
            res = false;
        }

        free_test_records(headers, 50U);
    }

    return res;
}

bool mceltest_query(void)
{
    mcel_record_header* headers[100U] = { 0U };
    const void* header_ptrs[100U] = { 0U };
    mcel_query_filter filter = { 0U };
    mcel_query_result result = { 0U };
    bool res;

    res = false;

    /* create test records */
    create_test_records(headers, 100U);

    for (size_t i = 0; i < 100U; ++i)
    {
        header_ptrs[i] = headers[i];
    }

    /* query all records (no filter) */
    mcel_query_filter_init(&filter);

    if (mcel_query_execute(&result, header_ptrs, NULL, NULL, 100U, &filter, NULL) == true)
    {
        res = (result.count == 100U);
        mcel_query_result_dispose(&result);
    }

    /* filter by timestamp range */
    if (res == true)
    {
        mcel_query_filter_init(&filter);
        /* after record 10 */
        filter.afterts = 1704067200U + (10U * 3600U);
        /* before record 20 */
        filter.beforets = 1704067200U + (20U * 3600U);

        if (mcel_query_execute(&result, header_ptrs, NULL, NULL, 100U, &filter, NULL) == true)
        {
            /* should match records 11-19 (9 records) */
            res = (result.count == 9U);
            mcel_query_result_dispose(&result);
        }
        else
        {
            res = false;
        }
    }

    /* filter by record type */
    if (res == true)
    {
        mcel_query_filter_init(&filter);
        /* type 2 */
        filter.requiredtype = 2U;

        if (mcel_query_execute(&result, header_ptrs, NULL, NULL, 100U, &filter, NULL) == true)
        {
            /* records with type 2: indices 1, 4, 7, ... (every 3rd starting at 1) */
            /* count = floor(100 / 3) = 33 */
            res = (result.count == 33U);

            /* verify all returned records have correct type */
            if (res == true)
            {
                for (size_t i = 0; i < result.count; ++i)
                {
                    const mcel_record_header* hdr;

                    hdr = (const mcel_record_header*)header_ptrs[result.recpositions[i]];

                    if (hdr->type != 2U)
                    {
                        res = false;
                        break;
                    }
                }
            }

            mcel_query_result_dispose(&result);
        }
        else
        {
            res = false;
        }
    }

    /* filter by flags */
    if (res == true)
    {
        mcel_query_filter_init(&filter);
        /* must have bit 0 set */
        filter.requiredflags = 0x01U;

        if (mcel_query_execute(&result, header_ptrs, NULL, NULL, 100U, &filter, NULL) == true)
        {
            /* records with flags & 0x01: indices 1, 3, 5, 7, ... */
            res = (result.count == 50U);
            mcel_query_result_dispose(&result);
        }
        else
        {
            res = false;
        }
    }

    /* pagination with offset and limit */
    if (res == true)
    {
        mcel_query_filter_init(&filter);
        filter.offset = 10U;
        filter.limit = 5U;

        if (mcel_query_execute(&result, header_ptrs, NULL, NULL, 100U, &filter, NULL) == true)
        {
            res = (result.count == 5U && result.hasmore != 0U);

            /* verify positions are 10, 11, 12, 13, 14 */
            if (res == true)
            {
                for (size_t i = 0U; i < result.count; ++i)
                {
                    if (result.recpositions[i] != (10U + i))
                    {
                        res = false;
                        break;
                    }
                }
            }

            mcel_query_result_dispose(&result);
        }
        else
        {
            res = false;
        }
    }

    /* reverse order */
    if (res == true)
    {
        mcel_query_filter_init(&filter);
        filter.reverseorder = 1U;
        filter.limit = 10U;

        if (mcel_query_execute(&result, header_ptrs, NULL, NULL, 100U, &filter, NULL) == true)
        {
            res = (result.count == 10U);

            /* verify positions are 99, 98, 97, ... 90 */
            if (res == true)
            {
                for (size_t i = 0; i < result.count; ++i)
                {
                    if (result.recpositions[i] != (99U - i))
                    {
                        res = false;
                        break;
                    }
                }
            }

            mcel_query_result_dispose(&result);
        }
        else
        {
            res = false;
        }
    }

    /* count without retrieval */
    if (res == true)
    {
        size_t match_count;

        mcel_query_filter_init(&filter);
        filter.requiredtype = 1U;

        if (mcel_query_count(&match_count, header_ptrs, 100U, &filter) == true)
        {
            /* type 1 appears at indices 0, 3, 6, ... = 34 times */
            res = (match_count == 34U);
        }
        else
        {
            res = false;
        }
    }

    /* combined filters */
    if (res == true)
    {
        mcel_query_filter_init(&filter);
        filter.requiredtype = 2U;
        /* type 2 AND flags with bit 1 set */
        filter.requiredflags = 0x02U;

        if (mcel_query_execute(&result, header_ptrs, NULL, NULL, 100U, &filter, NULL) == true)
        {
            /* type 2 at indices 1, 4, 7, 10, 13, ...
             * flags 0x02 at indices 2, 6, 10, 14, ...
             * intersection: 10, 22, 34, 46, 58, 70, 82, 94 = 8 records */
            res = (result.count == 16U);
            mcel_query_result_dispose(&result);
        }
        else
        {
            res = false;
        }
    }

    free_test_records(headers, 100U);

    return res;
}

bool mceltest_proof(void)
{
    mcel_merkle_proof proof = { 0U };
    uint8_t record_commits[10U * MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t merkle_root[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t serialized[MCEL_PROOF_MAX_SERIALIZED_SIZE] = { 0U };
    size_t written;
    bool res;

    written = 0U;
    res = false;

    /* Create test record commitments */
    for (size_t i = 0U; i < 10U; ++i)
    {
        for (size_t j = 0; j < MCEL_BLOCK_HASH_SIZE; ++j)
        {
            record_commits[(i * MCEL_BLOCK_HASH_SIZE) + j] = (uint8_t)(0xA0U + (uint8_t)i);
        }
    }

    /* compute Merkle root */
    if (mcel_merkle_root(merkle_root, record_commits, 10U) == true)
    {
        res = true;

        /* generate proof for middle record */
        if (mcel_proof_generate(&proof, record_commits, 10U, 5U, merkle_root) == true)
        {
            /* verify proof */
            if (mcel_proof_verify(&proof, merkle_root, 10U) == true)
            {
                res = true;
            }
            else
            {
                res = false;
            }

            /* serialize proof */
            if (res == true)
            {
                if (mcel_proof_serialize(serialized, sizeof(serialized), &proof, &written) == true)
                {
                    res = (written > 0U && written < sizeof(serialized));
                }
                else
                {
                    res = false;
                }
            }

            mcel_proof_dispose(&proof);
        }
        else
        {
            res = false;
        }
    }

    /* deserialize and verify */
    if (res == true)
    {
        if (mcel_proof_deserialize(&proof, serialized, written) == true)
        {
            res = mcel_proof_verify(&proof, merkle_root, 10U);
            mcel_proof_dispose(&proof);
        }
        else
        {
            res = false;
        }
    }

    /* proof for first record */
    if (res == true)
    {
        if (mcel_proof_generate(&proof, record_commits, 10U, 0U, merkle_root) == true)
        {
            res = mcel_proof_verify(&proof, merkle_root, 10U);
            mcel_proof_dispose(&proof);
        }
        else
        {
            res = false;
        }
    }

    /* proof for last record (edge case) */
    if (res == true)
    {
        if (mcel_proof_generate(&proof, record_commits, 10U, 9U, merkle_root) == true)
        {
            res = mcel_proof_verify(&proof, merkle_root, 10U);
            mcel_proof_dispose(&proof);
        }
        else
        {
            res = false;
        }
    }

    /* invalid proof (wrong root) */
    if (res == true)
    {
        uint8_t wrong_root[MCEL_BLOCK_HASH_SIZE];

        qsc_memutils_copy(wrong_root, merkle_root, MCEL_BLOCK_HASH_SIZE);
        wrong_root[0] ^= 0x01U;  /* Corrupt root */

        if (mcel_proof_generate(&proof, record_commits, 10U, 5U, merkle_root) == true)
        {
            /* verification against wrong root should fail */
            res = (mcel_proof_verify(&proof, wrong_root, 10U) == false);
            mcel_proof_dispose(&proof);
        }
        else
        {
            res = false;
        }
    }

    /* invalid proof (wrong record count) */
    if (res == true)
    {
        if (mcel_proof_generate(&proof, record_commits, 10U, 5U, merkle_root) == true)
        {
            /* verification with wrong count should fail */
            res = (mcel_proof_verify(&proof, merkle_root, 11U) == false);
            mcel_proof_dispose(&proof);
        }
        else
        {
            res = false;
        }
    }

    return res;
}

bool mceltest_index_query_integration(void)
{
    mcel_query_filter filter = { 0U };
    mcel_query_result result_indexed = { 0U };
    mcel_query_result result_scan = { 0U };
    mcel_index idx_seq = { 0U };
    mcel_index idx_type = { 0U };
    mcel_record_header* headers[50U] = { 0U };
    const void* header_ptrs[50U] = { 0U };
    uint8_t searchkey[8U] = { 0U };
    bool res;

    res = false;

    /* create test records */
    create_test_records(headers, 50U);

    for (size_t i = 0U; i < 50U; ++i)
    {
        header_ptrs[i] = headers[i];
    }

    /* build sequence index */
    if (mcel_index_create(&idx_seq, 0U, mcel_index_type_primary) == true)
    {
        if (mcel_index_rebuild(&idx_seq, header_ptrs, NULL, NULL, 50U, test_key_extractor_sequence) == true)
        {
            /* build type index */
            if (mcel_index_create(&idx_type, 0U, mcel_index_type_secondary) == true)
            {
                if (mcel_index_rebuild(&idx_type, header_ptrs, NULL, NULL, 50U, test_key_extractor_type) == true)
                {
                    res = true;

                    /* query by sequence using index vs scan */
                    mcel_query_filter_init(&filter);
                    qsc_intutils_be64to8(searchkey, 25U);
                    filter.searchkey = searchkey;
                    filter.searchkeylen = 8U;

                    /* with index */
                    if (mcel_query_execute(&result_indexed, header_ptrs, NULL, NULL, 50U, &filter, &idx_seq) == true)
                    {
                        /* without index (scan) */
                        mcel_query_filter_init(&filter);
                        filter.afterts = headers[24U]->timestamp;
                        filter.beforets = headers[26U]->timestamp;

                        if (mcel_query_execute(&result_scan, header_ptrs, NULL, NULL, 50U, &filter, NULL) == true)
                        {
                            /* both should return record 25 */
                            res = (result_indexed.count == 1U && result_scan.count == 1U);

                            if (res == true)
                            {
                                res = (result_indexed.recpositions[0U] == 25U && result_scan.recpositions[0] == 25U);
                            }

                            mcel_query_result_dispose(&result_scan);
                        }
                        else
                        {
                            res = false;
                        }

                        mcel_query_result_dispose(&result_indexed);
                    }
                    else
                    {
                        res = false;
                    }
                }

                mcel_index_dispose(&idx_type);
            }
            else
            {
                res = false;
            }
        }

        mcel_index_dispose(&idx_seq);
    }

    free_test_records(headers, 50U);

    return res;
}

bool mceltest_proof_end_to_end(void)
{
    mcel_merkle_proof proofs[3U];
    uint8_t record_commits[20U * MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t merkle_root[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t serialized[3U][MCEL_PROOF_MAX_SERIALIZED_SIZE] = { 0U };
    size_t written[3U] = { 0U };
    bool res;

    res = false;

    /* create ledger with 20 records */
    for (size_t i = 0U; i < 20U; ++i)
    {
        for (size_t j = 0U; j < MCEL_BLOCK_HASH_SIZE; ++j)
        {
            record_commits[(i * MCEL_BLOCK_HASH_SIZE) + j] = (uint8_t)(0xB0U + (uint8_t)i);
        }
    }

    /* compute root */
    if (mcel_merkle_root(merkle_root, record_commits, 20U) == true)
    {
        res = true;

        /* generate proofs for records at positions 3, 10, 17 */
        for (size_t i = 0U; i < 3U && res == true; ++i)
        {
            uint64_t pos;

            pos = (i == 0U) ? 3U : ((i == 1U) ? 10U : 17U);

            if (mcel_proof_generate(&proofs[i], record_commits, 20U, pos, merkle_root) == false)
            {
                res = false;
            }
        }

        /* serialize all proofs */
        for (size_t i = 0U; i < 3U && res == true; ++i)
        {
            if (mcel_proof_serialize(serialized[i], sizeof(serialized[i]), &proofs[i], &written[i]) == false)
            {
                res = false;
            }
        }

        /* dispose original proofs */
        for (size_t i = 0; i < 3U; ++i)
        {
            mcel_proof_dispose(&proofs[i]);
        }

        /* deserialize and verify all proofs */
        for (size_t i = 0U; i < 3U && res == true; ++i)
        {
            if (mcel_proof_deserialize(&proofs[i], serialized[i], written[i]) == true)
            {
                if (mcel_proof_verify(&proofs[i], merkle_root, 20U) == false)
                {
                    res = false;
                }
            }
            else
            {
                res = false;
            }
        }

        /* verify proof for record 3 fails with wrong record hash */
        if (res == true)
        {
            uint8_t wronghash[MCEL_BLOCK_HASH_SIZE] = { 0U };

            qsc_memutils_copy(wronghash, proofs[0U].recordhash, MCEL_BLOCK_HASH_SIZE);
            wronghash[0U] ^= 0x01U;
            qsc_memutils_copy(proofs[0U].recordhash, wronghash, MCEL_BLOCK_HASH_SIZE);

            res = (mcel_proof_verify(&proofs[0U], merkle_root, 20U) == false);
        }

        for (size_t i = 0U; i < 3U; ++i)
        {
            mcel_proof_dispose(&proofs[i]);
        }
    }

    return res;
}

bool mceltest_extensions_run(void)
{
    bool res;

    res = true;

    qsc_consoleutils_print_line("");
    qsc_consoleutils_print_line("***Starting MCEL Extensions Test Suite***");

    if (mceltest_index() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the index search test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the index search test.");
        res = false;
    }

    if (mceltest_query() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the query search test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the query search test.");
        res = false;
    }

    if (mceltest_proof() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the proof test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the proof test.");
        res = false;
    }

    if (mceltest_index_query_integration() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the index query integration test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the index query integration test.");
        res = false;
    }

    if (mceltest_proof_end_to_end() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the proof end-to-end test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the proof end-to-end test.");
        res = false;
    }

    return res;
}

bool mceltest_end_to_end(void)
{

    mcel_record_header rhdr = { 0U };
    uint8_t blkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t payload[32U] = { 0U };
    uint8_t pldcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t reccommits[(size_t)MCEL_BLOCK_HASH_SIZE * 5U] = { 0U };
    const size_t reccount = 5U;
    const size_t recindex = 2U;
    bool res;

    res = false;

    /* record commitments deterministically */
    for (size_t i = 0; i < reccount; ++i)
    {
        for (size_t j = 0; j < sizeof(payload); ++j)
        {
            payload[j] = (uint8_t)(0x30U + (uint8_t)i);
        }

        rhdr.keyid[0] = 0xA5U;
        rhdr.sequence = (uint64_t)(100U + i);
        rhdr.timestamp = (uint64_t)(200U + i);
        rhdr.payload_len = (uint32_t)sizeof(payload);
        rhdr.type = (uint32_t)mcel_record_type_event;
        rhdr.flags = (uint8_t)MCEL_RECORD_FLAG_ENCRYPTED;
        rhdr.version = (uint8_t)MCEL_RECORD_VERSION;

        res = mcel_payload_commit(pldcommit, true, payload, sizeof(payload));

        if (res == true)
        {
            res = mcel_record_commit(reccommits + (i * (size_t)MCEL_BLOCK_HASH_SIZE), &rhdr, pldcommit);
        }
    }

    /* seal block; merkle root, block commit, encode block */
    if (res == true)
    {
        mcel_block_header bhdr = { 0U };
        uint8_t blkcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };

        bhdr.keyid[0] = 0xA5U;
        bhdr.block_sequence = 7U;
        bhdr.first_record_seq = 100U;
        bhdr.timestamp = 123456U;
        bhdr.record_count = (uint32_t)reccount;
        bhdr.flags = 0U;
        bhdr.version = (uint8_t)MCEL_BLOCK_VERSION;

        res = mcel_merkle_root(blkroot, reccommits, reccount);

        if (res == true)
        {
            res = mcel_block_commit(blkcommit, &bhdr, blkroot);

            if (res == true)
            {
                /* for small test, stack buffer is fine */
                uint8_t blockbuf[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE] = { 0U };

                res = mcel_block_encode(blockbuf, sizeof(blockbuf), &bhdr, blkroot, blkcommit, reccommits, reccount);
            }
        }
    }

    /* seal checkpoint; commit, sign, encode bundle, verify */
    if (res == true)
    {
        mcel_checkpoint_header chdr = { 0U };
        mcel_checkpoint_header vhdr = { 0U };
        uint8_t bundle[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE] = { 0U };
        uint8_t prevcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
        uint8_t chkcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
        uint8_t sig[MCEL_CHECKPOINT_SIGNED_COMMIT_SIZE] = { 0U };
        uint8_t sigpk[MCEL_ASYMMETRIC_VERIFY_KEY_SIZE] = { 0U };
        uint8_t sigsk[MCEL_ASYMMETRIC_SIGNING_KEY_SIZE] = { 0U };
        uint8_t vblkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
        uint8_t vcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
        uint8_t vprev[MCEL_BLOCK_HASH_SIZE] = { 0U };
        size_t siglen;

        qsc_dilithium_generate_keypair(sigpk, sigsk, qsc_acp_generate);

        chdr.keyid[0] = 0xA5U;
        chdr.chk_sequence = 1U;
        chdr.first_record_seq = 100U;
        chdr.timestamp = 555555U;
        chdr.record_count = (uint32_t)reccount;
        chdr.version = (uint8_t)MCEL_CHECKPOINT_VERSION;
        chdr.flags = 0U;

        res = mcel_checkpoint_commit(chkcommit, &chdr, blkroot, prevcommit);

        if (res == true)
        {
            siglen = 0U;
            res = mcel_checkpoint_sign(sig, &siglen, chkcommit, sigsk, qsc_acp_generate);

            if (res == true)
            {
                res = mcel_checkpoint_bundle_encode(bundle, sizeof(bundle), &chdr, blkroot, prevcommit, sig, siglen);
            }
        }

        /* verify bundle */
        if (res == true)
        {
            qsc_memutils_clear(&vhdr, sizeof(vhdr));

            res = mcel_checkpoint_bundle_verify(vcommit, &vhdr, vblkroot, vprev, bundle, sizeof(bundle), sigpk);

            if (res == true)
            {
                if (qsc_intutils_are_equal8(vcommit, chkcommit, MCEL_BLOCK_HASH_SIZE) == true)
                {
                    if (qsc_intutils_are_equal8(vblkroot, blkroot, MCEL_BLOCK_HASH_SIZE) == true)
                    {
                        res = qsc_intutils_are_equal8(vprev, prevcommit, MCEL_BLOCK_HASH_SIZE);
                    }                    
                }
            }
        }

        /* tampered signature must fail */
        if (res == true)
        {
            uint8_t badbundle[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE];

            qsc_memutils_copy(badbundle, bundle, sizeof(bundle));

            /* flip a bit inside signature area (at end of bundle) */
            badbundle[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE - 1U] ^= 0x01U;
            qsc_memutils_clear(&vhdr, sizeof(vhdr));

            res = mcel_checkpoint_bundle_verify(vcommit, &vhdr, vblkroot, vprev, badbundle, sizeof(badbundle), sigpk) == false;
        }
    }

    /* merkle membership proof and verify */
    if (res == true)
    {
        uint8_t proof[(size_t)MCEL_BLOCK_HASH_SIZE * 8U] = { 0U };
        const size_t prooflen = mcel_merkle_proof_size(reccount);

        if (prooflen != 0U && prooflen <= sizeof(proof))
        {
            res = mcel_merkle_prove_member(proof, prooflen, reccommits, reccount, recindex);

            if (res == true)
            {
                res = mcel_merkle_member_verify(blkroot, reccommits + (recindex * (size_t)MCEL_BLOCK_HASH_SIZE), proof, prooflen, reccount, recindex);

                if (res == true)
                {
                    uint8_t badleaf[MCEL_BLOCK_HASH_SIZE];

                    /* tamper leaf should fail */
                    qsc_memutils_copy(badleaf, reccommits + (recindex * (size_t)MCEL_BLOCK_HASH_SIZE), MCEL_BLOCK_HASH_SIZE);
                    badleaf[0] ^= 0x01U;

                    res = mcel_merkle_member_verify(blkroot, badleaf, proof, prooflen, reccount, recindex) == false;
                }
            }
        }
    }

    return res;
}


typedef struct mceltest_head_store_state
{
    uint8_t head[64U];
    size_t headlen;
} mceltest_head_store_state;

static bool mceltest_store_write(void* context, const uint8_t* loc, size_t loclen, const uint8_t* data, size_t datalen)
{
    (void)context;
    (void)loc;
    (void)loclen;
    (void)data;
    (void)datalen;

    return true;
}

static bool mceltest_store_read(void* context, const uint8_t* loc, size_t loclen, uint8_t* data, size_t datalen, size_t* outread)
{
    const mceltest_head_store_state* st;
    bool res;

    (void)loc;
    (void)loclen;
    res = false;

    if (context != NULL && data != NULL && outread != NULL)
    {
        st = (const mceltest_head_store_state*)context;

        if (datalen >= st->headlen)
        {
            qsc_memutils_copy(data, st->head, st->headlen);
            *outread = st->headlen;
            res = true;
        }
    }

    return res;
}

static bool mceltest_store_append(void* context, const uint8_t* loc, size_t loclen, const uint8_t* data, size_t datalen, uint64_t* outpos)
{
    (void)context;
    (void)loc;
    (void)loclen;
    (void)data;
    (void)datalen;

    if (outpos != NULL)
    {
        *outpos = 0U;
    }

    return true;
}

static bool mceltest_store_size(void* context, const uint8_t* loc, size_t loclen, uint64_t* outlen)
{
    const mceltest_head_store_state* st;
    bool res;

    (void)loc;
    (void)loclen;
    res = false;

    if (context != NULL && outlen != NULL)
    {
        st = (const mceltest_head_store_state*)context;
        *outlen = (uint64_t)st->headlen;
        res = true;
    }

    return res;
}

static bool mceltest_store_flush(void* context, const uint8_t* loc, size_t loclen)
{
    (void)context;
    (void)loc;
    (void)loclen;

    return true;
}

bool mceltest_anchor_regression(void)
{
    mcel_anchor_reference aref = { 0 };
    uint8_t enc[64U] = { 0U };
    uint8_t encx[65U] = { 0U };
    const uint8_t chainid[4U] = { 0x4DU, 0x43U, 0x45U, 0x4CU };
    const uint8_t ref[8U] = { 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U };
    const uint8_t* cidptr;
    const uint8_t* refptr;
    uint16_t cidlen;
    uint16_t reflen;
    uint8_t flags;
    uint8_t type;
    size_t enclen;
    bool res;

    cidptr = NULL;
    refptr = NULL;
    cidlen = 0U;
    reflen = 0U;
    flags = 0U;
    type = 0U;
    res = false;

    enclen = mcel_anchor_reference_encoded_size(sizeof(chainid), sizeof(ref));

    if (enclen == ((size_t)MCEL_ANCHOR_REFERENCE_HEADER_SIZE + sizeof(chainid) + sizeof(ref)))
    {
        aref.version = (uint8_t)MCEL_ANCHOR_REFERENCE_VERSION;
        aref.flags = 0xA5U;
        aref.type = 0x02U;
        aref.reserved = 0U;
        aref.chain_id_len = (uint16_t)sizeof(chainid);
        aref.reference_len = (uint16_t)sizeof(ref);
        aref.chain_id = chainid;
        aref.reference = ref;

        res = mcel_anchor_reference_encode(enc, sizeof(enc), &aref);
    }

    if (res == true)
    {
        res = mcel_anchor_reference_verify(&flags, &type, &cidptr, &cidlen, &refptr, &reflen, enc, enclen);
    }

    if (res == true)
    {
        res = (flags == aref.flags) && (type == aref.type) && (cidlen == aref.chain_id_len) && (reflen == aref.reference_len) &&
            (qsc_intutils_are_equal8(cidptr, chainid, sizeof(chainid)) == true) &&
            (qsc_intutils_are_equal8(refptr, ref, sizeof(ref)) == true);
    }

    if (res == true)
    {
        qsc_memutils_copy(encx, enc, enclen);
        encx[enclen] = 0x99U;
        res = (mcel_anchor_reference_verify(NULL, NULL, NULL, NULL, NULL, NULL, encx, enclen + 1U) == false);
    }

    if (res == true)
    {
        res = (mcel_anchor_reference_encoded_size(0U, sizeof(ref)) == 0U) &&
            (mcel_anchor_reference_encoded_size(sizeof(chainid), 0U) == 0U) &&
            (mcel_anchor_reference_encoded_size(65536U, sizeof(ref)) == 0U) &&
            (mcel_anchor_reference_encoded_size(sizeof(chainid), 65536U) == 0U);
    }

    return res;
}

bool mceltest_policy_regression(void)
{
    mcel_policy policy = { 0 };
    mcel_policy_context ctx = { 0 };
    mcel_record_header rec = { 0 };
    mcel_checkpoint_header chk = { 0 };
    mcel_policy_errors perr;
    bool res;

    qsc_memutils_clear((uint8_t*)&policy, sizeof(policy));
    qsc_memutils_clear((uint8_t*)&ctx, sizeof(ctx));
    qsc_memutils_clear((uint8_t*)&rec, sizeof(rec));
    qsc_memutils_clear((uint8_t*)&chk, sizeof(chk));

    rec.sequence = 9U;
    rec.timestamp = 50U;
    rec.payload_len = 16U;
    rec.type = (uint32_t)mcel_record_type_event;
    rec.flags = (uint8_t)MCEL_RECORD_FLAG_ENCRYPTED;
    rec.version = (uint8_t)MCEL_RECORD_VERSION;
    ctx.last_record_sequence = 10U;
    ctx.last_record_timestamp = 100U;
    policy.require_encryption = 1U;
    policy.enforce_monotonic_seq = 1U;
    policy.enforce_monotonic_time = 1U;
    policy.allowed_record_mask = (1UL << (uint32_t)mcel_record_type_event);

    perr = mcel_policyerr_none;
    res = (mcel_policy_apply(&perr, &policy, &ctx, mcel_policyop_append_record, &rec, NULL) == false && perr == mcel_policyerr_sequence_invalid);


    if (res == true)
    {
        rec.sequence = 11U;
        rec.timestamp = 99U;
        res = (mcel_policy_apply(&perr, &policy, &ctx, mcel_policyop_append_record, &rec, NULL) == false && perr == mcel_policyerr_timestamp_invalid);
    }

    if (res == true)
    {
        rec.sequence = 11U;
        rec.timestamp = 100U;
        rec.flags = 0U;
        res = (mcel_policy_apply(&perr, &policy, &ctx, mcel_policyop_append_record, &rec, NULL) == false && perr == mcel_policyerr_plaintext_denied);
    }

    if (res == true)
    {
        rec.flags = (uint8_t)MCEL_RECORD_FLAG_ENCRYPTED;
        res = (mcel_policy_apply(&perr, &policy, &ctx, (mcel_policy_ops)99U, &rec, &chk) == false && perr == mcel_policyerr_invalid_parameter);
    }

    if (res == true)
    {
        rec.sequence = 11U;
        rec.timestamp = 100U;
        rec.flags = (uint8_t)MCEL_RECORD_FLAG_ENCRYPTED;
        res = (mcel_policy_apply(&perr, &policy, &ctx, mcel_policyop_append_record, &rec, NULL) == true && perr == mcel_policyerr_none);
    }

    return res;
}

bool mceltest_size_regression(void)
{
    mcel_record_header header = { 0 };
    uint8_t payload[MCEL_KEYROTATE_PAYLOAD_FIXED_SIZE + 8U] = { 0U };
    uint8_t keyid[MCEL_CHECKPOINT_KEYID_SIZE] = { 0U };
    uint8_t pubkey[8U] = { 0U };
    size_t bmax;
    size_t reslen;
    bool res;

    bmax = (((size_t)-1) - (size_t)MCEL_BLOCK_ENCODED_FIXED_SIZE) / (size_t)MCEL_BLOCK_HASH_SIZE;
    res = (mcel_block_encoded_size(bmax + 1U) == 0U);

    if (res == true)
    {
        res = (mcel_checkpoint_bundle_encoded_size((size_t)-1) == 0U);
    }

    if (res == true)
    {
        res = (mcel_keyrotate_payload_size((size_t)-1) == 0U);
    }

    if (res == true)
    {
        res = (mcel_keyrotate_record_create(&header, payload, sizeof(payload), 1U, 0U, keyid, pubkey, 65536U) == 0U);
    }

    if (res == true)
    {
        reslen = mcel_keyrotate_record_create(&header, payload, sizeof(payload), 1U, 0U, keyid, pubkey, sizeof(pubkey));
        res = (reslen == (MCEL_KEYROTATE_PAYLOAD_FIXED_SIZE + sizeof(pubkey)) && header.payload_len == (uint32_t)reslen);
    }

    return res;
}

bool mceltest_proof_regression(void)
{
    uint8_t reccommits[(size_t)MCEL_BLOCK_HASH_SIZE * 64U] = { 0U };
    uint8_t root[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t wrongroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t enc[MCEL_PROOF_MAX_SERIALIZED_SIZE + 1U] = { 0U };
    mcel_merkle_proof proof = { 0 };
    mcel_merkle_proof proof2 = { 0 };
    size_t written;
    bool res;

    for (size_t i = 0U; i < 64U; ++i)
    {
        for (size_t j = 0U; j < (size_t)MCEL_BLOCK_HASH_SIZE; ++j)
        {
            reccommits[(i * (size_t)MCEL_BLOCK_HASH_SIZE) + j] = (uint8_t)(i + j + 1U);
        }
    }

    res = true;

    for (size_t count = 2U; count <= 64U && res == true; ++count)
    {
        res = mcel_merkle_root(root, reccommits, count);

        for (size_t pos = 0U; pos < count && res == true; ++pos)
        {
            qsc_memutils_clear((uint8_t*)&proof, sizeof(proof));
            res = mcel_proof_generate(&proof, reccommits, count, (uint64_t)pos, root);

            if (res == true)
            {
                res = mcel_proof_verify(&proof, root, (uint64_t)count);
            }

            if (res == true && count == 7U && pos == 3U)
            {
                qsc_memutils_copy(wrongroot, root, sizeof(wrongroot));
                wrongroot[0U] ^= 0x01U;
                res = (mcel_proof_verify(&proof, wrongroot, (uint64_t)count) == false);
            }

            if (res == true && count == 9U && pos == 4U)
            {
                written = 0U;
                res = mcel_proof_serialize(enc, sizeof(enc), &proof, &written);

                if (res == true)
                {
                    qsc_memutils_clear((uint8_t*)&proof2, sizeof(proof2));
                    res = mcel_proof_deserialize(&proof2, enc, written);

                    if (res == true)
                    {
                        res = mcel_proof_verify(&proof2, root, (uint64_t)count);
                        mcel_proof_dispose(&proof2);
                    }
                }

                if (res == true)
                {
                    enc[written] = 0x44U;
                    qsc_memutils_clear((uint8_t*)&proof2, sizeof(proof2));
                    res = (mcel_proof_deserialize(&proof2, enc, written + 1U) == false);
                    mcel_proof_dispose(&proof2);
                }
            }

            mcel_proof_dispose(&proof);
        }
    }

    return res;
}

bool mceltest_encryption_regression(void)
{
    uint8_t key[MCEL_RCS256_KEY_SIZE] = { 0U };
    uint8_t nonce[MCEL_RCS_NONCE_SIZE] = { 0U };
    uint8_t plaintext[32U] = { 0U };
    uint8_t ciphertext[64U] = { 0U };
    bool res;

    res = mcel_record_encrypt_payload(ciphertext, plaintext, sizeof(plaintext), NULL, 0U, key, nonce);

    return res;
}

bool mceltest_ledger_recovery_regression(void)
{
    mceltest_head_store_state hstate = { 0 };
    mcel_store_callbacks store = { 0 };
    mcel_ledger_state ledger = { 0 };
    uint8_t headbuf[64U] = { 0U };
    uint8_t nsid[4U] = { 0x4DU, 0x43U, 0x45U, 0x4CU };
    uint8_t pubkey[MCEL_ASYMMETRIC_VERIFY_KEY_SIZE] = { 0U };
    bool res;

    for (size_t i = 0U; i < sizeof(hstate.head); ++i)
    {
        hstate.head[i] = (uint8_t)(0xA0U + i);
    }

    hstate.headlen = 16U;
    store.context = &hstate;
    store.write = mceltest_store_write;
    store.read = mceltest_store_read;
    store.append = mceltest_store_append;
    store.size = mceltest_store_size;
    store.flush = mceltest_store_flush;

    res = (mcel_ledger_initialize(&ledger, &store, nsid, sizeof(nsid), pubkey, headbuf, sizeof(headbuf)) == false);

    if (res == true)
    {
        hstate.headlen = 0U;
        qsc_memutils_clear((uint8_t*)&ledger, sizeof(ledger));
        res = mcel_ledger_initialize(&ledger, &store, nsid, sizeof(nsid), pubkey, headbuf, sizeof(headbuf));
    }

    return res;
}


static void mceltest_fill_commitments(uint8_t* leaves, size_t count, uint8_t seed)
{
    for (size_t i = 0U; i < count; ++i)
    {
        for (size_t j = 0U; j < (size_t)MCEL_BLOCK_HASH_SIZE; ++j)
        {
            leaves[(i * (size_t)MCEL_BLOCK_HASH_SIZE) + j] = (uint8_t)(seed + (uint8_t)(i * 3U) + (uint8_t)j);
        }
    }
}

static bool mceltest_consistency_case(const uint8_t* leaves, size_t first, size_t second)
{
    uint8_t firstroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t secondroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t proof[(size_t)MCEL_BLOCK_HASH_SIZE * 16U] = { 0U };
    size_t maxproof;
    size_t goodlen;
    bool res;

    goodlen = 0U;
    maxproof = 0U;
    res = mcel_merkle_root(firstroot, leaves, first);

    if (res == true)
    {
        res = mcel_merkle_root(secondroot, leaves, second);
    }

    if (res == true)
    {
        maxproof = mcel_merkle_consistency_proof_size(first, second);

        if (maxproof > sizeof(proof))
        {
            res = false;
        }
        else
        {
            qsc_memutils_clear(proof, sizeof(proof));
            res = mcel_checkpoint_prove_consistency(proof, maxproof, leaves, first, second);
        }
    }

    if (res == true)
    {
        if (first == second)
        {
            res = mcel_checkpoint_consistency_verify(firstroot, secondroot, first, second, proof, goodlen);
        }
        else
        {
            res = false;

            for (size_t prooflen = (size_t)MCEL_BLOCK_HASH_SIZE; prooflen <= maxproof; prooflen += (size_t)MCEL_BLOCK_HASH_SIZE)
            {
                if (mcel_checkpoint_consistency_verify(firstroot, secondroot, first, second, proof, prooflen) == true)
                {
                    goodlen = prooflen;
                    res = true;
                    break;
                }
            }
        }
    }

    if (res == true && first < second && goodlen != 0U)
    {
        proof[0U] ^= 0x01U;
        res = (mcel_checkpoint_consistency_verify(firstroot, secondroot, first, second, proof, goodlen) == false);
        proof[0U] ^= 0x01U;
    }

    if (res == true && first < second && goodlen != 0U)
    {
        uint8_t badroot[MCEL_BLOCK_HASH_SIZE] = { 0U };

        qsc_memutils_copy(badroot, firstroot, sizeof(badroot));
        badroot[0U] ^= 0x80U;
        res = (mcel_checkpoint_consistency_verify(badroot, secondroot, first, second, proof, goodlen) == false);
    }

    if (res == true && first < second && goodlen != 0U)
    {
        uint8_t badroot[MCEL_BLOCK_HASH_SIZE] = { 0U };

        qsc_memutils_copy(badroot, secondroot, sizeof(badroot));
        badroot[0U] ^= 0x40U;
        res = (mcel_checkpoint_consistency_verify(firstroot, badroot, first, second, proof, goodlen) == false);
    }

    return res;
}

bool mceltest_consistency_regression(void)
{
    uint8_t leaves[(size_t)MCEL_BLOCK_HASH_SIZE * 8U] = { 0U };
    bool res;

    mceltest_fill_commitments(leaves, 8U, 0x21U);

    res = mceltest_consistency_case(leaves, 1U, 1U);

    if (res == true)
    {
        res = mceltest_consistency_case(leaves, 1U, 2U);
    }

    if (res == true)
    {
        res = mceltest_consistency_case(leaves, 2U, 3U);
    }

    if (res == true)
    {
        res = mceltest_consistency_case(leaves, 3U, 7U);
    }

    if (res == true)
    {
        res = mceltest_consistency_case(leaves, 4U, 8U);
    }

    return res;
}

static bool mceltest_make_checkpoint_bundle(uint8_t* bundle, size_t* bundlen, uint8_t* chkcommit, mcel_checkpoint_header* header,
    const uint8_t* blkroot, const uint8_t* prevcommit, const uint8_t* sigkey)
{
    uint8_t sigcommit[MCEL_CHECKPOINT_SIGNED_COMMIT_SIZE] = { 0U };
    size_t siglen;
    bool res;

    siglen = 0U;
    res = mcel_checkpoint_commit(chkcommit, header, blkroot, prevcommit);

    if (res == true)
    {
        res = mcel_checkpoint_sign(sigcommit, &siglen, chkcommit, sigkey, qsc_acp_generate);
    }

    if (res == true)
    {
        *bundlen = mcel_checkpoint_bundle_encoded_size(siglen);
        res = (*bundlen != 0U && *bundlen <= MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE);
    }

    if (res == true)
    {
        res = mcel_checkpoint_bundle_encode(bundle, *bundlen, header, blkroot, prevcommit, sigcommit, siglen);
    }

    return res;
}

bool mceltest_checkpoint_audit_regression(void)
{
    mcel_checkpoint_header h0 = { 0U };
    mcel_checkpoint_header h1 = { 0U };
    mcel_checkpoint_header badh = { 0U };
    mcel_checkpoint_audit_item items[2U];
    uint8_t blkroot0[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t blkroot1[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t bundle0[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE] = { 0U };
    uint8_t bundle1[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE] = { 0U };
    uint8_t badbundle[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE] = { 0U };
    uint8_t chk0[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t chk1[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t head[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t prevzero[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t sigpk[MCEL_ASYMMETRIC_VERIFY_KEY_SIZE] = { 0U };
    uint8_t sigsk[MCEL_ASYMMETRIC_SIGNING_KEY_SIZE] = { 0U };
    size_t blen0;
    size_t blen1;
    bool res;

    mceltest_fill_commitments(blkroot0, 1U, 0x31U);
    mceltest_fill_commitments(blkroot1, 1U, 0x41U);
    qsc_dilithium_generate_keypair(sigpk, sigsk, qsc_acp_generate);

    h0.chk_sequence = 1U;
    h0.first_record_seq = 1U;
    h0.timestamp = 1000U;
    h0.record_count = 3U;
    h0.version = (uint8_t)MCEL_CHECKPOINT_VERSION;
    h0.keyid[0U] = 0xA1U;

    h1.chk_sequence = 2U;
    h1.first_record_seq = 4U;
    h1.timestamp = 1100U;
    h1.record_count = 2U;
    h1.version = (uint8_t)MCEL_CHECKPOINT_VERSION;
    h1.keyid[0U] = 0xA1U;

    blen0 = 0U;
    blen1 = 0U;
    res = mceltest_make_checkpoint_bundle(bundle0, &blen0, chk0, &h0, blkroot0, prevzero, sigsk);

    if (res == true)
    {
        res = mceltest_make_checkpoint_bundle(bundle1, &blen1, chk1, &h1, blkroot1, chk0, sigsk);
    }

    if (res == true)
    {
        items[0U].bundle = bundle0;
        items[0U].bundlelen = blen0;
        items[1U].bundle = bundle1;
        items[1U].bundlelen = blen1;
        res = mcel_checkpoint_audit_path_verify(head, items, 2U, sigpk);
    }

    if (res == true)
    {
        res = (qsc_intutils_are_equal8(head, chk1, MCEL_BLOCK_HASH_SIZE) == true);
    }

    if (res == true)
    {
        uint8_t badprev[MCEL_BLOCK_HASH_SIZE] = { 0U };

        qsc_memutils_copy(badprev, chk0, sizeof(badprev));
        badprev[0U] ^= 0x01U;
        res = (mcel_checkpoint_chain_link_verify(chk0, badprev, &h0, &h1) == false);
    }

    if (res == true)
    {
        badh = h1;
        badh.chk_sequence = h0.chk_sequence;
        res = (mcel_checkpoint_chain_link_verify(chk0, chk0, &h0, &badh) == false);
    }

    if (res == true)
    {
        badh = h1;
        badh.timestamp = h0.timestamp - 1U;
        res = (mcel_checkpoint_chain_link_verify(chk0, chk0, &h0, &badh) == false);
    }

    if (res == true)
    {
        badh = h1;
        badh.first_record_seq = h0.first_record_seq - 1U;
        res = (mcel_checkpoint_chain_link_verify(chk0, chk0, &h0, &badh) == false);
    }

    if (res == true)
    {
        qsc_memutils_copy(badbundle, bundle1, blen1);
        badbundle[blen1 - 1U] ^= 0x01U;
        items[1U].bundle = badbundle;
        items[1U].bundlelen = blen1;
        res = (mcel_checkpoint_audit_path_verify(head, items, 2U, sigpk) == false);
    }

    return res;
}

bool mceltest_commitment_vectors(void)
{
    static const uint8_t exp_ptxt[MCEL_BLOCK_HASH_SIZE] = { 0x4BU, 0xC1U, 0x50U, 0xA0U, 0xB2U, 0xD5U, 0xABU, 0x42U, 0x37U, 0xF9U, 0x6CU, 0x8FU, 0x9AU, 0xA9U, 0x89U, 0x67U, 0x61U, 0x4BU, 0x32U, 0x67U, 0xA7U, 0xAEU, 0x5AU, 0xEAU, 0x8CU, 0x85U, 0xDEU, 0xD5U, 0x36U, 0xC5U, 0x68U, 0x37U };
    static const uint8_t exp_ctxt[MCEL_BLOCK_HASH_SIZE] = { 0x4EU, 0x69U, 0x66U, 0x82U, 0x28U, 0x77U, 0x36U, 0xEAU, 0x34U, 0x90U, 0x84U, 0x57U, 0xE8U, 0x8EU, 0x13U, 0xD2U, 0x22U, 0x45U, 0xF6U, 0x43U, 0xCDU, 0x39U, 0x4FU, 0x99U, 0xFEU, 0xEEU, 0x3DU, 0x05U, 0x2EU, 0xCAU, 0x99U, 0x39U };
    static const uint8_t exp_rec[MCEL_BLOCK_HASH_SIZE] = { 0x00U, 0x1FU, 0xA9U, 0x35U, 0xD5U, 0x77U, 0x14U, 0x9EU, 0xB0U, 0x27U, 0x14U, 0xF4U, 0xF3U, 0x4BU, 0xFCU, 0xF6U, 0xACU, 0xFEU, 0x5EU, 0xC9U, 0x4FU, 0x59U, 0xF7U, 0x4CU, 0x4DU, 0xCEU, 0x2EU, 0xFAU, 0x4DU, 0xF3U, 0xEEU, 0xEAU };
    static const uint8_t exp_blkroot[MCEL_BLOCK_HASH_SIZE] = { 0x3DU, 0x47U, 0x50U, 0x34U, 0x11U, 0xCAU, 0x16U, 0xCCU, 0x2CU, 0x92U, 0xF4U, 0x85U, 0x95U, 0xEAU, 0xC1U, 0x78U, 0x58U, 0xE1U, 0x90U, 0x6BU, 0x5DU, 0x5DU, 0x58U, 0xEFU, 0x54U, 0x62U, 0xAFU, 0xD7U, 0x3FU, 0x45U, 0x83U, 0xE3U };
    static const uint8_t exp_blkcommit[MCEL_BLOCK_HASH_SIZE] = { 0xC6U, 0xB7U, 0xA0U, 0x41U, 0xB2U, 0xE2U, 0xD6U, 0xD1U, 0x63U, 0xA4U, 0x6CU, 0xF4U, 0xC9U, 0xC4U, 0xD4U, 0x6DU, 0x43U, 0xCDU, 0x49U, 0xCBU, 0x24U, 0xE2U, 0x0BU, 0x53U, 0x64U, 0x21U, 0x91U, 0xE6U, 0xA3U, 0x24U, 0x22U, 0xD1U };
    static const uint8_t exp_chk[MCEL_BLOCK_HASH_SIZE] = { 0x07U, 0xC5U, 0x77U, 0xCDU, 0x8DU, 0xDEU, 0x8CU, 0x66U, 0x3DU, 0x2CU, 0x60U, 0x0CU, 0xB8U, 0x1DU, 0x19U, 0x06U, 0x49U, 0x48U, 0x20U, 0xECU, 0xC3U, 0x1CU, 0xBAU, 0x33U, 0x31U, 0x86U, 0xF1U, 0x55U, 0x33U, 0x5DU, 0x53U, 0xAAU };
    static const uint8_t exp_anchor[MCEL_BLOCK_HASH_SIZE] = { 0x60U, 0x2EU, 0x05U, 0x68U, 0x7CU, 0xCEU, 0x36U, 0xC9U, 0x0CU, 0x62U, 0x33U, 0x14U, 0x44U, 0x8DU, 0x26U, 0xE6U, 0xEBU, 0xA1U, 0x0DU, 0x8AU, 0x93U, 0x56U, 0xBDU, 0xF4U, 0xECU, 0x5BU, 0x9BU, 0x2EU, 0xF0U, 0x5AU, 0x26U, 0x45U };
    uint8_t payload[16U] = { 0U };
    uint8_t reccommits[(size_t)MCEL_BLOCK_HASH_SIZE * 3U] = { 0U };
    uint8_t ptxt[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t ctxt[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t rechash[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t blkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t blkcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t chkcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t anchorcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t arefbuf[64U] = { 0U };
    uint8_t prev[MCEL_BLOCK_HASH_SIZE] = { 0U };
    const uint8_t chainid[4U] = { 0x4DU, 0x43U, 0x45U, 0x4CU };
    const uint8_t ref[8U] = { 0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U };
    mcel_record_header rh = { 0U };
    mcel_block_header bh = { 0U };
    mcel_checkpoint_header ch = { 0U };
    mcel_anchor_reference ar;
    size_t areflen;
    bool res;

    for (size_t i = 0U; i < sizeof(payload); ++i)
    {
        payload[i] = (uint8_t)i;
    }

    for (size_t i = 0U; i < sizeof(reccommits); ++i)
    {
        reccommits[i] = (uint8_t)(0x30U + i);
    }

    areflen = 0U;
    rh.sequence = 1U;
    rh.timestamp = 2U;
    rh.payload_len = (uint32_t)sizeof(payload);
    rh.type = (uint32_t)mcel_record_type_event;
    rh.version = (uint8_t)MCEL_RECORD_VERSION;
    rh.keyid[0U] = 0xA5U;

    bh.block_sequence = 7U;
    bh.first_record_seq = 100U;
    bh.timestamp = 123456U;
    bh.record_count = 3U;
    bh.version = (uint8_t)MCEL_BLOCK_VERSION;
    bh.keyid[0U] = 0xB6U;

    ch.chk_sequence = 1U;
    ch.first_record_seq = 100U;
    ch.timestamp = 123500U;
    ch.record_count = 3U;
    ch.version = (uint8_t)MCEL_CHECKPOINT_VERSION;
    ch.keyid[0U] = 0xC7U;

    ar.version = (uint8_t)MCEL_ANCHOR_REFERENCE_VERSION;
    ar.flags = 0xAAU;
    ar.type = 0x02U;
    ar.reserved = 0U;
    ar.chain_id_len = (uint16_t)sizeof(chainid);
    ar.reference_len = (uint16_t)sizeof(ref);
    ar.chain_id = chainid;
    ar.reference = ref;

    res = mcel_payload_commit(ptxt, false, payload, sizeof(payload));

    if (res == true)
    {
        res = (qsc_intutils_are_equal8(ptxt, exp_ptxt, MCEL_BLOCK_HASH_SIZE) == true);
    }

    if (res == true)
    {
        res = mcel_payload_commit(ctxt, true, payload, sizeof(payload));
    }

    if (res == true)
    {
        res = (qsc_intutils_are_equal8(ctxt, exp_ctxt, MCEL_BLOCK_HASH_SIZE) == true);
    }

    if (res == true)
    {
        res = mcel_record_commit(rechash, &rh, ptxt);
    }

    if (res == true)
    {
        res = (qsc_intutils_are_equal8(rechash, exp_rec, MCEL_BLOCK_HASH_SIZE) == true);
    }

    if (res == true)
    {
        res = mcel_merkle_root(blkroot, reccommits, 3U);
    }

    if (res == true)
    {
        res = (qsc_intutils_are_equal8(blkroot, exp_blkroot, MCEL_BLOCK_HASH_SIZE) == true);
    }

    if (res == true)
    {
        res = mcel_block_commit(blkcommit, &bh, blkroot);
    }

    if (res == true)
    {
        res = (qsc_intutils_are_equal8(blkcommit, exp_blkcommit, MCEL_BLOCK_HASH_SIZE) == true);
    }

    if (res == true)
    {
        res = mcel_checkpoint_commit(chkcommit, &ch, blkroot, prev);
    }

    if (res == true)
    {
        res = (qsc_intutils_are_equal8(chkcommit, exp_chk, MCEL_BLOCK_HASH_SIZE) == true);
    }

    if (res == true)
    {
        areflen = mcel_anchor_reference_encoded_size(sizeof(chainid), sizeof(ref));
        res = mcel_anchor_reference_encode(arefbuf, sizeof(arefbuf), &ar);
    }

    if (res == true)
    {
        res = mcel_anchor_commit(anchorcommit, chkcommit, arefbuf, areflen);
    }

    if (res == true)
    {
        res = (qsc_intutils_are_equal8(anchorcommit, exp_anchor, MCEL_BLOCK_HASH_SIZE) == true);
    }

    return res;
}

bool mceltest_domain_separation_regression(void)
{
    static const mcel_domain_types domains[] = {
        mcel_domain_block,
        mcel_domain_checkpoint,
        mcel_domain_ciphertext,
        mcel_domain_node,
        mcel_domain_plaintext,
        mcel_domain_record,
        mcel_domain_anchor
    };
    uint8_t digests[7U][MCEL_BLOCK_HASH_SIZE] = { 0U };
    const uint8_t msg[8U] = { 0x4DU, 0x43U, 0x45U, 0x4CU, 0x2DU, 0x54U, 0x45U, 0x53U };
    bool res;

    qsc_memutils_clear((uint8_t*)digests, sizeof(digests));
    res = true;

    for (size_t i = 0U; i < (sizeof(domains) / sizeof(domains[0U])) && res == true; ++i)
    {
        res = mcel_domain_hash_message(digests[i], domains[i], msg, sizeof(msg));
    }

    for (size_t i = 0U; i < (sizeof(domains) / sizeof(domains[0U])) && res == true; ++i)
    {
        for (size_t j = i + 1U; j < (sizeof(domains) / sizeof(domains[0U])) && res == true; ++j)
        {
            res = (qsc_intutils_are_equal8(digests[i], digests[j], MCEL_BLOCK_HASH_SIZE) == false);
        }
    }

    return res;
}

static bool mceltest_store_read_fail(void* context, const uint8_t* loc, size_t loclen, uint8_t* data, size_t datalen, size_t* outread)
{
    (void)context;
    (void)loc;
    (void)loclen;
    (void)data;
    (void)datalen;

    if (outread != NULL)
    {
        *outread = 0U;
    }

    return false;
}

static bool mceltest_store_append_fail(void* context, const uint8_t* loc, size_t loclen, const uint8_t* data, size_t datalen, uint64_t* outpos)
{
    (void)context;
    (void)loc;
    (void)loclen;
    (void)data;
    (void)datalen;

    if (outpos != NULL)
    {
        *outpos = 0U;
    }

    return false;
}

static bool mceltest_store_size_fail(void* context, const uint8_t* loc, size_t loclen, uint64_t* outlen)
{
    (void)context;
    (void)loc;
    (void)loclen;

    if (outlen != NULL)
    {
        *outlen = 0U;
    }

    return false;
}

static bool mceltest_store_read_short(void* context, const uint8_t* loc, size_t loclen, uint8_t* data, size_t datalen, size_t* outread)
{
    bool res;

    res = mceltest_store_read(context, loc, loclen, data, datalen, outread);

    if (res == true && outread != NULL && *outread != 0U)
    {
        --(*outread);
    }

    return res;
}

bool mceltest_storage_callback_regression(void)
{
    mceltest_head_store_state hstate = { 0 };
    mcel_store_callbacks input = { 0 };
    mcel_store_callbacks output = { 0 };
    mcel_ledger_state ledger = { 0 };
    uint8_t nsid[4U] = { 0x4DU, 0x43U, 0x45U, 0x4CU };
    uint8_t pubkey[MCEL_ASYMMETRIC_VERIFY_KEY_SIZE] = { 0U };
    uint8_t headbuf[64U] = { 0U };
    bool res;

    input.context = &hstate;
    input.write = mceltest_store_write;
    input.read = mceltest_store_read;
    input.append = mceltest_store_append;
    input.size = mceltest_store_size;
    input.flush = mceltest_store_flush;

    res = mcel_store_callbacks_initialize(&output, &input, &hstate);

    if (res == true)
    {
        res = (output.context == &hstate && output.write == input.write && output.read == input.read && output.append == input.append && output.size == input.size);
    }

    if (res == true)
    {
        input.size = mceltest_store_size_fail;
        res = mcel_ledger_initialize(&ledger, &input, nsid, sizeof(nsid), pubkey, headbuf, sizeof(headbuf));
    }

    if (res == true)
    {
        qsc_memutils_clear((uint8_t*)&ledger, sizeof(ledger));
        hstate.headlen = 16U;
        input.size = mceltest_store_size;
        input.read = mceltest_store_read_fail;
        res = (mcel_ledger_initialize(&ledger, &input, nsid, sizeof(nsid), pubkey, headbuf, sizeof(headbuf)) == false);
    }

    if (res == true)
    {
        qsc_memutils_clear((uint8_t*)&ledger, sizeof(ledger));
        input.read = mceltest_store_read_short;
        res = (mcel_ledger_initialize(&ledger, &input, nsid, sizeof(nsid), pubkey, headbuf, sizeof(headbuf)) == false);
    }

    if (res == true)
    {
        uint8_t reccommits[(size_t)MCEL_BLOCK_HASH_SIZE * 1U] = { 0U };
        uint8_t blkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
        uint8_t blkcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
        uint8_t blockbuf[MCEL_BLOCK_ENCODED_FIXED_SIZE + MCEL_BLOCK_HASH_SIZE] = { 0U };
        mcel_block_header bh = { 0U };

        qsc_memutils_clear((uint8_t*)&ledger, sizeof(ledger));
        hstate.headlen = 0U;
        input.read = mceltest_store_read;
        input.append = mceltest_store_append_fail;
        res = mcel_ledger_initialize(&ledger, &input, nsid, sizeof(nsid), pubkey, headbuf, sizeof(headbuf));

        if (res == true)
        {
            mceltest_fill_commitments(reccommits, 1U, 0x55U);
            bh.block_sequence = 1U;
            bh.first_record_seq = 1U;
            bh.timestamp = 1U;
            bh.record_count = 1U;
            bh.version = (uint8_t)MCEL_BLOCK_VERSION;
            res = (mcel_ledger_seal_block(&ledger, blkroot, blkcommit, &bh, reccommits, 1U, blockbuf, sizeof(blockbuf), NULL) == false);
        }
    }

    return res;
}

bool mceltest_query_index_regression(void)
{
    mcel_record_header* headers[10U] = { 0U };
    const void* header_ptrs[10U] = { 0U };
    uint8_t payloads[10U][4U];
    uint8_t* payload_ptrs[10U] = { 0U };
    const uint8_t* cpayload_ptrs[10U] = { 0U };
    size_t payloadlens[10U] = { 0U };
    mcel_index idx = { 0 };
    mcel_query_filter filter = { 0 };
    mcel_query_result result = { 0 };
    mcel_query_result scanres = { 0 };
    size_t count;
    bool res;

    create_test_records(headers, 10U);
    res = true;

    for (size_t i = 0U; i < 10U && res == true; ++i)
    {
        if (headers[i] == NULL)
        {
            res = false;
        }
        else
        {
            headers[i]->type = (uint32_t)((i % 2U) + 1U);
            headers[i]->flags = (uint8_t)(i % 4U);
            headers[i]->timestamp = 1000U + (uint64_t)(i * 10U);
            header_ptrs[i] = headers[i];
            payloads[i][0U] = (uint8_t)i;
            payloads[i][1U] = (uint8_t)(i + 1U);
            payloads[i][2U] = (uint8_t)(i + 2U);
            payloads[i][3U] = (uint8_t)(i + 3U);
            payload_ptrs[i] = payloads[i];
            cpayload_ptrs[i] = payloads[i];
            payloadlens[i] = sizeof(payloads[i]);
        }
    }

    if (res == true)
    {
        mcel_query_filter_init(&filter);
        filter.requiredtype = 1U;
        filter.reverseorder = 1U;
        filter.offset = 1U;
        filter.limit = 2U;
        res = mcel_query_execute(&result, header_ptrs, payload_ptrs, payloadlens, 10U, &filter, NULL);
    }

    if (res == true)
    {
        res = (result.count == 2U && result.recpositions[0U] == 6U && result.recpositions[1U] == 4U && result.hasmore != 0U);
    }

    if (res == true)
    {
        count = 0U;
        res = mcel_query_count(&count, header_ptrs, 10U, &filter);

        if (res == true)
        {
            res = (count == 5U);
        }
    }

    mcel_query_result_dispose(&result);

    if (res == true)
    {
        mcel_query_filter_init(&filter);
        filter.requiredflags = 0x01U;
        filter.excludedflags = 0x02U;
        res = mcel_query_execute(&result, header_ptrs, payload_ptrs, payloadlens, 10U, &filter, NULL);
    }

    if (res == true)
    {
        res = (result.count == 3U);
    }

    mcel_query_result_dispose(&result);

    if (res == true)
    {
        res = mcel_index_create(&idx, 8U, mcel_index_type_secondary);
    }

    if (res == true)
    {
        res = mcel_index_rebuild(&idx, header_ptrs, cpayload_ptrs, payloadlens, 10U, test_key_extractor_type);
    }

    if (res == true)
    {
        uint8_t key[4U] = { 0U };

        qsc_intutils_be32to8(key, 1U);
        mcel_query_filter_init(&filter);
        filter.searchkey = key;
        filter.searchkeylen = sizeof(key);
        filter.requiredtype = 1U;
        res = mcel_query_execute(&result, header_ptrs, payload_ptrs, payloadlens, 10U, &filter, &idx);

        if (res == true)
        {
            res = mcel_query_execute(&scanres, header_ptrs, payload_ptrs, payloadlens, 10U, &filter, NULL);
        }

        if (res == true)
        {
            res = (result.count == scanres.count);

            for (size_t i = 0U; i < result.count && res == true; ++i)
            {
                bool found;

                found = false;

                for (size_t j = 0U; j < scanres.count; ++j)
                {
                    if (result.recpositions[i] == scanres.recpositions[j])
                    {
                        found = true;
                        break;
                    }
                }

                res = found;
            }
        }
    }

    if (res == true)
    {
        uint8_t hash1[MCEL_INDEX_HASH_SIZE] = { 0U };
        uint8_t hash2[MCEL_INDEX_HASH_SIZE] = { 0U };

        res = mcel_index_compute_hash(&idx, hash1);

        if (res == true)
        {
            headers[0U]->type = 3U;
            res = mcel_index_rebuild(&idx, header_ptrs, cpayload_ptrs, payloadlens, 10U, test_key_extractor_type);
        }

        if (res == true)
        {
            res = mcel_index_compute_hash(&idx, hash2);
        }

        if (res == true)
        {
            res = (qsc_intutils_are_equal8(hash1, hash2, MCEL_INDEX_HASH_SIZE) == false);
        }
    }

    mcel_query_result_dispose(&result);
    mcel_query_result_dispose(&scanres);
    mcel_index_dispose(&idx);
    free_test_records(headers, 10U);

    return res;
}

bool mceltest_keyrotate_roundtrip(void)
{
    mcel_record_header header = { 0 };
    uint8_t payload[MCEL_KEYROTATE_PAYLOAD_FIXED_SIZE + 16U] = { 0U };
    uint8_t keyid[MCEL_RECORD_KEYID_SIZE] = { 0U };
    uint8_t pubkey[16U] = { 0U };
    uint64_t seq;
    uint8_t flags;
    uint16_t pklen;
    size_t plen;
    bool res;

    for (size_t i = 0U; i < sizeof(keyid); ++i)
    {
        keyid[i] = (uint8_t)(0x90U + i);
    }

    for (size_t i = 0U; i < sizeof(pubkey); ++i)
    {
        pubkey[i] = (uint8_t)(0x20U + i);
    }

    seq = 77U;
    flags = 0xA5U;
    plen = mcel_keyrotate_record_create(&header, payload, sizeof(payload), seq, flags, keyid, pubkey, sizeof(pubkey));
    res = (plen == (MCEL_KEYROTATE_PAYLOAD_FIXED_SIZE + sizeof(pubkey)));

    if (res == true)
    {
        res = (header.sequence == seq && header.type == (uint32_t)mcel_record_type_key_rotate &&
            header.flags == flags && header.version == (uint8_t)MCEL_RECORD_VERSION && header.payload_len == (uint32_t)plen);
    }

    if (res == true)
    {
        res = (payload[0U] == (uint8_t)MCEL_KEYROTATE_PAYLOAD_VERSION && payload[1U] == flags);
    }

    if (res == true)
    {
        res = (qsc_intutils_are_equal8(payload + (2U * sizeof(uint8_t)), keyid, MCEL_RECORD_KEYID_SIZE) == true);
    }

    if (res == true)
    {
        pklen = qsc_intutils_be8to16(payload + (2U * sizeof(uint8_t)) + MCEL_RECORD_KEYID_SIZE);
        res = (pklen == sizeof(pubkey));
    }

    if (res == true)
    {
        res = (qsc_intutils_are_equal8(payload + MCEL_KEYROTATE_PAYLOAD_FIXED_SIZE, pubkey, sizeof(pubkey)) == true);
    }

    return res;
}

bool mceltest_block_encoding_regression(void)
{
    uint8_t rec1[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t rec3[(size_t)MCEL_BLOCK_HASH_SIZE * 3U] = { 0U };
    uint8_t rec3tampered[(size_t)MCEL_BLOCK_HASH_SIZE * 3U] = { 0U };
    uint8_t root1[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t root3[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t root3b[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t commit3[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t commit3b[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t enc[MCEL_BLOCK_ENCODED_FIXED_SIZE + ((size_t)MCEL_BLOCK_HASH_SIZE * 3U)] = { 0U };
    mcel_block_header bh = { 0U };
    size_t encsize;
    bool res;

    mceltest_fill_commitments(rec1, 1U, 0x61U);
    mceltest_fill_commitments(rec3, 3U, 0x71U);
    qsc_memutils_copy(rec3tampered, rec3, sizeof(rec3tampered));
    rec3tampered[0U] ^= 0x01U;

    bh.block_sequence = 5U;
    bh.first_record_seq = 9U;
    bh.timestamp = 555U;
    bh.record_count = 3U;
    bh.version = (uint8_t)MCEL_BLOCK_VERSION;
    bh.keyid[0U] = 0xAAU;

    res = mcel_block_seal(root1, commit3, &bh, rec1, 1U);

    if (res == true)
    {
        res = mcel_block_seal(root3, commit3, &bh, rec3, 3U);
    }

    if (res == true)
    {
        res = mcel_block_seal(root3b, commit3b, &bh, rec3tampered, 3U);
    }

    if (res == true)
    {
        res = (qsc_intutils_are_equal8(root3, root3b, MCEL_BLOCK_HASH_SIZE) == false &&
            qsc_intutils_are_equal8(commit3, commit3b, MCEL_BLOCK_HASH_SIZE) == false);
    }

    if (res == true)
    {
        encsize = mcel_block_encoded_size(3U);
        res = (encsize == sizeof(enc));
    }

    if (res == true)
    {
        res = mcel_block_encode(enc, sizeof(enc), &bh, root3, commit3, rec3, 3U);
    }

    if (res == true)
    {
        enc[(size_t)MCEL_BLOCK_HEADER_ENCODED_SIZE + MCEL_BLOCK_HASH_SIZE] ^= 0x01U;
        res = (qsc_intutils_are_equal8(enc + (size_t)MCEL_BLOCK_HEADER_ENCODED_SIZE + MCEL_BLOCK_HASH_SIZE, commit3, MCEL_BLOCK_HASH_SIZE) == false);
    }


    return res;
}

bool mceltest_functions_run(void)
{
    bool res;

    res = true;

    qsc_consoleutils_print_line("***Starting MCEL Extensions Test Suite***");

    if (mceltest_index() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the index test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the index test.");
        res = false;
    }

    if (mceltest_query() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the query test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the query test.");
        res = false;
    }

    if (mceltest_proof() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the proof test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the proof test.");
        res = false;
    }

    if (mceltest_index_query_integration() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the index query test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the index query integration test.");
        res = false;
    }

    if (mceltest_proof_end_to_end() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the proof end-to-end test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the proof end-to-end test.");
        res = false;
    }

    if (mceltest_extensions_run() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the indexing functions self test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the indexing functions self test.");
        res = false;
    }

    if (mceltest_hash() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the hash function self test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the hash function self test.");
        res = false;
    }

    if (mceltest_merkle() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the merkle function self test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the merkle function self test.");
        res = false;
    }

    if (mceltest_record_commit() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the record commit test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the record commit test.");
        res = false;
    }

    if (mceltest_block_seal() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the block seal test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the block seal test.");
        res = false;
    }

    if (mceltest_checkpoint_seal_verify() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the checkpoint seal test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the checkpoint seal test.");
        res = false;
    }



    if (mceltest_anchor_regression() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the anchor regression test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the anchor regression test.");
        res = false;
    }

    if (mceltest_policy_regression() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the policy regression test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the policy regression test.");
        res = false;
    }

    if (mceltest_size_regression() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the size regression test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the size regression test.");
        res = false;
    }

    if (mceltest_proof_regression() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the proof regression test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the proof regression test.");
        res = false;
    }

    if (mceltest_encryption_regression() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the encryption regression test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the encryption regression test.");
        res = false;
    }

    if (mceltest_ledger_recovery_regression() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the ledger recovery regression test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the ledger recovery regression test.");
        res = false;
    }

    if (mceltest_consistency_regression() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the consistency proof regression test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the consistency proof regression test.");
        res = false;
    }

    if (mceltest_checkpoint_audit_regression() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the checkpoint audit regression test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the checkpoint audit regression test.");
        res = false;
    }

    if (mceltest_commitment_vectors() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the commitment vector test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the commitment vector test.");
        res = false;
    }

    if (mceltest_domain_separation_regression() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the domain separation regression test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the domain separation regression test.");
        res = false;
    }

    if (mceltest_storage_callback_regression() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the storage callback regression test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the storage callback regression test.");
        res = false;
    }

    if (mceltest_query_index_regression() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the query/index regression test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the query/index regression test.");
        res = false;
    }

    if (mceltest_keyrotate_roundtrip() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the key-rotation round-trip test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the key-rotation round-trip test.");
        res = false;
    }

    if (mceltest_block_encoding_regression() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the block encoding regression test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the block encoding regression test.");
        res = false;
    }

    if (mceltest_end_to_end() == true)
    {
        qsc_consoleutils_print_line("Success! Passed the blockchain end-to-end test.");
    }
    else
    {
        qsc_consoleutils_print_line("Failure! Failed the blockchain end-to-end test.");
        res = false;
    }

    return res;
}


