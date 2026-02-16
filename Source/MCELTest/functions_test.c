#include "functions_test.h"
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


