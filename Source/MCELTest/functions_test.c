#include "functions_test.h"
#include "domain.h"
#include "merkle.h"
#include "mcel.h"
#include "acp.h"
#include "consoleutils.h"
#include "dilithium.h"
#include "intutils.h"
#include "memutils.h"

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
            uint8_t vprev[MCEL_BLOCK_HASH_SIZE] = { 0U };

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


