#include "mcel.h"
#include "domain.h"
#include "merkle.h"
#include "acp.h"
#include "dilithium.h"
#include "intutils.h"
#include "memutils.h"
#include "rcs.h"
#include "sha3.h"
#include "timestamp.h"

static bool checkpoint_subtree_root(uint8_t* output, const uint8_t* leaves, size_t start, size_t count)
{
    uint8_t* level;
    size_t lcount;
    bool res;

    res = false;

    if (output != NULL && leaves != NULL && count > 0U)
    {
        lcount = count;
        level = (uint8_t*)qsc_memutils_malloc(lcount * (size_t)MCEL_BLOCK_HASH_SIZE);

        if (level != NULL)
        {
            qsc_memutils_copy(level, leaves + (start * (size_t)MCEL_BLOCK_HASH_SIZE), lcount * (size_t)MCEL_BLOCK_HASH_SIZE);
            res = true;

            while (lcount > 1U && res == true)
            {
                uint8_t* next;
                size_t ncount;

                ncount = (lcount + 1U) / 2U;
                next = (uint8_t*)qsc_memutils_malloc(ncount * (size_t)MCEL_BLOCK_HASH_SIZE);

                if (next == NULL)
                {
                    res = false;
                    break;
                }

                for (size_t i = 0; i < ncount; ++i)
                {
                    const uint8_t* left;
                    const uint8_t* right;

                    left = level + ((i * 2U) * (size_t)MCEL_BLOCK_HASH_SIZE);

                    if ((i * 2U + 1U) < lcount)
                    {
                        right = level + (((i * 2U) + 1U) * (size_t)MCEL_BLOCK_HASH_SIZE);
                    }
                    else
                    {
                        right = left;
                    }

                    res = mcel_merkle_node_hash(next + (i * (size_t)MCEL_BLOCK_HASH_SIZE), left, right);

                    if (res == false)
                    {
                        break;
                    }
                }

                qsc_memutils_alloc_free(level);
                level = next;
                lcount = ncount;
            }

            if (res == true)
            {
                qsc_memutils_copy(output, level, MCEL_BLOCK_HASH_SIZE);
            }

            qsc_memutils_alloc_free(level);
        }
    }

    return res;
}

static bool policy_record_type_allowed(uint32_t mask, uint32_t rectype)
{
    bool res;

    res = false;

    if (rectype < 32U)
    {
        res = (((mask >> rectype) & 1U) == 1U);
    }

    return res;
}

bool mcel_block_commit(uint8_t* output, const mcel_block_header* header, const uint8_t* blkroot)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(header != NULL);
    MCEL_ASSERT(blkroot != NULL);

    bool res;

    res = false;

    if (output != NULL && header != NULL && blkroot != NULL)
    {
        uint8_t enc[MCEL_BLOCK_HEADER_ENCODED_SIZE] = { 0U };
        uint8_t buf[MCEL_BLOCK_HEADER_ENCODED_SIZE + (size_t)MCEL_BLOCK_HASH_SIZE] = { 0U };

        /* canonically encode the block header */
        if (mcel_block_encode_header(enc, header) == true)
        {
            /* concatenate Enc(header) || blkroot */
            qsc_memutils_copy(buf, enc, MCEL_BLOCK_HEADER_ENCODED_SIZE);
            qsc_memutils_copy(buf + MCEL_BLOCK_HEADER_ENCODED_SIZE, blkroot, MCEL_BLOCK_HASH_SIZE);

            /* compute H(BLK; buf) */
            res = mcel_domain_hash_message(output, mcel_domain_block, buf, sizeof(buf));
        }
    }

    return res;
}

bool mcel_block_encode(uint8_t* output, size_t outlen, const mcel_block_header* header, const uint8_t* blkroot, const uint8_t* blkcommit, const uint8_t* reccommits, size_t reccount)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(outlen != 0);
    MCEL_ASSERT(header != NULL);
    MCEL_ASSERT(blkroot != NULL);
    MCEL_ASSERT(blkcommit != NULL);
    MCEL_ASSERT(reccommits != NULL);
    MCEL_ASSERT(reccount > 0U);

    bool res;

    res = false;

    if (output != NULL && outlen != 0U && header != NULL && blkroot != NULL && blkcommit != NULL && reccommits != NULL && reccount > 0U)
    {
        if (outlen >= (size_t)MCEL_BLOCK_ENCODED_FIXED_SIZE + (reccount * (size_t)MCEL_BLOCK_HASH_SIZE))
        {
            uint8_t henc[MCEL_BLOCK_HEADER_ENCODED_SIZE] = { 0U };
            size_t pos;

            res = mcel_block_encode_header(henc, header);

            if (res == true)
            {
                pos = 0;

                qsc_memutils_copy(output + pos, henc, sizeof(henc));
                pos += sizeof(henc);
                qsc_memutils_copy(output + pos, blkroot, MCEL_BLOCK_HASH_SIZE);
                pos += (size_t)MCEL_BLOCK_HASH_SIZE;
                qsc_memutils_copy(output + pos, blkcommit, MCEL_BLOCK_HASH_SIZE);
                pos += (size_t)MCEL_BLOCK_HASH_SIZE;
                qsc_memutils_copy(output + pos, reccommits, reccount * (size_t)MCEL_BLOCK_HASH_SIZE);
                pos += reccount * (size_t)MCEL_BLOCK_HASH_SIZE;

                res = (pos == MCEL_BLOCK_HEADER_ENCODED_SIZE + MCEL_BLOCK_HASH_SIZE + MCEL_BLOCK_HASH_SIZE + (reccount * MCEL_BLOCK_HASH_SIZE));
            }
        }
    }

    return res;
}

size_t mcel_block_encoded_size(size_t reccount)
{
    MCEL_ASSERT(reccount > 0U);

    size_t res;

    res = 0U;

    if (reccount > 0U)
    {
        res = (size_t)MCEL_BLOCK_ENCODED_FIXED_SIZE + (reccount * (size_t)MCEL_BLOCK_HASH_SIZE);
    }

    return res;
}

bool mcel_block_encode_header(uint8_t* output, const mcel_block_header* header)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(header != NULL);

    size_t pos;
    bool res;

    res = false;

    if (output != NULL && header != NULL)
    {
        qsc_memutils_clear(output, MCEL_BLOCK_HEADER_ENCODED_SIZE);
        pos = 0U;

        qsc_intutils_be64to8(output + pos, header->block_sequence);
        pos += sizeof(uint64_t);
        qsc_intutils_be64to8(output + pos, header->first_record_seq);
        pos += sizeof(uint64_t);
        qsc_intutils_be64to8(output + pos, header->timestamp);
        pos += sizeof(uint64_t);
        qsc_intutils_be32to8(output + pos, header->record_count);
        pos += sizeof(uint32_t);
        output[pos] = header->flags;
        pos += sizeof(uint8_t);
        output[pos] = header->version;
        pos += sizeof(uint8_t);

        qsc_memutils_copy(output + pos, header->keyid, MCEL_BLOCK_KEYID_SIZE);
        pos += MCEL_BLOCK_KEYID_SIZE;

        res = (pos == (size_t)MCEL_BLOCK_HEADER_ENCODED_SIZE);
    }

    return res;
}

bool mcel_block_seal(uint8_t* blkroot, uint8_t* blkcommit, const mcel_block_header* header, const uint8_t* reccommits, size_t reccount)
{
    MCEL_ASSERT(blkroot != NULL);
    MCEL_ASSERT(blkcommit != NULL);
    MCEL_ASSERT(header != NULL);

    bool res;

    res = false;

    if (blkroot != NULL && blkcommit != NULL && header != NULL)
    {
        /* seal the block by computing the Merkle root of record commitments */
        res = mcel_merkle_root(blkroot, reccommits, reccount);

        if (res == true)
        {
            /* bind the block header to the root */
            res = mcel_block_commit(blkcommit, header, blkroot);
        }
    }

    return res;
}

bool mcel_checkpoint_audit_path_verify(uint8_t* outheadcommit, const mcel_checkpoint_audit_item* items, size_t itemcount, const uint8_t* publickey)
{
    MCEL_ASSERT(outheadcommit != NULL);
    MCEL_ASSERT(items != NULL);
    MCEL_ASSERT(itemcount > 0U);
    MCEL_ASSERT(publickey != NULL);

    bool res;

    res = false;

    if (outheadcommit != NULL && items != NULL && itemcount > 0U && publickey != NULL)
    {
        uint8_t prevcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
        mcel_checkpoint_header prevhdr;
        bool haveprev;

        qsc_memutils_clear(&prevhdr, sizeof(prevhdr));
        haveprev = false;

        res = true;

        for (size_t i = 0; i < itemcount && res == true; ++i)
        {
            mcel_checkpoint_header curhdr = { 0U };
            uint8_t curcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
            uint8_t curblkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
            uint8_t curprevcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };

            /* verify current bundle signature and commitment correctness */
            res = mcel_checkpoint_bundle_verify(curcommit, &curhdr, curblkroot, curprevcommit, items[i].bundle, items[i].bundlelen, publickey);

            if (res == true && haveprev == true)
            {
                /* verify chain linkage */
                res = mcel_checkpoint_chain_link_verify(prevcommit, curprevcommit, &prevhdr, &curhdr);
            }

            if (res == true)
            {
                /* carry forward */
                qsc_memutils_copy(prevcommit, curcommit, MCEL_BLOCK_HASH_SIZE);
                prevhdr = curhdr;
                haveprev = true;
            }
        }

        if (res == true && haveprev == true)
        {
            qsc_memutils_copy(outheadcommit, prevcommit, MCEL_BLOCK_HASH_SIZE);
        }
        else
        {
            qsc_memutils_clear(outheadcommit, MCEL_BLOCK_HASH_SIZE);
            res = false;
        }
    }

    return res;
}

size_t mcel_checkpoint_bundle_encoded_size(size_t siglen)
{
    MCEL_ASSERT(siglen != 0U);

    size_t res;

    res = (size_t)MCEL_CHECKPOINT_BUNDLE_FIXED_SIZE + siglen;

    return res;
}

bool mcel_checkpoint_bundle_encode(uint8_t* output, size_t outlen, const mcel_checkpoint_header* header, 
    const uint8_t* blkroot, const uint8_t* prevcommit, const uint8_t* sigcommit, size_t siglen)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(outlen != 0U);
    MCEL_ASSERT(header != NULL);
    MCEL_ASSERT(blkroot != NULL);
    MCEL_ASSERT(prevcommit != NULL);
    MCEL_ASSERT(sigcommit != NULL);
    MCEL_ASSERT(siglen != 0U);

    bool res;

    res = false;

    if (output != NULL && outlen != 0U && header != NULL && blkroot != NULL && prevcommit != NULL && sigcommit != NULL && siglen != 0U)
    {
        uint8_t henc[MCEL_CHECKPOINT_HEADER_ENCODED_SIZE] = { 0U };
        size_t pos;
        size_t req;

        /* required serialized length */
        req = (size_t)MCEL_CHECKPOINT_BUNDLE_FIXED_SIZE + siglen;

        if (outlen >= req)
        {
            /* encode header */
            res = mcel_checkpoint_encode_header(henc, header);

            if (res == true)
            {
                pos = 0U;

                qsc_memutils_copy(output + pos, henc, sizeof(henc));
                pos += sizeof(henc);
                qsc_memutils_copy(output + pos, blkroot, MCEL_BLOCK_HASH_SIZE);
                pos += (size_t)MCEL_BLOCK_HASH_SIZE;
                qsc_memutils_copy(output + pos, prevcommit, MCEL_BLOCK_HASH_SIZE);
                pos += (size_t)MCEL_BLOCK_HASH_SIZE;
                qsc_memutils_copy(output + pos, sigcommit, siglen);
                pos += siglen;

                res = (pos == req);
            }
        }
    }

    return res;
}

bool mcel_checkpoint_bundle_verify(uint8_t* chkcommit, mcel_checkpoint_header* header, uint8_t* blkroot, uint8_t* prevcommit,
    const uint8_t* bundle, size_t bundlelen, const uint8_t* publickey)
{
    MCEL_ASSERT(chkcommit != NULL);
    MCEL_ASSERT(header != NULL);
    MCEL_ASSERT(blkroot != NULL);
    MCEL_ASSERT(prevcommit != NULL);
    MCEL_ASSERT(bundle != NULL);
    MCEL_ASSERT(publickey != NULL);

    bool res;

    res = false;

    if (chkcommit != NULL && header != NULL && blkroot != NULL && prevcommit != NULL && bundle != NULL && publickey != NULL)
    {
        uint8_t henc[MCEL_CHECKPOINT_HEADER_ENCODED_SIZE] = { 0U };
        const uint8_t* sigcommit;
        size_t pos;
        size_t siglen;

        /* bundle must contain at least the fixed-size portion */
        if (bundlelen >= (size_t)MCEL_CHECKPOINT_BUNDLE_FIXED_SIZE)
        {
            pos = 0U;

            qsc_memutils_copy(henc, bundle + pos, sizeof(henc));
            pos += sizeof(henc);
            qsc_memutils_copy(blkroot, bundle + pos, MCEL_BLOCK_HASH_SIZE);
            pos += (size_t)MCEL_BLOCK_HASH_SIZE;
            qsc_memutils_copy(prevcommit, bundle + pos, MCEL_BLOCK_HASH_SIZE);
            pos += (size_t)MCEL_BLOCK_HASH_SIZE;

            /* signed commitment message is the remainder */
            sigcommit = bundle + pos;
            siglen = bundlelen - pos;

            /* decode header */
            res = mcel_checkpoint_decode_header(header, henc);

            if (res == true)
            {
                uint8_t expcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
                uint8_t gotcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
                size_t glen;

                /* recompute expected checkpoint commitment */
                res = mcel_checkpoint_commit(expcommit, header, blkroot, prevcommit);

                if (res == true)
                {
                    /* verify signature and extract commitment */
                    glen = 0U;
                    res = mcel_checkpoint_verify(gotcommit, &glen, sigcommit, siglen, publickey);
                    
                    if (res == true && glen == MCEL_BLOCK_HASH_SIZE)
                    {
                        /* compare extracted commitment with recomputed commitment */
                        res = (qsc_intutils_verify(expcommit, gotcommit, MCEL_BLOCK_HASH_SIZE) == 0U);

                        if (res == true)
                        {
                            /* return the verified commitment */
                            qsc_memutils_copy(chkcommit, expcommit, MCEL_BLOCK_HASH_SIZE);
                        }
                    }
                }
            }
        }
    }

    return res;
}

bool mcel_checkpoint_chain_link_verify(const uint8_t* prevcommit, const uint8_t* curprevcommit, const mcel_checkpoint_header* prevhdr, const mcel_checkpoint_header* curhdr)
{
    MCEL_ASSERT(prevcommit != NULL);
    MCEL_ASSERT(curprevcommit != NULL);
    MCEL_ASSERT(prevhdr != NULL);
    MCEL_ASSERT(curhdr != NULL);

    bool res;

    res = false;

    if (prevcommit != NULL && curprevcommit != NULL && prevhdr != NULL && curhdr != NULL)
    {
        /* prev pointer matches previous checkpoint commitment */
        res = (qsc_intutils_verify(prevcommit, curprevcommit, MCEL_BLOCK_HASH_SIZE) == 0U);

        if (res == true)
        {
            /* enforce sequential checkpoint numbering */
            res = (curhdr->chk_sequence == (prevhdr->chk_sequence + 1U));

            if (res == true)
            {
                /* enforce record sequence monotonicity */
                res = (curhdr->first_record_seq >= prevhdr->first_record_seq);

                if (res == true)
                {
                    /* enforce nondecreasing timestamps */
                    res = (curhdr->timestamp >= prevhdr->timestamp);
                }
            }
        }
    }

    return res;
}

bool mcel_checkpoint_commit(uint8_t* output, const mcel_checkpoint_header* header, const uint8_t* blkroot, const uint8_t* pldcommit)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(header != NULL);
    MCEL_ASSERT(blkroot != NULL);
    MCEL_ASSERT(pldcommit != NULL);

    bool res;

    res = false;

    if (output != NULL && header != NULL && blkroot != NULL && pldcommit != NULL)
    {
        uint8_t enc[MCEL_CHECKPOINT_HEADER_ENCODED_SIZE] = { 0U };
        uint8_t buf[MCEL_CHECKPOINT_HEADER_ENCODED_SIZE + MCEL_BLOCK_HASH_SIZE + MCEL_BLOCK_HASH_SIZE] = { 0U };

        /* canonically encode the checkpoint header */
        if (mcel_checkpoint_encode_header(enc, header) == true)
        {
            /* concatenate Enc(header) || blkroot || pldcommit */
            qsc_memutils_copy(buf, enc, MCEL_CHECKPOINT_HEADER_ENCODED_SIZE);
            qsc_memutils_copy(buf + MCEL_CHECKPOINT_HEADER_ENCODED_SIZE, blkroot, MCEL_BLOCK_HASH_SIZE);
            qsc_memutils_copy(buf + MCEL_CHECKPOINT_HEADER_ENCODED_SIZE + (size_t)MCEL_BLOCK_HASH_SIZE, pldcommit, MCEL_BLOCK_HASH_SIZE);

            /* compute H(CHK; buf) */
            res = mcel_domain_hash_message(output, mcel_domain_checkpoint, buf, sizeof(buf));
        }
    }

    return res;
}

bool mcel_checkpoint_consistency_verify(const uint8_t* firstroot, const uint8_t* secondroot, size_t first, size_t second, const uint8_t* proof, size_t prooflen)
{
    MCEL_ASSERT(firstroot != NULL);
    MCEL_ASSERT(secondroot != NULL);
    MCEL_ASSERT(first > 0U);
    MCEL_ASSERT(second > 0U);
    MCEL_ASSERT(first <= second);

    bool res;

    res = false;

    if (firstroot != NULL && secondroot != NULL && first > 0U && second > 0U && first <= second)
    {
        size_t pcount;

        pcount = prooflen / (size_t)MCEL_BLOCK_HASH_SIZE;

        if ((prooflen % (size_t)MCEL_BLOCK_HASH_SIZE) != 0U)
        {
            res = false;
        }
        else if (first == second)
        {
            /* identical trees: proof must be empty and roots must match */
            res = (pcount == 0U) && (qsc_intutils_are_equal8(firstroot, secondroot, MCEL_BLOCK_HASH_SIZE) == true);
        }
        else if (proof == NULL || pcount == 0U)
        {
            /* for first < second: proof must be non-empty */
            res = false;
        }
        else
        {
            uint8_t fr[MCEL_BLOCK_HASH_SIZE] = { 0U };
            uint8_t sr[MCEL_BLOCK_HASH_SIZE] = { 0U };
            uint8_t tmp[MCEL_BLOCK_HASH_SIZE] = { 0U };
            size_t fn;
            size_t pi;
            size_t sn;

            /* step 3: fn = first - 1, sn = second - 1 */
            fn = first - 1U;
            sn = second - 1U;
            pi = 0U;

            /* step 2: if first is power of two, conceptually prepend firstroot to proof.
             * That means we set fr=sr=firstroot and start consuming proof from proof[0].
             * Otherwise fr=sr=proof[0] and consume starting at proof[1]. */
            if (qsc_intutils_is_power_of_two(first) == true)
            {
                qsc_memutils_copy(fr, firstroot, MCEL_BLOCK_HASH_SIZE);
                qsc_memutils_copy(sr, firstroot, MCEL_BLOCK_HASH_SIZE);
            }
            else
            {
                qsc_memutils_copy(fr, proof + (pi * (size_t)MCEL_BLOCK_HASH_SIZE), MCEL_BLOCK_HASH_SIZE);
                qsc_memutils_copy(sr, proof + (pi * (size_t)MCEL_BLOCK_HASH_SIZE), MCEL_BLOCK_HASH_SIZE);
                ++pi;
            }

            /* step 4: if LSB(fn) set, right shift fn and sn until LSB(fn) not set */
            if (qsc_intutils_lsb_is_set(fn) == true)
            {
                while (qsc_intutils_lsb_is_set(fn) == true)
                {
                    fn >>= 1;
                    sn >>= 1;
                }
            }

            res = true;

            /* step 6: iterate remaining proof elements */
            for (; pi < pcount && res == true; ++pi)
            {
                const uint8_t* c;

                if (sn == 0U)
                {
                    res = false;
                    break;
                }

                c = proof + (pi * (size_t)MCEL_BLOCK_HASH_SIZE);

                if (qsc_intutils_lsb_is_set(fn) == true || fn == sn)
                {
                    /* fr = H(c || fr) */
                    res = mcel_merkle_node_hash(tmp, c, fr);

                    if (res == true)
                    {
                        qsc_memutils_copy(fr, tmp, MCEL_BLOCK_HASH_SIZE);
                    }

                    /* sr = H(c || sr) */
                    if (res == true)
                    {
                        res = mcel_merkle_node_hash(tmp, c, sr);

                        if (res == true)
                        {
                            qsc_memutils_copy(sr, tmp, MCEL_BLOCK_HASH_SIZE);
                        }
                    }

                    /* if LSB(fn) not set, right shift fn and sn until either LSB(fn) set or fn == 0 */
                    if (res == true && qsc_intutils_lsb_is_set(fn) == false)
                    {
                        while (qsc_intutils_lsb_is_set(fn) == false && fn != 0U)
                        {
                            fn >>= 1;
                            sn >>= 1;
                        }
                    }
                }
                else
                {
                    /* sr = H(sr || c) */
                    res = mcel_merkle_node_hash(tmp, sr, c);

                    if (res == true)
                    {
                        qsc_memutils_copy(sr, tmp, MCEL_BLOCK_HASH_SIZE);
                    }
                }

                /* finally, right shift fn and sn one time */
                fn >>= 1;
                sn >>= 1;
            }

            if (res == true)
            {
                /* step 7: must end with sn == 0 and matching roots */
                res = (sn == 0U);

                if (res == true)
                {
                    res = (qsc_intutils_are_equal8(fr, firstroot, MCEL_BLOCK_HASH_SIZE) == true);
                }

                if (res == true)
                {
                    res = (qsc_intutils_are_equal8(sr, secondroot, MCEL_BLOCK_HASH_SIZE) == true);
                }
            }
        }
    }

    return res;
}

bool mcel_checkpoint_decode_header(mcel_checkpoint_header* header, const uint8_t* enc)
{
    MCEL_ASSERT(header != NULL);
    MCEL_ASSERT(enc != NULL);

    size_t pos;
    bool res;

    res = false;

    if (header != NULL && enc != NULL)
    {
        pos = 0U;

        header->chk_sequence = qsc_intutils_be8to64(enc + pos);
        pos += sizeof(uint64_t);
        header->first_record_seq = qsc_intutils_be8to64(enc + pos);
        pos += sizeof(uint64_t);
        header->timestamp = qsc_intutils_be8to64(enc + pos);
        pos += sizeof(uint64_t);
        header->record_count = qsc_intutils_be8to32(enc + pos);
        pos += sizeof(uint32_t);
        header->flags = enc[pos];
        pos += sizeof(uint8_t);
        header->version = enc[pos];
        pos += sizeof(uint8_t);

        qsc_memutils_copy(header->keyid, enc + pos, MCEL_CHECKPOINT_KEYID_SIZE);
        pos += MCEL_CHECKPOINT_KEYID_SIZE;
        res = (pos == (size_t)MCEL_CHECKPOINT_HEADER_ENCODED_SIZE);
    }

    return res;
}

bool mcel_checkpoint_encode_header(uint8_t* output, const mcel_checkpoint_header* header)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(header != NULL);

    size_t pos;
    bool res;

    res = false;

    if (output != NULL && header != NULL)
    {
        qsc_memutils_clear(output, MCEL_CHECKPOINT_HEADER_ENCODED_SIZE);
        pos = 0U;

        qsc_intutils_be64to8(output + pos, header->chk_sequence);
        pos += sizeof(uint64_t);
        qsc_intutils_be64to8(output + pos, header->first_record_seq);
        pos += sizeof(uint64_t);
        qsc_intutils_be64to8(output + pos, header->timestamp);
        pos += sizeof(uint64_t);
        qsc_intutils_be32to8(output + pos, header->record_count);
        pos += sizeof(uint32_t);
        output[pos] = header->flags;
        pos += sizeof(uint8_t);
        output[pos] = header->version;
        pos += sizeof(uint8_t);

        qsc_memutils_copy(output + pos, header->keyid, MCEL_CHECKPOINT_KEYID_SIZE);
        pos += MCEL_CHECKPOINT_KEYID_SIZE;
        res = (pos == (size_t)MCEL_CHECKPOINT_HEADER_ENCODED_SIZE);
    }

    return res;
}

bool mcel_checkpoint_prove_consistency(uint8_t* proof, size_t prooflen, const uint8_t* leaves, size_t oldcount, size_t newcount)
{
    MCEL_ASSERT(proof != NULL);
    MCEL_ASSERT(prooflen != 0U);
    MCEL_ASSERT(leaves != NULL);
    MCEL_ASSERT(oldcount > 0U);
    MCEL_ASSERT(newcount > 0U);
    MCEL_ASSERT(oldcount <= newcount);

    bool res;

    res = false;

    if (proof != NULL && prooflen != 0U && leaves != NULL && oldcount > 0U && newcount > 0U && oldcount <= newcount)
    {
        /* special case: identical trees, proof is empty (valid) */
        if (oldcount == newcount)
        {
            res = true;
        }
        else
        {
            /* we build proof hashes into proof[] as a simple concatenation */
            size_t pos;
            size_t n;
            size_t m;
            size_t start;

            res = true;
            pos = 0U;
            n = oldcount;
            m = newcount;
            start = 0U;

            /* if n is a power of two, the first proof element is the root of the first n leaves.
               otherwise, we will accumulate using the standard decomposition */
            if (qsc_intutils_is_power_of_two(n) == true)
            {
                uint8_t h[MCEL_BLOCK_HASH_SIZE] = { 0U };

                if (checkpoint_subtree_root(h, leaves, 0U, n) == false)
                {
                    res = false;
                }
                else if (prooflen < (size_t)MCEL_BLOCK_HASH_SIZE)
                {
                    res = false;
                }
                else
                {
                    qsc_memutils_copy(proof + pos, h, MCEL_BLOCK_HASH_SIZE);
                    pos += (size_t)MCEL_BLOCK_HASH_SIZE;
                }
            }

            if (res == true)
            {
                /* walk down the implicit binary tree describing [0..m) while tracking [0..n)
                   using the standard approach: at each step, split by the largest power-of-two
                   less than the current m */
                while (n != m)
                {
                    size_t k = 1U;

                    /* largest power-of-two less than m (highest bit) */
                    while ((k << 1U) < m)
                    {
                        k <<= 1U;
                    }

                    if (n <= k)
                    {
                        uint8_t h[MCEL_BLOCK_HASH_SIZE] = { 0U };

                        /* right subtree root is included for the new tree */
                        if (checkpoint_subtree_root(h, leaves, start + k, m - k) == false)
                        {
                            res = false;
                            break;
                        }

                        if (pos + (size_t)MCEL_BLOCK_HASH_SIZE > prooflen)
                        {
                            res = false;
                            break;
                        }

                        qsc_memutils_copy(proof + pos, h, MCEL_BLOCK_HASH_SIZE);
                        pos += (size_t)MCEL_BLOCK_HASH_SIZE;

                        /* descend into left side */
                        m = k;
                    }
                    else
                    {
                        uint8_t h[MCEL_BLOCK_HASH_SIZE] = { 0U };

                        /* left subtree root is included for the old tree */
                        if (checkpoint_subtree_root(h, leaves, start, k) == false)
                        {
                            res = false;
                            break;
                        }

                        if (pos + (size_t)MCEL_BLOCK_HASH_SIZE > prooflen)
                        {
                            res = false;
                            break;
                        }

                        qsc_memutils_copy(proof + pos, h, MCEL_BLOCK_HASH_SIZE);
                        pos += (size_t)MCEL_BLOCK_HASH_SIZE;

                        /* descend into right side, adjust start and n */
                        start += k;
                        n -= k;
                        m -= k;
                    }
                }
            }
        }
    }

    return res;
}

bool mcel_checkpoint_seal(uint8_t* chkcommit, uint8_t* sigcommit, size_t* siglen, const mcel_checkpoint_header* header, const uint8_t* blkroot,
    const uint8_t* prevcommit, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
    MCEL_ASSERT(chkcommit != NULL);
    MCEL_ASSERT(sigcommit != NULL);
    MCEL_ASSERT(siglen != NULL);
    MCEL_ASSERT(header != NULL);
    MCEL_ASSERT(blkroot != NULL);
    MCEL_ASSERT(prevcommit != NULL);
    MCEL_ASSERT(privatekey != NULL);
    MCEL_ASSERT(rng_generate != NULL);

    bool res;

    res = false;

    if (chkcommit != NULL && sigcommit != NULL && siglen != NULL && header != NULL && blkroot != NULL && prevcommit != NULL && privatekey != NULL && rng_generate != NULL)
    {
        /* generate the checkpoint commitment from header, sealed block root, and previous checkpoint */
        res = mcel_checkpoint_commit(chkcommit, header, blkroot, prevcommit);

        if (res == true)
        {
            /* sign the commitment to produce an auditable checkpoint artifact */
            res = mcel_checkpoint_sign(sigcommit, siglen, chkcommit, privatekey, rng_generate);
        }
    }

    return res;
}

bool mcel_checkpoint_sign(uint8_t* sigcommit, size_t* siglen, const uint8_t* chkcommit, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t))
{
    MCEL_ASSERT(sigcommit != NULL);
    MCEL_ASSERT(siglen != NULL);
    MCEL_ASSERT(chkcommit != NULL);
    MCEL_ASSERT(privatekey != NULL);
    MCEL_ASSERT(rng_generate != NULL);

    bool res;

    res = false;

    if (sigcommit != NULL && siglen != NULL && chkcommit != NULL && privatekey != NULL && rng_generate != NULL)
    {
        mcel_signature_sign(sigcommit, siglen, chkcommit, (size_t)MCEL_BLOCK_HASH_SIZE, privatekey, rng_generate);
        res = (*siglen == (size_t)MCEL_CHECKPOINT_SIGNED_COMMIT_SIZE);
    }

    return res;
}

bool mcel_checkpoint_verify(uint8_t* chkcommit, size_t* commitlen, const uint8_t* sigcommit, size_t siglen, const uint8_t* publickey)
{
    MCEL_ASSERT(chkcommit != NULL);
    MCEL_ASSERT(commitlen != NULL);
    MCEL_ASSERT(sigcommit != NULL);
    MCEL_ASSERT(publickey != NULL);

    bool res;

    res = false;

    if (chkcommit != NULL && commitlen != NULL && sigcommit != NULL && publickey != NULL)
    {
        /* verify extracts the original message */
        res = mcel_signature_verify(chkcommit, commitlen, sigcommit, siglen, publickey);

        /* The verified message must be exactly a 32-byte checkpoint commitment */
        if (res == true)
        {
            res = (*commitlen == (size_t)MCEL_BLOCK_HASH_SIZE);
        }
    }

    return res;
}

void mcel_generate_keypair(uint8_t* sigkey, uint8_t* verkey)
{
    mcel_signature_generate_keypair(verkey, sigkey, qsc_acp_generate);
}

size_t mcel_keyrotate_payload_size(size_t pubkeylen)
{
    size_t res;

    res = 0U;

    if (pubkeylen > 0U)
    {
        res = (size_t)MCEL_KEYROTATE_PAYLOAD_FIXED_SIZE + pubkeylen;
    }

    return res;
}

size_t mcel_keyrotate_record_create(mcel_record_header* header, uint8_t* payload, size_t payloadlen, uint64_t sequence, 
    uint8_t flags, const uint8_t* newkeyid, const uint8_t* newpubkey, size_t pubkeylen)
{
    MCEL_ASSERT(header != NULL);
    MCEL_ASSERT(payload != NULL);
    MCEL_ASSERT(payloadlen != 0U);
    MCEL_ASSERT(newkeyid != NULL);
    MCEL_ASSERT(newpubkey != NULL);
    MCEL_ASSERT(pubkeylen != 0U);

    size_t res;

    res = 0U;

    if (header != NULL && payload != NULL && payloadlen != 0U && newkeyid != NULL && newpubkey != NULL && pubkeylen != 0U)
    {
        size_t pos;
        const size_t req = mcel_keyrotate_payload_size(pubkeylen);

        if (req != 0U && payloadlen >= req)
        {
            pos = 0U;

            payload[pos] = (uint8_t)MCEL_KEYROTATE_PAYLOAD_VERSION;
            pos += sizeof(uint8_t);
            payload[pos] = flags;
            pos += sizeof(uint8_t);
            qsc_memutils_copy(payload + pos, newkeyid, MCEL_CHECKPOINT_KEYID_SIZE);
            pos += (size_t)MCEL_CHECKPOINT_KEYID_SIZE;
            qsc_intutils_be16to8(payload + pos, (uint16_t)pubkeylen);
            pos += sizeof(uint16_t);
            qsc_memutils_copy(payload + pos, newpubkey, pubkeylen);
            pos += pubkeylen;
            res = pos;

            /* fill record header */
            qsc_memutils_clear(header, sizeof(mcel_record_header));

            header->version = (uint8_t)MCEL_RECORD_VERSION;
            header->type = (uint8_t)MCEL_RECORD_TYPE_KEYROTATE;
            header->flags = flags;
            header->sequence = sequence;
            header->timestamp = qsc_timestamp_datetime_utc();
        }
    }

    return res;
}

bool mcel_ledger_append_record(mcel_ledger_state* state, uint8_t* reccommit, uint64_t* outpos, const mcel_record_header* header, const uint8_t* payload, size_t paylen)
{
    MCEL_ASSERT(state != NULL);
    MCEL_ASSERT(reccommit != NULL);
    MCEL_ASSERT(header != NULL);
    MCEL_ASSERT(payload != NULL);
    MCEL_ASSERT(paylen != 0U);

    bool res;

    res = false;

    if (state != NULL && reccommit != NULL && header != NULL && payload != NULL && paylen != 0U)
    {
        const uint8_t* loc;
        size_t loclen;

        /* required storage primitive */
        if (state->store.append != NULL)
        {
            uint8_t pldcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };

            loc = (const uint8_t*)MCEL_STORE_LOC_RECORDS;
            loclen = sizeof(MCEL_STORE_LOC_RECORDS) - 1U;

            /* compute payload commitment */
            const bool encrypted = ((header->flags & (uint8_t)MCEL_RECORD_FLAG_ENCRYPTED) != 0U);
            res = mcel_payload_commit(pldcommit, encrypted, payload, paylen);

            if (res == true)
            {
                /* compute record commitment */
                res = mcel_record_commit(reccommit, header, pldcommit);

                if (res == true)
                {
                    uint8_t henc[MCEL_RECORD_HEADER_ENCODED_SIZE] = { 0U };
                    size_t pos;
                    size_t rlen;

                    /* encode record header */
                    res = mcel_record_encode_header(henc, header);

                    if (res == true)
                    {
                        /* Canonical record serialization:
                           Enc(header) | payload_commit | payload */
                        rlen = (size_t)MCEL_RECORD_HEADER_ENCODED_SIZE + (size_t)MCEL_BLOCK_HASH_SIZE + paylen;

                        /* stack allocation is not safe for unbounded payload sizes */
                        uint8_t* rbuf;

                        rbuf = (uint8_t*)qsc_memutils_malloc(rlen);

                        if (rbuf != NULL)
                        {
                            pos = 0;

                            qsc_memutils_copy(rbuf + pos, henc, sizeof(henc));
                            pos += sizeof(henc);
                            qsc_memutils_copy(rbuf + pos, pldcommit, MCEL_BLOCK_HASH_SIZE);
                            pos += (size_t)MCEL_BLOCK_HASH_SIZE;
                            qsc_memutils_copy(rbuf + pos, payload, paylen);
                            pos += paylen;

                            res = (pos == rlen);

                            if (res == true)
                            {
                                /* append to the host-managed record log */
                                res = state->store.append(state->store.context, loc, loclen, rbuf, rlen, outpos);
                            }

                            qsc_memutils_alloc_free(rbuf);
                        }
                    }
                }
            }
        }
    }

    return res;
}

bool mcel_ledger_initialize(mcel_ledger_state* state, const mcel_store_callbacks* store, const uint8_t* nsid, size_t nsidlen,
    const uint8_t* publickey, uint8_t* headbuf, size_t headbuflen)
{
    MCEL_ASSERT(state != NULL);
    MCEL_ASSERT(store != NULL);
    MCEL_ASSERT(nsid != NULL);
    MCEL_ASSERT(nsidlen != 0U);
    MCEL_ASSERT(nsidlen <= (size_t)MCEL_LEDGER_NAMESPACE_ID_MAX);
    MCEL_ASSERT(publickey != NULL);
    MCEL_ASSERT(headbuf != NULL);
    MCEL_ASSERT(headbuflen != 0U);

    bool res;

    res = false;

    if (state != NULL && store != NULL && nsid != NULL && nsidlen != 0U && nsidlen <= (size_t)MCEL_LEDGER_NAMESPACE_ID_MAX &&
        publickey != NULL && headbuf != NULL && headbuflen != 0U)
    {
        uint64_t headlen;
        size_t outread;
        const uint8_t* headloc;
        size_t headloclen;

        qsc_memutils_clear(state, sizeof(mcel_ledger_state));

        /* copy callbacks and namespace */
        qsc_memutils_copy(&state->store, store, sizeof(mcel_store_callbacks));
        qsc_memutils_copy(state->nsid, nsid, nsidlen);
        state->nsidlen = nsidlen;
        state->publickey = publickey;

        /* default: no head loaded */
        state->have_head = 0U;
        qsc_memutils_clear(state->head_commit, MCEL_BLOCK_HASH_SIZE);
        qsc_memutils_clear(&state->head_header, sizeof(mcel_checkpoint_header));

        headloc = (const uint8_t*)MCEL_STORE_LOC_HEAD;
        headloclen = sizeof(MCEL_STORE_LOC_HEAD) - 1U;
        headlen = 0U;
        outread = 0U;

        /* if no head exists yet, initialization still succeeds */
        if (state->store.size != NULL && state->store.size(state->store.context, headloc, headloclen, &headlen) == true && headlen != 0U)
        {
            uint8_t blkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
            uint8_t prevcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };

            if ((size_t)headlen <= headbuflen)
            {
                if (state->store.read != NULL && state->store.read(state->store.context, headloc, headloclen, headbuf, (size_t)headlen, &outread) == true)
                {
                    if (outread >= (size_t)headlen)
                    {
                        /* verify and load head bundle */
                        res = mcel_checkpoint_bundle_verify(state->head_commit, &state->head_header, blkroot, prevcommit, headbuf, (size_t)headlen, state->publickey);

                        if (res == true)
                        {
                            state->have_head = 1U;
                        }
                    }
                }
            }
        }

        /* no head present, treat as new/empty ledger */
        res = true;
    }

    return res;
}

bool mcel_ledger_get_checkpoint_head(mcel_ledger_state* state, uint8_t* headcommit, mcel_checkpoint_header* headheader)
{
    MCEL_ASSERT(state != NULL);
    MCEL_ASSERT(headcommit != NULL);
    MCEL_ASSERT(headheader != NULL);

    bool res;

    res = false;

    if (state != NULL && headcommit != NULL && headheader != NULL)
    {
        if (state->have_head != 0U)
        {
            qsc_memutils_copy(headcommit, state->head_commit, MCEL_BLOCK_HASH_SIZE);
            *headheader = state->head_header;
            res = true;
        }
    }

    return res;
}

bool mcel_ledger_seal_block(mcel_ledger_state* state, uint8_t* blkroot, uint8_t* blkcommit, const mcel_block_header* header, const uint8_t* reccommits,
    size_t reccount, uint8_t* blockbuf, size_t blockbuflen, uint64_t* outpos)
{
    MCEL_ASSERT(state != NULL);
    MCEL_ASSERT(blkroot != NULL);
    MCEL_ASSERT(blkcommit != NULL);
    MCEL_ASSERT(header != NULL);
    MCEL_ASSERT(reccommits != NULL);
    MCEL_ASSERT(reccount > 0U);
    MCEL_ASSERT(blockbuf != NULL);
    MCEL_ASSERT(blockbuflen != 0U);

    bool res;

    res = false;

    if (state != NULL && blkroot != NULL && blkcommit != NULL && header != NULL && reccommits != NULL 
        && reccount > 0U && blockbuf != NULL && blockbuflen != 0U)
    {
        const uint8_t* loc;
        size_t loclen;
        size_t encsz;

        if (state->store.append != NULL)
        {
            loc = (const uint8_t*)MCEL_STORE_LOC_BLOCKS;
            loclen = sizeof(MCEL_STORE_LOC_BLOCKS) - 1U;

            /* required encoded block size */
            encsz = mcel_block_encoded_size(reccount);

            if (encsz != 0U && blockbuflen >= encsz)
            {
                /* compute merkle root over record commitments */
                res = mcel_merkle_root(blkroot, reccommits, reccount);

                if (res == true)
                {
                    /* compute block commitment */
                    res = mcel_block_commit(blkcommit, header, blkroot);

                    if (res == true)
                    {
                        /* encode sealed block */
                        res = mcel_block_encode(blockbuf, encsz, header, blkroot, blkcommit, reccommits, reccount);

                        if (res == true)
                        {
                            /* store sealed block */
                            res = state->store.append(state->store.context, loc, loclen, blockbuf, encsz, outpos);
                        }
                    }
                }
            }
        }
    }

    return res;
}

bool mcel_ledger_seal_checkpoint(mcel_ledger_state* state, uint8_t* chkcommit, const mcel_checkpoint_header* header, const uint8_t* blkroot,
    const void* sigkey, uint8_t* bundlebuf, size_t bundlebuflen, uint64_t* outpos)
{
    MCEL_ASSERT(state != NULL);
    MCEL_ASSERT(chkcommit != NULL);
    MCEL_ASSERT(header != NULL);
    MCEL_ASSERT(blkroot != NULL);
    MCEL_ASSERT(sigkey != NULL);
    MCEL_ASSERT(bundlebuf != NULL);
    MCEL_ASSERT(bundlebuflen != 0U);

    bool res;

    res = false;

    if (state != NULL && chkcommit != NULL && header != NULL && blkroot != NULL && sigkey != NULL && bundlebuf != NULL && bundlebuflen != 0U)
    {
        uint8_t prevcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
        uint8_t sigcommit[MCEL_CHECKPOINT_SIGNED_COMMIT_SIZE] = { 0U };
        const uint8_t* headloc;
        const uint8_t* logloc;
        size_t bundlen;
        size_t headloclen;
        size_t logloclen;
        size_t siglen;

        /* required callbacks */
        if (state->store.append != NULL)
        {
            logloc = (const uint8_t*)MCEL_STORE_LOC_CHECKPOINTS;
            logloclen = sizeof(MCEL_STORE_LOC_CHECKPOINTS) - 1U;

            headloc = (const uint8_t*)MCEL_STORE_LOC_HEAD;
            headloclen = sizeof(MCEL_STORE_LOC_HEAD) - 1U;

            /* determine previous commitment */
            if (state->have_head != 0U)
            {
                qsc_memutils_copy(prevcommit, state->head_commit, MCEL_BLOCK_HASH_SIZE);
            }
            else
            {
                qsc_memutils_clear(prevcommit, MCEL_BLOCK_HASH_SIZE);
            }

            /* compute checkpoint commitment */
            res = mcel_checkpoint_commit(chkcommit, header, blkroot, prevcommit);

            if (res == true)
            {
                /* sign checkpoint commitment */
                siglen = 0;
                res = mcel_checkpoint_sign(sigcommit, &siglen, chkcommit, sigkey, qsc_acp_generate);

                if (res == true)
                {
                    /* compute bundle size and encode */
                    bundlen = mcel_checkpoint_bundle_encoded_size(siglen);

                    if (bundlen != 0U && bundlebuflen >= bundlen)
                    {
                        res = mcel_checkpoint_bundle_encode(bundlebuf, bundlen, header, blkroot, prevcommit, sigcommit, siglen);

                        if (res == true)
                        {
                            /* append checkpoint bundle to history log */
                            res = state->store.append(state->store.context, logloc, logloclen, bundlebuf, bundlen, outpos);

                            if (res == true)
                            {
                                /* update head pointer */
                                if (state->store.write != NULL)
                                {
                                    res = state->store.write(state->store.context, headloc, headloclen, bundlebuf, bundlen);
                                }
                                else
                                {
                                    /* if no overwrite primitive, append head updates */
                                    res = state->store.append(state->store.context, headloc, headloclen, bundlebuf, bundlen, NULL);
                                }
                            }

                            if (res == true)
                            {
                                /* update in-memory head */
                                qsc_memutils_copy(state->head_commit, chkcommit, MCEL_BLOCK_HASH_SIZE);
                                state->head_header = *header;
                                state->have_head = 1U;
                            }
                        }
                    }
                }
            }
        }
    }

    return res;
}

bool mcel_ledger_verify_integrity(mcel_ledger_state* state, uint8_t* headbuf, size_t headbuflen, const mcel_checkpoint_audit_item* audit, size_t auditcount)
{
    MCEL_ASSERT(state != NULL);
    MCEL_ASSERT(headbuf != NULL);
    MCEL_ASSERT(headbuflen != 0U);

    bool res;

    res = false;

    if (state != NULL && headbuf != NULL && headbuflen != 0U)
    {
        const uint8_t* headloc;
        uint64_t headlen;
        size_t headloclen;
        size_t outread;

        if (state->store.size != NULL && state->store.read != NULL && state->publickey != NULL)
        {
            headloc = (const uint8_t*)MCEL_STORE_LOC_HEAD;
            headloclen = sizeof(MCEL_STORE_LOC_HEAD) - 1U;

            headlen = 0;
            outread = 0;

            /* no head present is not an integrity failure for an empty ledger */
            if (state->store.size(state->store.context, headloc, headloclen, &headlen) == false || headlen == 0U)
            {
                /* if audit path is provided, verify it anyway */
                if (audit != NULL && auditcount != 0U)
                {
                    uint8_t head_commit[MCEL_BLOCK_HASH_SIZE] = { 0U };
                    res = mcel_checkpoint_audit_path_verify(head_commit, audit, auditcount, state->publickey);
                }
                else
                {
                    res = true;
                }
            }
            else
            {
                if ((size_t)headlen > headbuflen)
                {
                    res = false;
                }
                else if (state->store.read(state->store.context, headloc, headloclen, headbuf, (size_t)headlen, &outread) == false)
                {
                    res = false;
                }
                else if (outread != (size_t)headlen)
                {
                    res = false;
                }
                else
                {
                    /* verify head bundle */
                    uint8_t head_commit[MCEL_BLOCK_HASH_SIZE] = { 0U };
                    uint8_t blkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
                    uint8_t prevcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
                    mcel_checkpoint_header hdr;

                    qsc_memutils_clear(&hdr, sizeof(hdr));
                    res = mcel_checkpoint_bundle_verify(head_commit, &hdr, blkroot, prevcommit, headbuf, (size_t)headlen, state->publickey);

                    if (res == true)
                    {
                        /* if state has a head loaded, confirm it matches storage */
                        if (state->have_head != 0U)
                        {
                            res = (qsc_intutils_are_equal8(state->head_commit, head_commit, MCEL_BLOCK_HASH_SIZE) == true);
                        }

                        if (res == true)
                        {
                            /* refresh state head from storage */
                            qsc_memutils_copy(state->head_commit, head_commit, MCEL_BLOCK_HASH_SIZE);
                            state->head_header = hdr;
                            state->have_head = 1U;
                        }
                    }
                }
            }
        }

        /* optional: verify caller-supplied audit path */
        if (res == true && audit != NULL && auditcount != 0U)
        {
            uint8_t audit_head[MCEL_BLOCK_HASH_SIZE] = { 0U };

            res = mcel_checkpoint_audit_path_verify(audit_head, audit, auditcount, state->publickey);

            if (res == true)
            {
                /* audit path head must match stored head */
                res = (qsc_intutils_are_equal8(audit_head, state->head_commit, MCEL_BLOCK_HASH_SIZE) == true);
            }
        }
    }

    return res;
}

bool mcel_payload_commit(uint8_t* output, bool encrypted, const uint8_t* payload, size_t paylen)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(payload != NULL);

    bool res;

    res = false;

    if (output != NULL && payload != NULL && paylen != 0U)
    {
        const mcel_domain_types domain = encrypted ? mcel_domain_ciphertext : mcel_domain_plaintext;

        /* enforce a maximum payload size if configured (0 means unlimited). */
        if (paylen <= (size_t)MCEL_PAYLOAD_MAX_SIZE)
        {
            /* compute H(domain, payload) */
            res = mcel_domain_hash_message(output, domain, payload, paylen);
        }
    }

    return res;
}

bool mcel_policy_apply(mcel_policy_errors* perr, const mcel_policy* policy, const mcel_policy_context* state, mcel_policy_ops op,
    const mcel_record_header* recordhdr, const mcel_checkpoint_header* checkpointhdr)
{
    MCEL_ASSERT(perr != NULL);
    MCEL_ASSERT(policy != NULL);
    MCEL_ASSERT(state != NULL);

    *perr = mcel_policyerr_none;

    if (perr != NULL || policy != NULL || state != NULL)
    {
        if (op == mcel_policyop_append_record)
        {
            MCEL_ASSERT(recordhdr != NULL);

            if (recordhdr == NULL)
            {
                *perr = mcel_policyerr_invalid_parameter;
            }
            else if (policy->max_payload_size != 0U && (size_t)recordhdr->payload_len > policy->max_payload_size)
            {
                *perr = mcel_policyerr_payload_too_large;
            }
            else if (policy->allowed_record_mask != 0U && policy_record_type_allowed(policy->allowed_record_mask, recordhdr->type) == false)
            {
                *perr = mcel_policyerr_record_type_denied;
            }
            else if (policy->require_encryption != 0U)
            {
                if ((recordhdr->flags & (uint8_t)MCEL_RECORD_FLAG_ENCRYPTED) == 0U)
                {
                    *perr = mcel_policyerr_plaintext_denied;
                }
            }
            else if (policy->enforce_monotonic_seq != 0U && state->last_record_sequence != 0U)
            {
                if (recordhdr->sequence <= state->last_record_sequence)
                {
                    *perr = mcel_policyerr_sequence_invalid;
                }
            }
            else if (policy->enforce_monotonic_time != 0U && state->last_record_timestamp != 0U)
            {
                if (recordhdr->timestamp < state->last_record_timestamp)
                {
                    *perr = mcel_policyerr_timestamp_invalid;
                }
            }
        }
        else if (op == mcel_policyop_seal_checkpoint)
        {
            MCEL_ASSERT(checkpointhdr != NULL);

            if (checkpointhdr == NULL)
            {
                *perr = mcel_policyerr_invalid_parameter;
            }
            else if (policy->enforce_monotonic_seq != 0U && state->have_checkpoint != 0U)
            {
                if (checkpointhdr->chk_sequence != (state->checkpoint.chk_sequence + 1U))
                {
                    *perr = mcel_policyerr_sequence_invalid;
                }
            }
            else if (policy->enforce_monotonic_time != 0U && state->have_checkpoint != 0U)
            {
                if (checkpointhdr->timestamp < state->checkpoint.timestamp)
                {
                    *perr = mcel_policyerr_timestamp_invalid;
                }
            }
            else if (policy->enforce_keyid_link != 0U && state->have_checkpoint != 0U)
            {
                if (qsc_intutils_are_equal8(checkpointhdr->keyid, state->checkpoint.keyid, MCEL_CHECKPOINT_KEYID_SIZE) == false)
                {
                    *perr = mcel_policyerr_keyid_mismatch;
                }
            }
        }
    }
    else
    {
        *perr = mcel_policyerr_invalid_parameter;
    }

    return (*perr == mcel_policyerr_none);
}

bool mcel_record_decrypt_payload(uint8_t* output, const uint8_t* ciphertext, size_t ctlen, const uint8_t* ad, size_t adlen, const uint8_t* key, uint8_t* nonce)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(ciphertext != NULL);
    MCEL_ASSERT(ctlen != 0U);
    MCEL_ASSERT(key != NULL);
    MCEL_ASSERT(nonce != NULL);

    bool res;

    res = false;

    if (output != NULL && ciphertext != NULL && ctlen != 0U && key != NULL && nonce != NULL)
    {
        qsc_rcs_state state = { 0U };
        const qsc_rcs_keyparams kp = { .key = key, .keylen = MCEL_RCS256_KEY_SIZE, .nonce = nonce, .info = NULL, .infolen = 0U };

        qsc_rcs_initialize(&state, &kp, false);

        if (adlen != 0U)
        {
            qsc_rcs_set_associated(&state, ad, adlen);
        }

        res = qsc_rcs_transform(&state, output, ciphertext, ctlen);
        qsc_rcs_dispose(&state);
    }

    return res;
}

bool mcel_record_encode_header(uint8_t* output, const mcel_record_header* header)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(header != NULL);

    size_t pos;
    bool res;

    res = false;

    if (output != NULL && header != NULL)
    {
        qsc_memutils_clear(output, MCEL_RECORD_HEADER_ENCODED_SIZE);
        pos = 0U;

        qsc_intutils_be64to8(output + pos, header->sequence);
        pos += sizeof(uint64_t);
        qsc_intutils_be64to8(output + pos, header->timestamp);
        pos += sizeof(uint64_t);
        qsc_intutils_be32to8(output + pos, header->payload_len);
        pos += sizeof(uint32_t);
        qsc_intutils_be32to8(output + pos, header->type);
        pos += sizeof(uint32_t);
        output[pos] = header->flags;
        pos += sizeof(uint8_t);
        output[pos] = header->version;
        pos += sizeof(uint8_t);

        qsc_memutils_copy(output + pos, header->keyid, MCEL_RECORD_KEYID_SIZE);
        pos += MCEL_RECORD_KEYID_SIZE;
        res = (pos == (size_t)MCEL_RECORD_HEADER_ENCODED_SIZE);
    }

    return res;
}

void mcel_record_encrypt_payload(uint8_t* output, const uint8_t* plaintext, size_t ptlen, const uint8_t* ad, size_t adlen, const uint8_t* key, uint8_t* nonce)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(plaintext != NULL);
    MCEL_ASSERT(ptlen != 0U);
    MCEL_ASSERT(key != NULL);
    MCEL_ASSERT(nonce != NULL);

    if (output != NULL && plaintext != NULL && ptlen != 0U && key != NULL && nonce != NULL)
    {
        qsc_rcs_state state;
        const qsc_rcs_keyparams kp = { .key = key, .keylen = MCEL_RCS256_KEY_SIZE, .nonce = nonce, .info = NULL, .infolen = 0U };

        qsc_rcs_initialize(&state, &kp, true);

        if (adlen != 0U)
        {
            qsc_rcs_set_associated(&state, ad, adlen);
        }

        qsc_rcs_transform(&state, output, plaintext, ptlen);
        qsc_rcs_dispose(&state);
    }
}

bool mcel_record_commit(uint8_t* output, const mcel_record_header* header, const uint8_t* pldcommit)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(header != NULL);
    MCEL_ASSERT(pldcommit != NULL);

    bool res;

    res = false;

    if (output != NULL && header != NULL && pldcommit != NULL)
    {
        uint8_t enc[MCEL_RECORD_HEADER_ENCODED_SIZE] = { 0U };
        uint8_t buf[MCEL_RECORD_HEADER_ENCODED_SIZE + MCEL_BLOCK_HASH_SIZE] = { 0U };

        /* canonically encode the header */
        if (mcel_record_encode_header(enc, header) == true)
        {
            /* concatenate enc(header) || pldcommit */
            qsc_memutils_copy(buf, enc, MCEL_RECORD_HEADER_ENCODED_SIZE);
            qsc_memutils_copy(buf + MCEL_RECORD_HEADER_ENCODED_SIZE, pldcommit, MCEL_BLOCK_HASH_SIZE);

            /* compute H(rec, buf) */
            res = mcel_domain_hash_message(output, mcel_domain_record, buf, sizeof(buf));
        }
    }

    return res;
}

bool mcel_store_callbacks_initialize(mcel_store_callbacks* output, const mcel_store_callbacks* input, void* context)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(input != NULL);

    bool res;

    res = false;

    if (output != NULL && input != NULL)
    {
        /* required callbacks */
        MCEL_ASSERT(input->write != NULL);
        MCEL_ASSERT(input->read != NULL);
        MCEL_ASSERT(input->append != NULL);
        MCEL_ASSERT(input->size != NULL);

        if (input->write != NULL && input->read != NULL && input->append != NULL && input->size != NULL)
        {
            qsc_memutils_copy(output, input, sizeof(mcel_store_callbacks));
            output->context = context;

            res = true;
        }
    }

    return res;
}
