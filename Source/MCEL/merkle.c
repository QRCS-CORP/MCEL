#include "merkle.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

size_t mcel_merkle_consistency_proof_size(size_t oldcount, size_t newcount)
{
    MCEL_ASSERT(oldcount > 0U);
    MCEL_ASSERT(newcount > 0U);
    MCEL_ASSERT(oldcount <= newcount);

    size_t bits;
    size_t m;
    size_t res;

    res = 0U;

    if (oldcount != 0U && newcount != 0U && oldcount <= newcount)
    {
        /* worst case is O(log m) hashes, bounded by 2 * log2(m) + 1 */
        m = newcount;
        bits = 0U;

        while (m > 1U)
        {
            m >>= 1;
            ++bits;
        }

        res = (size_t)MCEL_MERKLE_HASH_SIZE * (2U * bits + 1U);
    }

    return res;
}

bool mcel_merkle_node_hash(uint8_t* output, const uint8_t* left, const uint8_t* right)
{
    uint8_t buf[MCEL_MERKLE_NODE_SIZE] = { 0U };
    bool res;

    qsc_memutils_copy(buf, left, MCEL_MERKLE_HASH_SIZE);
    qsc_memutils_copy(buf + MCEL_MERKLE_HASH_SIZE, right, MCEL_MERKLE_HASH_SIZE);
    res = mcel_domain_hash_message(output, mcel_domain_node, buf, sizeof(buf));

    return res;
}

size_t mcel_merkle_proof_size(size_t count)
{
    MCEL_ASSERT(count > 0U);

    size_t height;
    size_t level;
    size_t nodes;

    level = 0U;

    if (count > 0U)
    {
        nodes = count;
        height = 0U;

        while (nodes > 1U)
        {
            nodes = (nodes + 1U) / 2U;
            ++height;
        }

        /* guard against unreasonable trees */
        MCEL_ASSERT(height <= (size_t)MCEL_MERKLE_PROOF_HASHES_MAX);

        if (height <= (size_t)MCEL_MERKLE_PROOF_HASHES_MAX)
        {
            level = height * (size_t)MCEL_MERKLE_HASH_SIZE;
        }
    }

    return level;
}

bool mcel_merkle_prove_member(uint8_t* proof, size_t prooflen, const uint8_t* leaves, size_t count, size_t index)
{
    MCEL_ASSERT(proof != NULL);
    MCEL_ASSERT(prooflen != 0U);
    MCEL_ASSERT(leaves != NULL);
    MCEL_ASSERT(count > 1U);
    MCEL_ASSERT(index < count);

    bool res;

    res = false;

    if (proof != NULL && prooflen != 0U && leaves != NULL && count > 1U && index < count)
    {
        size_t req;

        req = mcel_merkle_proof_size(count);

        if (req != 0U && prooflen >= req)
        {
            uint8_t* level;
            uint8_t* next;
            size_t idx;
            size_t lcount;
            size_t ncount;
            size_t pos;

            lcount = count;
            idx = index;
            pos = 0;

            level = (uint8_t*)qsc_memutils_malloc(lcount * (size_t)MCEL_MERKLE_HASH_SIZE);

            if (level != NULL)
            {
                qsc_memutils_clear(level, lcount * (size_t)MCEL_MERKLE_HASH_SIZE);
                qsc_memutils_copy(level, leaves, lcount * (size_t)MCEL_MERKLE_HASH_SIZE);

                res = true;

                while (lcount > 1U && res == true)
                {
                    /* sibling selection at this level */
                    size_t sib;

                    if ((idx % 2U) == 0U)
                    {
                        /* right sibling, or duplicate self if missing */
                        sib = (idx + 1U < lcount) ? (idx + 1U) : idx;
                    }
                    else
                    {
                        /* left sibling always exists */
                        sib = idx - 1U;
                    }

                    /* write sibling hash to proof */
                    qsc_memutils_copy(proof + pos, level + (sib * (size_t)MCEL_MERKLE_HASH_SIZE), MCEL_MERKLE_HASH_SIZE);
                    pos += (size_t)MCEL_MERKLE_HASH_SIZE;

                    /* build next level */
                    ncount = (lcount + 1U) / 2U;
                    next = (uint8_t*)qsc_memutils_malloc(ncount * (size_t)MCEL_MERKLE_HASH_SIZE);

                    if (next == NULL)
                    {
                        res = false;
                        break;
                    }

                    for (size_t i = 0; i < ncount; ++i)
                    {
                        const uint8_t* left;
                        const uint8_t* right;

                        left = level + ((i * 2U) * (size_t)MCEL_MERKLE_HASH_SIZE);

                        if ((i * 2U + 1U) < lcount)
                        {
                            right = level + (((i * 2U) + 1U) * (size_t)MCEL_MERKLE_HASH_SIZE);
                        }
                        else
                        {
                            right = left;
                        }

                        res = mcel_merkle_node_hash(next + (i * (size_t)MCEL_MERKLE_HASH_SIZE), left, right);

                        if (res == false)
                        {
                            break;
                        }
                    }

                    qsc_memutils_alloc_free(level);
                    level = next;
                    lcount = ncount;
                    idx /= 2U;
                }

                if (level != NULL)
                {
                    qsc_memutils_alloc_free(level);
                }

                /* pos must equal required proof size */
                if (res == true)
                {
                    res = (pos == req);
                }
            }
        }
    }

    return res;
}

bool mcel_merkle_root(uint8_t* root, const uint8_t* leaves, size_t count)
{
    MCEL_ASSERT(root != NULL);

    bool res;

    res = false;

    if (root != NULL)
    {
        uint8_t* level;
        uint8_t* next;
        size_t lcount;
        size_t ncount;

        if (count != 0)
        {
            if (leaves != NULL)
            {
                lcount = count;

                /* allocate working buffers: lcount and ceil(lcount / 2) hashes */
                level = (uint8_t*)qsc_memutils_malloc(lcount * (size_t)MCEL_MERKLE_HASH_SIZE);

                if (level != NULL)
                {
                    /* copy the leaves into the working level buffer */
                    qsc_memutils_copy(level, leaves, lcount * (size_t)MCEL_MERKLE_HASH_SIZE);
                    res = true;

                    while (lcount > 1)
                    {
                        ncount = (lcount + 1) / 2;
                        next = (uint8_t*)qsc_memutils_malloc(ncount * (size_t)MCEL_MERKLE_HASH_SIZE);

                        if (next != NULL)
                        {
                            /* hash pairs left-to-right, duplicate the last node if odd */
                            for (size_t i = 0; i < ncount; ++i)
                            {
                                const uint8_t* left;
                                const uint8_t* right;

                                left = level + ((i * 2) * (size_t)MCEL_MERKLE_HASH_SIZE);

                                if ((i * 2 + 1) < lcount)
                                {
                                    right = level + (((i * 2) + 1) * (size_t)MCEL_MERKLE_HASH_SIZE);
                                }
                                else
                                {
                                    right = left;
                                }

                                res = mcel_merkle_node_hash(next + (i * (size_t)MCEL_MERKLE_HASH_SIZE), left, right);

                                if (res == false)
                                {
                                    qsc_memutils_alloc_free(next);
                                    break;
                                }
                            }

                            qsc_memutils_alloc_free(level);

                            if (res == false)
                            {
                                break;
                            }

                            level = next;
                            lcount = ncount;
                        }
                        else
                        {
                            res = false;
                            qsc_memutils_alloc_free(level);
                            break;
                        }
                    }

                    if (res == true)
                    {
                        /* the remaining element is the root */
                        qsc_memutils_copy(root, level, MCEL_MERKLE_HASH_SIZE);
                        qsc_memutils_alloc_free(level);
                    }
                }
            }
        }
        else
        {
            /* an empty block root is a deterministic value */
            qsc_memutils_clear(root, MCEL_MERKLE_HASH_SIZE);
            res = mcel_merkle_root_hash(root, mcel_domain_node);
        }
    }

    return res;
}

bool mcel_merkle_root_hash(uint8_t* output, mcel_domain_types domain)
{
    MCEL_ASSERT(output != NULL);

    bool res;

    res = false;

    if (output != NULL)
    {
        const char* dcust;

        dcust = mcel_domain_to_name(domain);
        qsc_cshake256_compute(output, MCEL_MERKLE_HASH_SIZE, (const uint8_t*)MCEL_DOMAIN_NAME_STRING, sizeof(MCEL_DOMAIN_NAME_STRING) - 1U, NULL, 0U, (const uint8_t*)dcust, MCEL_DOMAIN_STRING_WIDTH - 1U);
        res = true;
    }

    return res;
}

bool mcel_merkle_member_verify(const uint8_t* root, const uint8_t* leaf, const uint8_t* proof, size_t prooflen, size_t count, size_t index)
{
    MCEL_ASSERT(root != NULL);
    MCEL_ASSERT(leaf != NULL);
    MCEL_ASSERT(proof != NULL);
    MCEL_ASSERT(prooflen != 0U);
    MCEL_ASSERT(count > 1U);
    MCEL_ASSERT(index < count);

    bool res;

    res = false;

    if (root != NULL && leaf != NULL && proof != NULL && prooflen != 0U && count > 1U && index < count)
    {
        size_t req;

        req = mcel_merkle_proof_size(count);

        if (req != 0U && prooflen >= req)
        {
            uint8_t acc[MCEL_MERKLE_HASH_SIZE] = { 0U };
            uint8_t tmp[MCEL_MERKLE_HASH_SIZE] = { 0U };
            size_t idx;
            size_t nodes;
            size_t pos;

            qsc_memutils_copy(acc, leaf, MCEL_MERKLE_HASH_SIZE);

            idx = index;
            nodes = count;
            pos = 0U;

            res = true;

            while (nodes > 1U && res == true)
            {
                const uint8_t* sib;

                /* proof provides the sibling hash at this level */
                sib = proof + pos;
                pos += (size_t)MCEL_MERKLE_HASH_SIZE;

                if ((idx % 2U) == 0U)
                {
                    /* current is left child, sibling is right or duplicated */
                    res = mcel_merkle_node_hash(tmp, acc, sib);
                }
                else
                {
                    /* current is right child, sibling is left */
                    res = mcel_merkle_node_hash(tmp, sib, acc);
                }

                if (res == true)
                {
                    qsc_memutils_copy(acc, tmp, MCEL_MERKLE_HASH_SIZE);
                }

                /* advance to next level */
                idx /= 2U;
                nodes = (nodes + 1U) / 2U;
            }

            if (res == true)
            {
                /* proof must have been consumed exactly */
                res = (pos == req);

                if (res == true)
                {
                    res = (qsc_intutils_verify(acc, root, MCEL_MERKLE_HASH_SIZE) == 0U);
                }
            }
        }
    }

    return res;
}
