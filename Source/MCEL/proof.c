#include "proof.h"
#include "mcel.h"
#include "memutils.h"
#include "intutils.h"
#include "timestamp.h"
#include <stdlib.h>
#include <string.h>


static size_t merkle_tree_depth(size_t leaf_count)
{
    /* calculate the depth of a Merkle tree with given leaf count */
    size_t depth;
    size_t n;
    
    depth = 0U;
    n = leaf_count;
    
    while (n > 1U)
    {
        ++depth;
        n = (n + 1U) / 2U;
    }
    
    return depth;
}


static uint64_t get_sibling_position(uint64_t position)
{
    /* get the sibling position in the Merkle tree */
    uint64_t sibling;
    
    if ((position & 1U) == 1U)
    {
        sibling = position - 1U;
    }
    else
    {
        sibling = position + 1U;
    }
    
    return sibling;
}

bool mcel_proof_generate(mcel_merkle_proof* proof, const uint8_t* reccommits, size_t reccount, uint64_t recposition, const uint8_t* merkleroot)
{
    MCEL_ASSERT(proof != NULL);
    MCEL_ASSERT(reccommits != NULL);
    MCEL_ASSERT(reccount > 0U);
    MCEL_ASSERT(merkleroot != NULL);
    
    uint8_t** levelnodes;
    size_t* levelcounts;
    size_t currdepth;
    size_t maxdepth;
    bool res;
    
    res = false;
    
    if (proof != NULL && reccommits != NULL && reccount > 0U && merkleroot != NULL)
    {
        if (recposition < reccount)
        {
            qsc_memutils_clear((uint8_t*)proof, sizeof(mcel_merkle_proof));
            maxdepth = merkle_tree_depth(reccount);
            
            if (maxdepth <= MCEL_MERKLE_PROOF_HASHES_MAX)
            {
                /* allocate path storage */
                proof->pathhashes = (uint8_t**)qsc_memutils_malloc(maxdepth * sizeof(uint8_t*));
                proof->pathdirections = (uint8_t*)qsc_memutils_malloc(maxdepth * sizeof(uint8_t));

                if (proof->pathhashes != NULL && proof->pathdirections != NULL)
                {
                    /* initialize path arrays */
                    for (size_t i = 0U; i < maxdepth; ++i)
                    {
                        proof->pathhashes[i] = NULL;
                    }

                    /* allocate temporary storage for tree levels */
                    levelnodes = (uint8_t**)qsc_memutils_malloc((maxdepth + 1U) * sizeof(uint8_t*));
                    levelcounts = (size_t*)qsc_memutils_malloc((maxdepth + 1U) * sizeof(size_t));

                    if (levelnodes != NULL && levelcounts != NULL)
                    {
                        /* initialize leaf level */
                        levelcounts[0U] = reccount;
                        levelnodes[0U] = (uint8_t*)qsc_memutils_malloc(reccount * MCEL_BLOCK_HASH_SIZE);

                        if (levelnodes[0U] != NULL)
                        {
                            qsc_memutils_copy(levelnodes[0U], reccommits, reccount * MCEL_BLOCK_HASH_SIZE);

                            /* copy target record hash */
                            qsc_memutils_copy(proof->recordhash, reccommits + (recposition * MCEL_BLOCK_HASH_SIZE), MCEL_BLOCK_HASH_SIZE);

                            /* build tree and collect proof path */
                            currdepth = 0U;
                            res = true;

                            while (levelcounts[currdepth] > 1U && res == true)
                            {
                                size_t parcount;
                                uint64_t posatlevel;
                                uint64_t siblingpos;
                                bool isright;

                                parcount = (levelcounts[currdepth] + 1U) / 2U;
                                levelnodes[currdepth + 1U] = (uint8_t*)qsc_memutils_malloc(parcount * MCEL_BLOCK_HASH_SIZE);

                                if (levelnodes[currdepth + 1U] == NULL)
                                {
                                    res = false;
                                    break;
                                }

                                levelcounts[currdepth + 1U] = parcount;

                                /* Compute position at this level */
                                posatlevel = recposition >> currdepth;
                                siblingpos = get_sibling_position(posatlevel);
                                isright = ((posatlevel & 1U) == 1U);

                                /* allocate and copy sibling hash */
                                proof->pathhashes[currdepth] = (uint8_t*)qsc_memutils_malloc(MCEL_BLOCK_HASH_SIZE);

                                if (proof->pathhashes[currdepth] == NULL)
                                {
                                    res = false;
                                    break;
                                }

                                if (siblingpos < levelcounts[currdepth])
                                {
                                    qsc_memutils_copy(proof->pathhashes[currdepth], levelnodes[currdepth] + (siblingpos * MCEL_BLOCK_HASH_SIZE), MCEL_BLOCK_HASH_SIZE);
                                }
                                else
                                {
                                    /* No sibling, use self */
                                    qsc_memutils_copy(proof->pathhashes[currdepth], levelnodes[currdepth] + (posatlevel * MCEL_BLOCK_HASH_SIZE), MCEL_BLOCK_HASH_SIZE);
                                }

                                proof->pathdirections[currdepth] = isright ? 1U : 0U;

                                /* build parent level */
                                for (size_t i = 0U; i < parcount; ++i)
                                {
                                    const uint8_t* left;
                                    const uint8_t* right;

                                    left = levelnodes[currdepth] + ((i * 2U) * MCEL_BLOCK_HASH_SIZE);

                                    if ((i * 2U + 1U) < levelcounts[currdepth])
                                    {
                                        right = levelnodes[currdepth] + (((i * 2U) + 1U) * MCEL_BLOCK_HASH_SIZE);
                                    }
                                    else
                                    {
                                        right = left;
                                    }

                                    if (mcel_merkle_node_hash(levelnodes[currdepth + 1U] + (i * MCEL_BLOCK_HASH_SIZE), left, right) == false)
                                    {
                                        res = false;
                                        break;
                                    }
                                }

                                ++currdepth;
                            }

                            if (res == true)
                            {
                                /* copy final root */
                                qsc_memutils_copy(proof->merkleroot, levelnodes[currdepth], MCEL_BLOCK_HASH_SIZE);

                                /* verify root matches expected */
                                if (qsc_memutils_are_equal(proof->merkleroot, merkleroot, MCEL_BLOCK_HASH_SIZE) == false)
                                {
                                    res = false;
                                }
                                else
                                {
                                    proof->pathlength = currdepth;
                                    proof->ledgerrecordcount = reccount;
                                    proof->recordposition = recposition;
                                    proof->prooftimestamp = qsc_timestamp_epochtime_seconds();
                                    proof->version = MCEL_PROOF_VERSION;
                                }
                            }
                        }

                        /* free temporary level storage */
                        for (size_t i = 0U; i <= maxdepth; ++i)
                        {
                            if (levelnodes[i] != NULL)
                            {
                                qsc_memutils_alloc_free(levelnodes[i]);
                            }
                        }

                        qsc_memutils_alloc_free(levelnodes);
                        qsc_memutils_alloc_free(levelcounts);
                    }
                }
            }
            
            if (res == false)
            {
                mcel_proof_dispose(proof);
            }
        }
    }
    
    return res;
}

bool mcel_proof_verify(const mcel_merkle_proof* proof, const uint8_t* exproot, uint64_t exprecordcount)
{
    MCEL_ASSERT(proof != NULL);
    MCEL_ASSERT(exproot != NULL);

    bool res;

    res = false;

    if (proof != NULL && exproot != NULL)
    {
        uint8_t comphash[MCEL_BLOCK_HASH_SIZE] = { 0U };
        uint64_t position;

        /* verify proof metadata - reject if any check fails */
        if (proof->ledgerrecordcount == exprecordcount &&
            proof->recordposition < proof->ledgerrecordcount &&
            proof->version == MCEL_PROOF_VERSION)
        {
            /* start with record hash */
            qsc_memutils_copy(comphash, proof->recordhash, MCEL_BLOCK_HASH_SIZE);
            position = proof->recordposition;

            /* compute root by ascending the tree */
            res = true;

            for (size_t i = 0U; i < proof->pathlength; ++i)
            {
                uint8_t nodehash[MCEL_BLOCK_HASH_SIZE] = { 0U };
                const uint8_t* left;
                const uint8_t* right;
                bool isright;

                isright = (proof->pathdirections[i] != 0U);

                if (isright == true)
                {
                    left = proof->pathhashes[i];
                    right = comphash;
                }
                else
                {
                    left = comphash;
                    right = proof->pathhashes[i];
                }

                if (mcel_merkle_node_hash(nodehash, left, right) == false)
                {
                    res = false;
                    break;
                }

                qsc_memutils_copy(comphash, nodehash, MCEL_BLOCK_HASH_SIZE);
                position >>= 1;
            }
        }

        /* verify computed root matches expected */
        if (res == true)
        {
            res = qsc_memutils_are_equal(comphash, exproot, MCEL_BLOCK_HASH_SIZE);
        }
    }

    return res;
}

bool mcel_proof_serialize(uint8_t* output, size_t outlen, const mcel_merkle_proof* proof, size_t* written)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(outlen > 0U);
    MCEL_ASSERT(proof != NULL);
    MCEL_ASSERT(written != NULL);
    
    bool res;
    
    res = false;
    
    if (output != NULL && outlen > 0U && proof != NULL && written != NULL)
    {
        size_t reqsize;
        size_t pos;
        
        reqsize = mcel_proof_serialized_size(proof->pathlength);
        
        if (reqsize != 0U && outlen >= reqsize)
        {
            pos = 0U;

            /* write version */
            output[pos] = proof->version;
            pos += sizeof(uint8_t);
            /* write path length */
            output[pos] = (uint8_t)proof->pathlength;
            pos += sizeof(uint8_t);
            /* write record position (8 bytes, big-endian) */
            qsc_intutils_be64to8(output + pos, proof->recordposition);
            pos += sizeof(uint64_t);
            /* write ledger record count (8 bytes, big-endian) */
            qsc_intutils_be64to8(output + pos, proof->ledgerrecordcount);
            pos += sizeof(uint64_t);
            /* write proof timestamp (8 bytes, big-endian) */
            qsc_intutils_be64to8(output + pos, proof->prooftimestamp);
            pos += sizeof(uint64_t);
            /* write record hash */
            qsc_memutils_copy(output + pos, proof->recordhash, MCEL_BLOCK_HASH_SIZE);
            pos += MCEL_BLOCK_HASH_SIZE;
            /* write merkle root */
            qsc_memutils_copy(output + pos, proof->merkleroot, MCEL_BLOCK_HASH_SIZE);
            pos += MCEL_BLOCK_HASH_SIZE;

            /* write path hashes and directions */
            for (size_t i = 0U; i < proof->pathlength; ++i)
            {
                qsc_memutils_copy(output + pos, proof->pathhashes[i], MCEL_BLOCK_HASH_SIZE);
                pos += MCEL_BLOCK_HASH_SIZE;
            }

            /* write direction bits (packed into bytes) */
            for (size_t i = 0U; i < proof->pathlength; ++i)
            {
                output[pos] = proof->pathdirections[i];
                pos += 1U;
            }

            *written = pos;
            res = true;
        }
    }
    
    return res;
}

bool mcel_proof_deserialize(mcel_merkle_proof* proof, const uint8_t* input, size_t inplen)
{
    MCEL_ASSERT(proof != NULL);
    MCEL_ASSERT(input != NULL);
    MCEL_ASSERT(inplen > 0U);
    
    bool res;
    
    res = false;
    
    if (proof != NULL && input != NULL && inplen > 0U)
    {
        size_t pos;
        size_t path_length;
        
        if (inplen >= MCEL_PROOF_HEADER_SIZE)
        {
            qsc_memutils_clear((uint8_t*)proof, sizeof(mcel_merkle_proof));

            pos = 0U;

            /* read version */
            proof->version = input[pos];
            pos += sizeof(uint8_t);

            if (proof->version != MCEL_PROOF_VERSION)
            {
                return false;
            }

            /* read path length */
            path_length = input[pos];
            pos += sizeof(uint8_t);

            if (path_length > MCEL_MERKLE_PROOF_HASHES_MAX)
            {
                return false;
            }

            /* read record position */
            proof->recordposition = qsc_intutils_be8to64(input + pos);
            pos += sizeof(uint64_t);
            /* read ledger record count */
            proof->ledgerrecordcount = qsc_intutils_be8to64(input + pos);
            pos += sizeof(uint64_t);
            /* read proof timestamp */
            proof->prooftimestamp = qsc_intutils_be8to64(input + pos);
            pos += sizeof(uint64_t);
            /* read record hash */
            qsc_memutils_copy(proof->recordhash, input + pos, MCEL_BLOCK_HASH_SIZE);
            pos += MCEL_BLOCK_HASH_SIZE;
            /* read merkle root */
            qsc_memutils_copy(proof->merkleroot, input + pos, MCEL_BLOCK_HASH_SIZE);
            pos += MCEL_BLOCK_HASH_SIZE;

            /* verify remaining input length */
            if (inplen < pos + (path_length * MCEL_BLOCK_HASH_SIZE) + path_length)
            {
                return false;
            }

            /* allocate path arrays */
            proof->pathhashes = (uint8_t**)qsc_memutils_malloc(path_length * sizeof(uint8_t*));
            proof->pathdirections = (uint8_t*)qsc_memutils_malloc(path_length * sizeof(uint8_t));

            if (proof->pathhashes != NULL && proof->pathdirections != NULL)
            {
                /* initialize hash pointers */
                for (size_t i = 0U; i < path_length; ++i)
                {
                    proof->pathhashes[i] = NULL;
                }

                /* read path hashes */
                for (size_t i = 0U; i < path_length; ++i)
                {
                    proof->pathhashes[i] = (uint8_t*)qsc_memutils_malloc(MCEL_BLOCK_HASH_SIZE);

                    if (proof->pathhashes[i] == NULL)
                    {
                        mcel_proof_dispose(proof);
                        return false;
                    }

                    qsc_memutils_copy(proof->pathhashes[i], input + pos, MCEL_BLOCK_HASH_SIZE);
                    pos += MCEL_BLOCK_HASH_SIZE;
                }

                /* read direction bits */
                for (size_t i = 0U; i < path_length; ++i)
                {
                    proof->pathdirections[i] = input[pos];
                    pos += sizeof(uint8_t);
                }

                proof->pathlength = path_length;
                res = true;
            }
            else
            {
                mcel_proof_dispose(proof);
            }
        }
    }
    
    return res;
}

size_t mcel_proof_serialized_size(size_t pathlen)
{
    size_t size;
    
    size = 0U;
    
    if (pathlen <= MCEL_MERKLE_PROOF_HASHES_MAX)
    {
        size = MCEL_PROOF_HEADER_SIZE + (pathlen * MCEL_BLOCK_HASH_SIZE) + pathlen;
    }
    
    return size;
}

void mcel_proof_dispose(mcel_merkle_proof* proof)
{
    if (proof != NULL)
    {
        if (proof->pathhashes != NULL)
        {
            for (size_t i = 0U; i < proof->pathlength; ++i)
            {
                if (proof->pathhashes[i] != NULL)
                {
                    qsc_memutils_alloc_free(proof->pathhashes[i]);
                }
            }
            
            qsc_memutils_alloc_free(proof->pathhashes);
        }
        
        if (proof->pathdirections != NULL)
        {
            qsc_memutils_alloc_free(proof->pathdirections);
        }
        
        qsc_memutils_clear((uint8_t*)proof, sizeof(mcel_merkle_proof));
    }
}
