#include "index.h"
#include "memutils.h"
#include "sha3.h"

#define FNV1A_32_INIT 2166136261U
#define FNV1A_32_PRIME 16777619U

static uint32_t index_hash_key(const uint8_t* key, size_t keylen, size_t bucket_count)
{
    /* internal hash function for index keys */
    uint32_t hash;
    
    hash = 0U;
    
    if (key != NULL && keylen > 0U && bucket_count > 0U)
    {
        /* Simple FNV-1a hash */
        hash = FNV1A_32_INIT;
        
        for (size_t i = 0; i < keylen; ++i)
        {
            hash ^= key[i];
            hash *= FNV1A_32_PRIME;
        }
        
        hash %= bucket_count;
    }
    
    return hash;
}


static bool index_keys_equal(const uint8_t* key1, size_t len1, const uint8_t* key2, size_t len2)
{
    /* compare two keys for equality */
    bool res;
    
    res = false;
    
    if (key1 != NULL && key2 != NULL && len1 == len2)
    {
        res = qsc_memutils_are_equal(key1, key2, len1);
    }
    
    return res;
}


static bool index_resize(mcel_index* index, size_t newbucketcount)
{
    /* resize index when load factor exceeds threshold */
    MCEL_ASSERT(index != NULL);
    MCEL_ASSERT(newbucketcount > 0U);
    
    mcel_index_entry** newbuckets;
    bool res;
    
    res = false;
    
    if (index != NULL && newbucketcount > 0U)
    {
        newbuckets = (mcel_index_entry**)qsc_memutils_malloc(newbucketcount * sizeof(mcel_index_entry*));
        
        if (newbuckets != NULL)
        {
            qsc_memutils_clear((uint8_t*)newbuckets, newbucketcount * sizeof(mcel_index_entry*));
            
            /* rehash all entries into new buckets */
            for (size_t i = 0U; i < index->bucketcount; ++i)
            {
                mcel_index_entry* entry;
                
                entry = index->buckets[i];
                
                while (entry != NULL)
                {
                    mcel_index_entry* next;
                    uint32_t newhash;
                    
                    next = entry->next;
                    newhash = index_hash_key(entry->key, entry->keylen, newbucketcount);
                    
                    /* insert at head of new bucket chain */
                    entry->next = newbuckets[newhash];
                    newbuckets[newhash] = entry;
                    
                    entry = next;
                }
            }
            
            /* Replace old buckets */
            qsc_memutils_alloc_free(index->buckets);
            index->buckets = newbuckets;
            index->bucketcount = newbucketcount;
            res = true;
        }
    }
    
    return res;
}

bool mcel_index_create(mcel_index* index, size_t bucket_count, uint8_t indextype)
{
    MCEL_ASSERT(index != NULL);
    
    bool res;
    
    res = false;
    
    if (index != NULL)
    {
        qsc_memutils_clear((uint8_t*)index, sizeof(mcel_index));
        
        if (bucket_count == 0U)
        {
            bucket_count = MCEL_INDEX_DEFAULT_BUCKETS;
        }
        
        index->buckets = (mcel_index_entry**)qsc_memutils_malloc(bucket_count * sizeof(mcel_index_entry*));
        
        if (index->buckets != NULL)
        {
            qsc_memutils_clear((uint8_t*)index->buckets, bucket_count * sizeof(mcel_index_entry*));
            index->bucketcount = bucket_count;
            index->entrycount = 0U;
            index->indexedthrough = 0U;
            index->indextype = indextype;
            index->buildtimestamp = 0U;
            qsc_memutils_clear(index->indexhash, MCEL_INDEX_HASH_SIZE);
            res = true;
        }
    }
    
    return res;
}

bool mcel_index_insert(mcel_index* index, const uint8_t* key, size_t keylen, uint64_t recordpos)
{
    MCEL_ASSERT(index != NULL);
    MCEL_ASSERT(key != NULL);
    MCEL_ASSERT(keylen > 0U);
    
    bool res;
    
    res = false;
    
    if (index != NULL && key != NULL && keylen > 0U)
    {
        uint32_t hash;
        mcel_index_entry* entry;
        double loadfactor;
        
        if (index->bucketcount != 0U)
        {
            /* check if resize needed */
            loadfactor = (double)index->entrycount / (double)index->bucketcount;

            if (loadfactor > MCEL_INDEX_LOAD_FACTOR_MAX)
            {
                if (index_resize(index, index->bucketcount * 2U) == false)
                {
                    return false;
                }
            }

            hash = index_hash_key(key, keylen, index->bucketcount);

            /* for primary indices, check if key already exists */
            if (index->indextype == mcel_index_type_primary)
            {
                entry = index->buckets[hash];

                while (entry != NULL)
                {
                    if (index_keys_equal(entry->key, entry->keylen, key, keylen) == true)
                    {
                        /* key already exists in primary index */
                        return false;
                    }

                    entry = entry->next;
                }
            }

            /* create new entry */
            entry = (mcel_index_entry*)qsc_memutils_malloc(sizeof(mcel_index_entry));

            if (entry != NULL)
            {
                entry->key = (uint8_t*)qsc_memutils_malloc(keylen);

                if (entry->key != NULL)
                {
                    qsc_memutils_copy(entry->key, key, keylen);
                    entry->keylen = keylen;
                    entry->recordpos = recordpos;

                    /* Insert at head of chain */
                    entry->next = index->buckets[hash];
                    index->buckets[hash] = entry;
                    ++index->entrycount;

                    res = true;
                }
                else
                {
                    qsc_memutils_alloc_free(entry);
                }
            }
        }
    }
    
    return res;
}

bool mcel_index_lookup(const mcel_index* index, const uint8_t* key, size_t keylen, uint64_t** positionsout, size_t* countout)
{
    MCEL_ASSERT(index != NULL);
    MCEL_ASSERT(key != NULL);
    MCEL_ASSERT(keylen > 0U);
    MCEL_ASSERT(positionsout != NULL);
    MCEL_ASSERT(countout != NULL);
    
    bool res;
    
    res = false;
    
    if (index != NULL && key != NULL && keylen > 0U && positionsout != NULL && countout != NULL)
    {
        uint32_t hash;
        mcel_index_entry* entry;
        size_t match_count;
        uint64_t* positions;
        size_t alloc_size;
        
        *positionsout = NULL;
        *countout = 0U;
        
        hash = index_hash_key(key, keylen, index->bucketcount);
        
        /* First pass: count matches */
        match_count = 0U;
        entry = index->buckets[hash];
        
        while (entry != NULL)
        {
            if (index_keys_equal(entry->key, entry->keylen, key, keylen) == true)
            {
                ++match_count;
            }
            
            entry = entry->next;
        }
        
        if (match_count == 0U)
        {
            /* no matches found, but operation succeeded */
            res = true;
        }
        else
        {
            /* second pass: collect positions */
            alloc_size = match_count * sizeof(uint64_t);
            positions = (uint64_t*)qsc_memutils_malloc(alloc_size);
            
            if (positions != NULL)
            {
                size_t idx;
                
                idx = 0U;
                entry = index->buckets[hash];
                
                while (entry != NULL && idx < match_count)
                {
                    if (index_keys_equal(entry->key, entry->keylen, key, keylen) == true)
                    {
                        positions[idx] = entry->recordpos;
                        ++idx;
                    }
                    
                    entry = entry->next;
                }
                
                *positionsout = positions;
                *countout = match_count;
                res = true;
            }
        }
    }
    
    return res;
}

bool mcel_index_rebuild(mcel_index* index, const void** recheaders, const uint8_t** recpayloads, const size_t* payloadlens, 
    size_t reccount, mcel_index_key_extractor extractor)
{
    MCEL_ASSERT(index != NULL);
    MCEL_ASSERT(recheaders != NULL);
    MCEL_ASSERT(extractor != NULL);

    bool res;
    size_t saved_bucketcount;
    uint8_t saved_indextype;

    res = false;

    if (index != NULL && recheaders != NULL && extractor != NULL)
    {
        /* Save parameters before disposal */
        saved_bucketcount = index->bucketcount;
        saved_indextype = index->indextype;

        /* Clear existing entries */
        mcel_index_dispose(index);

        /* Recreate with saved parameters */
        if (mcel_index_create(index, saved_bucketcount, saved_indextype) == true)
        {
            res = mcel_index_update(index, recheaders, recpayloads, payloadlens, reccount, extractor);
        }
    }

    return res;
}

bool mcel_index_update(mcel_index* index, const void** recheaders, const uint8_t** recpayloads, const size_t* payloadlens, 
    size_t record_count, mcel_index_key_extractor extractor)
{
    MCEL_ASSERT(index != NULL);
    MCEL_ASSERT(recheaders != NULL);
    MCEL_ASSERT(extractor != NULL);
    
    bool res;
    
    res = false;
    
    if (index != NULL && recheaders != NULL && extractor != NULL)
    {
        res = true;
        
        for (size_t i = 0; i < record_count && res == true; ++i)
        {
            uint8_t** keys;
            size_t* keylens;
            size_t keycount;
            const uint8_t* payload;
            size_t payloadlen;
            
            keys = NULL;
            keylens = NULL;
            payload = (recpayloads != NULL) ? recpayloads[i] : NULL;
            payloadlen = (payloadlens != NULL) ? payloadlens[i] : 0U;
            
            /* extract keys from this record */
            keycount = extractor(recheaders[i], payload, payloadlen, &keys, &keylens);
            
            /* insert each extracted key */
            for (size_t j = 0U; j < keycount; ++j)
            {
                if (mcel_index_insert(index, keys[j], keylens[j], i) == false)
                {
                    res = false;
                    break;
                }
            }
            
            /* free extractor allocations */
            if (keys != NULL)
            {
                for (size_t j = 0U; j < keycount; ++j)
                {
                    if (keys[j] != NULL)
                    {
                        qsc_memutils_alloc_free(keys[j]);
                    }
                }
                
                qsc_memutils_alloc_free(keys);
            }
            
            if (keylens != NULL)
            {
                qsc_memutils_alloc_free(keylens);
            }
        }
        
        if (res == true)
        {
            if (record_count > 0U)
            {
                index->indexedthrough = record_count - 1U;
            }
            else
            {
                index->indexedthrough = 0U;
            }
        }
    }
    
    return res;
}

bool mcel_index_compute_hash(const mcel_index* index, uint8_t* output)
{
    MCEL_ASSERT(index != NULL);
    MCEL_ASSERT(output != NULL);
    
    bool res;
    
    res = false;
    
    if (index != NULL && output != NULL)
    {
        qsc_keccak_state kstate = { 0U };
        
        qsc_keccak_initialize_state(&kstate);
        
        /* Hash index metadata */
        qsc_sha3_update(&kstate, QSC_KECCAK_256_RATE, (const uint8_t*)&index->bucketcount, sizeof(index->bucketcount));
        qsc_sha3_update(&kstate, QSC_KECCAK_256_RATE, (const uint8_t*)&index->entrycount, sizeof(index->entrycount));
        qsc_sha3_update(&kstate, QSC_KECCAK_256_RATE, (const uint8_t*)&index->indexedthrough, sizeof(index->indexedthrough));
        qsc_sha3_update(&kstate, QSC_KECCAK_256_RATE, &index->indextype, sizeof(index->indextype));
        
        /* Hash all entries in bucket order */
        for (size_t i = 0U; i < index->bucketcount; ++i)
        {
            mcel_index_entry* entry;
            
            entry = index->buckets[i];
            
            while (entry != NULL)
            {
                qsc_sha3_update(&kstate, QSC_KECCAK_256_RATE, entry->key, entry->keylen);
                qsc_sha3_update(&kstate, QSC_KECCAK_256_RATE, (const uint8_t*)&entry->recordpos, sizeof(entry->recordpos));
                entry = entry->next;
            }
        }
        
        qsc_sha3_finalize(&kstate, QSC_KECCAK_256_RATE, output);
        res = true;
    }
    
    return res;
}

bool mcel_index_verify(const mcel_index* index, const void** recheaders, const uint8_t** recpayloads, const size_t* payloadlens, 
    size_t reccount, mcel_index_key_extractor extractor)
{
    MCEL_ASSERT(index != NULL);
    MCEL_ASSERT(recheaders != NULL);
    MCEL_ASSERT(extractor != NULL);
    
    mcel_index rebuild;
    uint8_t hash1[MCEL_INDEX_HASH_SIZE] = { 0U };
    uint8_t hash2[MCEL_INDEX_HASH_SIZE] = { 0U };
    bool res;
    
    res = false;
    
    if (index != NULL && recheaders != NULL && extractor != NULL)
    {
        /* rebuild index from source records */
        if (mcel_index_create(&rebuild, index->bucketcount, index->indextype) == true)
        {
            if (mcel_index_update(&rebuild, recheaders, recpayloads, payloadlens, reccount, extractor) == true)
            {
                /* compare hashes */
                if (mcel_index_compute_hash(index, hash1) == true && 
                    mcel_index_compute_hash(&rebuild, hash2) == true)
                {
                    res = qsc_memutils_are_equal(hash1, hash2, MCEL_INDEX_HASH_SIZE);
                }
            }
            
            mcel_index_dispose(&rebuild);
        }
    }
    
    return res;
}

void mcel_index_dispose(mcel_index* index)
{
    if (index != NULL)
    {
        if (index->buckets != NULL)
        {
            for (size_t i = 0; i < index->bucketcount; ++i)
            {
                mcel_index_entry* entry;
                
                entry = index->buckets[i];
                
                while (entry != NULL)
                {
                    mcel_index_entry* next;
                    
                    next = entry->next;
                    
                    if (entry->key != NULL)
                    {
                        qsc_memutils_alloc_free(entry->key);
                    }
                    
                    qsc_memutils_alloc_free(entry);
                    entry = next;
                }
            }
            
            qsc_memutils_alloc_free(index->buckets);
        }
        
        qsc_memutils_clear((uint8_t*)index, sizeof(mcel_index));
    }
}
