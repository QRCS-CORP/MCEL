#include "search.h"
#include "memutils.h"
#include "intutils.h"

static size_t extract_key_sequence(const void* recheader, const uint8_t* recpayload, size_t payloadlen, uint8_t*** keysout, size_t** keylensout)
{
    /* extract sequence number from record header for primary index */
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

        if (keys != NULL)
        {
            lens = (size_t*)qsc_memutils_malloc(sizeof(size_t));

            if (lens != NULL)
            {
                keys[0U] = (uint8_t*)qsc_memutils_malloc(sizeof(uint64_t));

                if (keys[0U] != NULL)
                {
                    qsc_intutils_be64to8(keys[0U], header->sequence);
                    lens[0U] = sizeof(uint64_t);
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

static size_t extract_key_keyid(const void* recheader, const uint8_t* recpayload, size_t payloadlen, uint8_t*** keysout, size_t** keylensout)
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

        if (keys != NULL)
        {
            lens = (size_t*)qsc_memutils_malloc(sizeof(size_t));

            if (lens != NULL)
            {
                keys[0U] = (uint8_t*)qsc_memutils_malloc(MCEL_RECORD_KEYID_SIZE);

                if (keys[0U] != NULL)
                {
                    qsc_memutils_copy(keys[0U], header->keyid, MCEL_RECORD_KEYID_SIZE);
                    lens[0U] = MCEL_RECORD_KEYID_SIZE;
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

static size_t extract_key_type(const void* recheader, const uint8_t* recpayload, size_t payloadlen, uint8_t*** keysout, size_t** keylensout)
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

        if (keys != NULL)
        {
            lens = (size_t*)qsc_memutils_malloc(sizeof(size_t));

            if (lens != NULL)
            {
                keys[0U] = (uint8_t*)qsc_memutils_malloc(sizeof(uint32_t));

                if (keys[0U] != NULL)
                {
                    qsc_intutils_be32to8(keys[0U], header->type);
                    lens[0U] = sizeof(uint32_t);
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

mclr_errors mclr_search_count(const mclr_search_index* idx, const mclr_search_filter* filter, size_t* countout)
{
    MCLR_ASSERT(idx != NULL);
    MCLR_ASSERT(filter != NULL);
    MCLR_ASSERT(countout != NULL);

    const mcel_index* selidx;
    mclr_errors err;

    err = mclr_error_none;

    if (idx != NULL && filter != NULL && countout != NULL)
    {
        /* select optimal index */
        selidx = NULL;

        if (filter->useeventtype == true && (idx->indexflags & MCLR_INDEX_SECONDARY_ACTIVE) != 0U)
        {
            selidx = &idx->secondary;
        }
        else if ((idx->indexflags & MCLR_INDEX_PRIMARY_ACTIVE) != 0U)
        {
            selidx = &idx->primary;
        }

        /* execute count query */
        if (mcel_query_count(countout, idx->recheaders, idx->recordcount, &filter->mcelfilter) == false)
        {
            err = mclr_error_invalid_input;
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }

    return err;
}

mclr_errors mclr_search_execute(mclr_search_index* idx, const mclr_search_filter* filter, mclr_search_result* result)
{
    MCLR_ASSERT(idx != NULL);
    MCLR_ASSERT(filter != NULL);
    MCLR_ASSERT(result != NULL);

    const mcel_index* selidx;
    mclr_errors err;

    err = mclr_error_none;

    if (idx != NULL && filter != NULL && result != NULL)
    {
        qsc_memutils_clear((uint8_t*)result, sizeof(mclr_search_result));

        /* select optimal index based on filter */
        selidx = NULL;

        if (filter->useeventtype == true && (idx->indexflags & MCLR_INDEX_SECONDARY_ACTIVE) != 0U)
        {
            selidx = &idx->secondary;
        }
        else if ((idx->indexflags & MCLR_INDEX_PRIMARY_ACTIVE) != 0U)
        {
            selidx = &idx->primary;
        }

        /* execute query */
        if (mcel_query_execute(&result->mcelresult, idx->recheaders, idx->recpayloads, idx->payloadlens, idx->recordcount, &filter->mcelfilter, selidx) == false)
        {
            err = mclr_error_invalid_input;
        }

        result->sourceindex = idx;
    }
    else
    {
        err = mclr_error_invalid_input;
    }

    return err;
}

void mclr_search_filter_init(mclr_search_filter* filter)
{
    MCLR_ASSERT(filter != NULL);

    if (filter != NULL)
    {
        qsc_memutils_clear((uint8_t*)filter, sizeof(mclr_search_filter));
        mcel_query_filter_init(&filter->mcelfilter);
        filter->eventtype = 0U;
        filter->useeventtype = false;
    }
}

void mclr_search_filter_set_event_type(mclr_search_filter* filter, uint32_t eventtype)
{
    MCLR_ASSERT(filter != NULL);
    
    if (filter != NULL)
    {
        filter->eventtype = eventtype;
        filter->useeventtype = (eventtype != 0U);
        filter->mcelfilter.requiredtype = eventtype;
    }
}

void mclr_search_filter_set_flags(mclr_search_filter* filter, uint8_t reqflags, uint8_t excflags)
{
    MCLR_ASSERT(filter != NULL);
    
    if (filter != NULL)
    {
        filter->mcelfilter.requiredflags = reqflags;
        filter->mcelfilter.excludedflags = excflags;
    }
}

void mclr_search_filter_set_keyid(mclr_search_filter* filter, const uint8_t* keyid)
{
    MCLR_ASSERT(filter != NULL);
    MCLR_ASSERT(keyid != NULL);

    if (filter != NULL && keyid != NULL)
    {
        qsc_memutils_copy(filter->mcelfilter.keyid, keyid, MCEL_RECORD_KEYID_SIZE);
        filter->mcelfilter.filterbykeyid = 1U;
    }
}

void mclr_search_filter_set_ordering(mclr_search_filter* filter, bool reverse_order)
{
    MCLR_ASSERT(filter != NULL);
    
    if (filter != NULL)
    {
        filter->mcelfilter.reverseorder = reverse_order ? 1U : 0U;
    }
}

void mclr_search_filter_set_pagination(mclr_search_filter* filter, size_t offset, size_t limit)
{
    MCLR_ASSERT(filter != NULL);
    
    if (filter != NULL)
    {
        filter->mcelfilter.offset = offset;
        filter->mcelfilter.limit = limit;
    }
}

void mclr_search_filter_set_timerange(mclr_search_filter* filter, uint64_t afterts, uint64_t beforets)
{
    MCLR_ASSERT(filter != NULL);
    
    if (filter != NULL)
    {
        filter->mcelfilter.afterts = afterts;
        filter->mcelfilter.beforets = beforets;
    }
}

void mclr_search_free_records(void** headers, uint8_t** payloads, size_t* payloadlens, size_t count)
{
    if (headers != NULL)
    {
        for (size_t i = 0U; i < count; ++i)
        {
            if (headers[i] != NULL)
            {
                qsc_memutils_alloc_free(headers[i]);
            }
        }

        qsc_memutils_alloc_free(headers);
    }

    if (payloads != NULL)
    {
        for (size_t i = 0U; i < count; ++i)
        {
            if (payloads[i] != NULL)
            {
                qsc_memutils_alloc_free(payloads[i]);
            }
        }

        qsc_memutils_alloc_free(payloads);
    }

    if (payloadlens != NULL)
    {
        qsc_memutils_alloc_free(payloadlens);
    }
}

mclr_errors mclr_search_index_build(mclr_search_index* idx, const void** recheaders, const uint8_t** recpayloads, size_t* payloadlens, size_t reccount)
{
    MCLR_ASSERT(idx != NULL);
    MCLR_ASSERT(recheaders != NULL);
    MCLR_ASSERT(recpayloads != NULL);
    MCLR_ASSERT(payloadlens != NULL);

    mclr_errors err;

    err = mclr_error_none;

    if (idx != NULL && recheaders != NULL)
    {
        /* store record pointers */
        idx->recheaders = recheaders;
        idx->recpayloads = recpayloads;
        idx->payloadlens = payloadlens;
        idx->recordcount = reccount;

        /* build primary index (sequence number) */
        if ((idx->indexflags & MCLR_INDEX_PRIMARY_ACTIVE) != 0U)
        {
            if (mcel_index_rebuild(&idx->primary, recheaders, recpayloads, payloadlens, reccount, extract_key_sequence) == false)
            {
                err = mclr_error_initialization;
            }
        }

        /* build secondary index (event type) */
        if (err == mclr_error_none && (idx->indexflags & MCLR_INDEX_SECONDARY_ACTIVE) != 0U)
        {
            if (mcel_index_rebuild(&idx->secondary, recheaders, recpayloads, payloadlens, reccount, extract_key_type) == false)
            {
                err = mclr_error_initialization;
            }
        }

        /* build tertiary index (keyid) */
        if (err == mclr_error_none && (idx->indexflags & MCLR_INDEX_TERTIARY_ACTIVE) != 0U)
        {
            if (mcel_index_rebuild(&idx->tertiary, recheaders, recpayloads, payloadlens, reccount, extract_key_keyid) == false)
            {
                err = mclr_error_initialization;
            }
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }

    return err;
}

mclr_errors mclr_search_index_create(mclr_search_index* idx, bool createsecondary, bool createtertiary)
{
    MCLR_ASSERT(idx != NULL);

    mclr_errors err;

    err = mclr_error_none;

    if (idx != NULL)
    {
        qsc_memutils_clear((uint8_t*)idx, sizeof(mclr_search_index));

        /* create primary index (always) */
        if (mcel_index_create(&idx->primary, 0U, mcel_index_type_primary) == true)
        {
            idx->indexflags = MCLR_INDEX_PRIMARY_ACTIVE;

            /* create secondary index (event type) if requested */
            if (createsecondary == true)
            {
                if (mcel_index_create(&idx->secondary, 0U, mcel_index_type_secondary) == true)
                {
                    idx->indexflags |= MCLR_INDEX_SECONDARY_ACTIVE;
                }
                else
                {
                    mcel_index_dispose(&idx->primary);
                    err = mclr_error_initialization;
                }
            }

            /* create tertiary index (keyid) if requested */
            if (err == mclr_error_none && createtertiary == true)
            {
                if (mcel_index_create(&idx->tertiary, 0U, mcel_index_type_secondary) == true)
                {
                    idx->indexflags |= MCLR_INDEX_TERTIARY_ACTIVE;
                }
                else
                {
                    mcel_index_dispose(&idx->primary);

                    if ((idx->indexflags & MCLR_INDEX_SECONDARY_ACTIVE) != 0U)
                    {
                        mcel_index_dispose(&idx->secondary);
                    }

                    err = mclr_error_initialization;
                }
            }
        }
        else
        {
            err = mclr_error_initialization;
        }
    }

    return err;
}

void mclr_search_index_dispose(mclr_search_index* idx)
{
    MCLR_ASSERT(idx != NULL);

    if (idx != NULL)
    {
        if ((idx->indexflags & MCLR_INDEX_PRIMARY_ACTIVE) != 0U)
        {
            mcel_index_dispose(&idx->primary);
        }
        
        if ((idx->indexflags & MCLR_INDEX_SECONDARY_ACTIVE) != 0U)
        {
            mcel_index_dispose(&idx->secondary);
        }
        
        if ((idx->indexflags & MCLR_INDEX_TERTIARY_ACTIVE) != 0U)
        {
            mcel_index_dispose(&idx->tertiary);
        }
        
        qsc_memutils_clear((uint8_t*)idx, sizeof(mclr_search_index));
    }
}

mclr_errors mclr_search_index_update(mclr_search_index* idx, const void** newheaders, const uint8_t** newpayloads,
    const size_t* newpayloadlens, size_t newcount)
{
    MCLR_ASSERT(idx != NULL);
    MCLR_ASSERT(newheaders != NULL);

    mclr_errors err;
    err = mclr_error_none;

    if (idx != NULL && newheaders != NULL && newcount != 0U)
    {
        /* update primary index */
        if ((idx->indexflags & MCLR_INDEX_PRIMARY_ACTIVE) != 0U)
        {
            if (mcel_index_update(&idx->primary, newheaders, newpayloads, newpayloadlens, newcount, extract_key_sequence) == false)
            {
                err = mclr_error_initialization;
            }
        }

        /* update secondary index */
        if (err == mclr_error_none && (idx->indexflags & MCLR_INDEX_SECONDARY_ACTIVE) != 0U)
        {
            if (mcel_index_update(&idx->secondary, newheaders, newpayloads, newpayloadlens, newcount, extract_key_type) == false)
            {
                err = mclr_error_initialization;
            }
        }

        /* update tertiary index */
        if (err == mclr_error_none && (idx->indexflags & MCLR_INDEX_TERTIARY_ACTIVE) != 0U)
        {
            if (mcel_index_update(&idx->tertiary, newheaders, newpayloads, newpayloadlens, newcount, extract_key_keyid) == false)
            {
                err = mclr_error_initialization;
            }
        }

        if (err == mclr_error_none)
        {
             /* update record count */
            idx->recordcount += newcount;
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }

    return err;
}

mclr_errors mclr_search_index_verify(const mclr_search_index* idx)
{
    MCLR_ASSERT(idx != NULL);

    mclr_errors err;

    err = mclr_error_none;

    if (idx != NULL)
    {
        /* verify primary index */
        if ((idx->indexflags & MCLR_INDEX_PRIMARY_ACTIVE) != 0U)
        {
            if (mcel_index_verify(&idx->primary, idx->recheaders, idx->recpayloads, idx->payloadlens, idx->recordcount, extract_key_sequence) == false)
            {
                err = mclr_error_integrity_failure;
            }
        }

        /* verify secondary index */
        if (err == mclr_error_none && (idx->indexflags & MCLR_INDEX_SECONDARY_ACTIVE) != 0U)
        {
            if (mcel_index_verify(&idx->secondary, idx->recheaders, idx->recpayloads, idx->payloadlens, idx->recordcount, extract_key_type) == false)
            {
                err = mclr_error_integrity_failure;
            }
        }

        /* verify tertiary index */
        if (err == mclr_error_none && (idx->indexflags & MCLR_INDEX_TERTIARY_ACTIVE) != 0U)
        {
            if (mcel_index_verify(&idx->tertiary, idx->recheaders, idx->recpayloads, idx->payloadlens, idx->recordcount, extract_key_keyid) == false)
            {
                err = mclr_error_integrity_failure;
            }
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }

    return err;
}

mclr_errors mclr_search_load_records(const mclr_logging_state* state, uint64_t startpos, size_t count, void*** headersout, uint8_t*** payloadsout, size_t** payloadlensout)
{
    MCLR_ASSERT(state != NULL);
    MCLR_ASSERT(headersout != NULL);
    MCLR_ASSERT(payloadsout != NULL);
    MCLR_ASSERT(payloadlensout != NULL);

    /* NOTE: This is a placeholder implementation.
     * The actual implementation depends on how records are stored in MCEL.
     * Applications should implement their own record loading based on their storage model.
     *
     * This function would need to:
     * 1. Read records from storage using state->store callbacks
     * 2. Allocate arrays for headers, payloads, and lengths
     * 3. Parse and populate each record
     * 4. Return allocated arrays to caller
     */

    (void)state;
    (void)startpos;
    (void)count;
    (void)headersout;
    (void)payloadsout;
    (void)payloadlensout;

    return mclr_error_invalid_input;
}

void mclr_record_proof_dispose(mclr_record_proof* proof)
{
    MCLR_ASSERT(proof != NULL);

    if (proof != NULL)
    {
        mcel_proof_dispose(&proof->mcelproof);
        qsc_memutils_clear((uint8_t*)proof, sizeof(mclr_record_proof));
    }
}

mclr_errors mclr_record_proof_deserialize(const uint8_t* input, size_t inplen, mclr_record_proof* proof)
{
    MCLR_ASSERT(input != NULL);
    MCLR_ASSERT(proof != NULL);

    size_t mlen;
    size_t pos;
    mclr_errors err;

    err = mclr_error_none;

    if (input != NULL && proof != NULL)
    {
        /* calculate MCEL proof size from header */
        if (inplen >= 2U)
        {
            /* read path length to calculate size */
            mlen = mcel_proof_serialized_size((size_t)input[1]);

            if (inplen >= mlen + sizeof(uint64_t) + sizeof(uint32_t))
            {
                /* deserialize MCEL proof */
                if (mcel_proof_deserialize(&proof->mcelproof, input, mlen) == true)
                {
                    pos = mlen;

                    /* read MCLR metadata */
                    proof->recsequence = qsc_intutils_be8to64(input + pos);
                    pos += sizeof(uint64_t);

                    proof->eventtype = qsc_intutils_be8to32(input + pos);
                    pos += sizeof(uint32_t);
                }
                else
                {
                    err = mclr_error_invalid_input;
                }
            }
            else
            {
                err = mclr_error_invalid_input;
            }
        }
        else
        {
            err = mclr_error_invalid_input;
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }

    return err;
}

mclr_errors mclr_record_proof_serialize(const mclr_record_proof* proof, uint8_t* output, size_t outlen, size_t* writtenout)
{
    MCLR_ASSERT(proof != NULL);
    MCLR_ASSERT(output != NULL);
    MCLR_ASSERT(writtenout != NULL);

    size_t mcel_written;
    size_t pos;
    mclr_errors err;

    err = mclr_error_none;

    if (proof != NULL && output != NULL && writtenout != NULL)
    {
        /* serialize MCEL proof */
        if (mcel_proof_serialize(output, outlen, &proof->mcelproof, &mcel_written) == true)
        {
            pos = mcel_written;

            /* append MCLR metadata */
            if (outlen >= pos + sizeof(uint64_t) + sizeof(uint32_t))
            {
                qsc_intutils_be64to8(output + pos, proof->recsequence);
                pos += sizeof(uint64_t);

                qsc_intutils_be32to8(output + pos, proof->eventtype);
                pos += sizeof(uint32_t);

                *writtenout = pos;
            }
            else
            {
                err = mclr_error_invalid_input;
            }
        }
        else
        {
            err = mclr_error_invalid_input;
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }

    return err;
}

size_t mclr_record_proof_serialized_size(const mclr_record_proof* proof)
{
    MCLR_ASSERT(proof != NULL);

    size_t plen;

    plen = 0U;

    if (proof != NULL)
    {
        plen = mcel_proof_serialized_size(proof->mcelproof.pathlength);

        if (plen > 0U)
        {
            plen += sizeof(uint64_t) + sizeof(uint32_t);
        }
    }

    return plen;
}

mclr_errors mclr_record_proof_verify(const mclr_record_proof* proof, const uint8_t* exproot, uint64_t expreccount)
{
    MCLR_ASSERT(proof != NULL);
    MCLR_ASSERT(exproot != NULL);

    mclr_errors err;

    err = mclr_error_none;

    if (proof != NULL && exproot != NULL)
    {
        if (mcel_proof_verify(&proof->mcelproof, exproot, expreccount) == false)
        {
            err = mclr_error_integrity_failure;
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }

    return err;
}

void mclr_search_result_dispose(mclr_search_result* result)
{
    MCLR_ASSERT(result != NULL);

    if (result != NULL)
    {
        mcel_query_result_dispose(&result->mcelresult);
        qsc_memutils_clear((uint8_t*)result, sizeof(mclr_search_result));
    }
}

mclr_errors mclr_search_result_get_header(const mclr_search_result* result, size_t resindex, const mcel_record_header** headerout)
{
    MCLR_ASSERT(result != NULL);
    MCLR_ASSERT(headerout != NULL);

    uint64_t recpos;
    mclr_errors err;
    
    err = mclr_error_none;

    if (result != NULL && headerout != NULL)
    {
        if (resindex < result->mcelresult.count)
        {
            recpos = result->mcelresult.recpositions[resindex];

            if (recpos < result->sourceindex->recordcount)
            {
                *headerout = (const mcel_record_header*)result->sourceindex->recheaders[recpos];
            }
            else
            {
                err = mclr_error_invalid_input;
            }
        }
        else
        {
            err = mclr_error_invalid_input;
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }
    
    return err;
}

mclr_errors mclr_search_result_get_payload(const mclr_search_result* result, size_t resindex, const uint8_t** payloadout, size_t* payloadlenout)
{
    MCLR_ASSERT(result != NULL);
    MCLR_ASSERT(payloadout != NULL);
    MCLR_ASSERT(payloadlenout != NULL);

    uint64_t recpos;
    mclr_errors err;

    err = mclr_error_none;

    if (result != NULL && payloadout != NULL && payloadlenout != NULL)
    {
        if (resindex < result->mcelresult.count)
        {
            recpos = result->mcelresult.recpositions[resindex];

            if (recpos < result->sourceindex->recordcount)
            {
                if (result->sourceindex->recpayloads != NULL)
                {
                    *payloadout = result->sourceindex->recpayloads[recpos];

                    if (result->sourceindex->payloadlens != NULL)
                    {
                        *payloadlenout = result->sourceindex->payloadlens[recpos];
                    }
                    else
                    {
                        *payloadlenout = 0U;
                    }
                }
                else
                {
                    *payloadout = NULL;
                    *payloadlenout = 0U;
                }
            }
            else
            {
                err = mclr_error_invalid_input;
            }
        }
        else
        {
            err = mclr_error_invalid_input;
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }
    
    return err;
}

mclr_errors mclr_search_result_generate_proof(const mclr_search_result* result, size_t resindex, const uint8_t* reccommits, size_t commitcount, const uint8_t* blockroot, mclr_record_proof* proof)
{
    MCLR_ASSERT(result != NULL);
    MCLR_ASSERT(reccommits != NULL);
    MCLR_ASSERT(blockroot != NULL);
    MCLR_ASSERT(proof != NULL);

    uint64_t recpos;
    const mcel_record_header* header;
    mclr_errors err;

    err = mclr_error_none;

    if (result != NULL && reccommits != NULL && blockroot != NULL && proof != NULL)
    {
        if (resindex < result->mcelresult.count)
        {
            recpos = result->mcelresult.recpositions[resindex];

            if (recpos < commitcount)
            {
                /* generate proof */
                if (mcel_proof_generate(&proof->mcelproof, reccommits, commitcount, recpos, blockroot) == true)
                {
                    /* add MCLR metadata */
                    header = (const mcel_record_header*)result->sourceindex->recheaders[recpos];
                    proof->recsequence = header->sequence;
                    proof->eventtype = header->type;
                }
                else
                {
                    err = mclr_error_invalid_input;
                }
            }
            else
            {
                err = mclr_error_invalid_input;
            }
        }
        else
        {
            err = mclr_error_invalid_input;
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }
    
    return err;
}

mclr_errors mclr_search_result_generate_all_proofs(const mclr_search_result* result, const uint8_t* reccommits, size_t commitcount, const uint8_t* blockroot, mclr_record_proof* proofs, size_t proofscapacity)
{
    MCLR_ASSERT(result != NULL);
    MCLR_ASSERT(reccommits != NULL);
    MCLR_ASSERT(blockroot != NULL);
    MCLR_ASSERT(proofs != NULL);

    mclr_errors err;

    err = mclr_error_none;

    if (result != NULL && reccommits != NULL && blockroot != NULL && proofs != NULL)
    {
        if (proofscapacity >= result->mcelresult.count)
        {
            /* generate proof for each result */
            for (size_t i = 0U; i < result->mcelresult.count; ++i)
            {
                if (mclr_search_result_generate_proof(result, i, reccommits, commitcount, blockroot, &proofs[i]) != mclr_error_none)
                {
                    /* clean up previously generated proofs */
                    for (size_t j = 0U; j < i; ++j)
                    {
                        mclr_record_proof_dispose(&proofs[j]);
                    }

                    err = mclr_error_invalid_input;
                    break;
                }
            }
        }
        else
        {
            err = mclr_error_invalid_input;
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }

    return err;
}
