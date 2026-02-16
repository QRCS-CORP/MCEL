#include "query.h"
#include "memutils.h"
#include "timestamp.h"
#include <stdlib.h>
#include <string.h>

static bool record_matches_filter(const mcel_record_header* header, const mcel_query_filter* filter)
{
    /* check if a record matches the filter criteria */
    MCEL_ASSERT(header != NULL);
    MCEL_ASSERT(filter != NULL);
    
    bool matches;
    
    matches = true;
    
    if (header != NULL && filter != NULL)
    {
        /* check timestamp range */
        if (filter->afterts != 0U && header->timestamp <= filter->afterts)
        {
            matches = false;
        }
        
        if (matches == true && filter->beforets != 0U && header->timestamp >= filter->beforets)
        {
            matches = false;
        }
        
        /* check record type */
        if (matches == true && filter->requiredtype != 0U && header->type != filter->requiredtype)
        {
            matches = false;
        }
        
        /* check required flags */
        if (matches == true && filter->requiredflags != 0U)
        {
            if ((header->flags & filter->requiredflags) != filter->requiredflags)
            {
                matches = false;
            }
        }
        
        /* check excluded flags */
        if (matches == true && filter->excludedflags != 0U)
        {
            if ((header->flags & filter->excludedflags) != 0U)
            {
                matches = false;
            }
        }
        
        /* check keyid */
        if (matches == true && filter->filterbykeyid != 0U)
        {
            if (qsc_memutils_are_equal(header->keyid, filter->keyid, MCEL_RECORD_KEYID_SIZE) == false)
            {
                matches = false;
            }
        }
    }
    
    return matches;
}


static mcel_query_strategy select_query_strategy(const mcel_query_filter* filter, const mcel_index* index)
{
    /* select optimal query strategy based on filter and available indices */
    mcel_query_strategy strategy;
    
    strategy = mcel_query_strategy_ledger_scan;
    
    if (filter != NULL)
    {
        /* if index exists and filter has search key, use index lookup */
        if (index != NULL && filter->searchkey != NULL && filter->searchkeylen > 0U)
        {
            strategy = mcel_query_strategy_index_lookup;
        }

        /* if index exists and filter is selective, scan index */
        else if (index != NULL && (filter->requiredtype != 0U || filter->requiredflags != 0U))
        {
            strategy = mcel_query_strategy_index_scan;
        }
    }
    
    return strategy;
}


static bool execute_index_lookup(mcel_query_result* result, const void** recheaders, size_t reccount, const mcel_query_filter* filter, const mcel_index* index)
{
    /* execute query using index lookup strategy */
    MCEL_ASSERT(result != NULL);
    MCEL_ASSERT(recheaders != NULL);
    MCEL_ASSERT(filter != NULL);
    MCEL_ASSERT(index != NULL);
    
    uint64_t* candpositions;
    uint64_t* filtpositions;
    size_t candcount;
    size_t filtcount;
    bool res;
    
    res = false;
    candpositions = NULL;
    filtpositions = NULL;
    
    if (result != NULL && recheaders != NULL && filter != NULL && index != NULL)
    {
        /* lookup by key in index */
        if (mcel_index_lookup(index, filter->searchkey, filter->searchkeylen, &candpositions, &candcount) == true)
        {
            if (candcount == 0U)
            {
                /* No matches */
                result->recpositions = NULL;
                result->count = 0U;
                result->hasmore = 0U;
                result->totalmatches = 0U;
                result->usedindex = 1U;
                res = true;
            }
            else
            {
                /* apply additional filters to candidates */
                filtpositions = (uint64_t*)qsc_memutils_malloc(candcount * sizeof(uint64_t));
                
                if (filtpositions != NULL)
                {
                    filtcount = 0U;
                    
                    for (size_t i = 0; i < candcount; ++i)
                    {
                        if (candpositions[i] < reccount)
                        {
                            const mcel_record_header* header;
                            
                            header = (const mcel_record_header*)recheaders[candpositions[i]];
                            
                            if (record_matches_filter(header, filter) == true)
                            {
                                filtpositions[filtcount] = candpositions[i];
                                ++filtcount;
                            }
                        }
                    }
                    
                    /* apply pagination */
                    if (filter->offset > 0U && filter->offset < filtcount)
                    {
                        size_t offsetcount;

                        offsetcount = filtcount - filter->offset;

                        /* use memmove for overlapping regions */
                        memmove(filtpositions, filtpositions + filter->offset, offsetcount * sizeof(uint64_t));
                        filtcount = offsetcount;
                    }
                    else if (filter->offset >= filtcount)
                    {
                        filtcount = 0U;
                    }
                    
                    if (filter->limit > 0U && filter->limit < filtcount)
                    {
                        result->hasmore = 1U;
                        filtcount = filter->limit;
                    }
                    else
                    {
                        result->hasmore = 0U;
                    }
                    
                    result->recpositions = filtpositions;
                    result->count = filtcount;
                    result->totalmatches = filtcount;
                    result->usedindex = 1U;
                    res = true;
                }
                
                qsc_memutils_alloc_free(candpositions);
            }
        }
    }
    
    return res;
}

static bool execute_ledger_scan(mcel_query_result* result, const void** recheaders, size_t reccount, const mcel_query_filter* filter)
{
    /* execute query using ledger scan strategy */
    MCEL_ASSERT(result != NULL);
    MCEL_ASSERT(recheaders != NULL);
    MCEL_ASSERT(filter != NULL);
    
    uint64_t* positions;
    size_t matchcount;
    size_t allocsize;
    bool res;
    
    res = false;
    positions = NULL;
    
    if (result != NULL && recheaders != NULL && filter != NULL)
    {
        /* allocate maximum possible size */
        allocsize = reccount * sizeof(uint64_t);
        positions = (uint64_t*)qsc_memutils_malloc(allocsize);
        
        if (positions != NULL)
        {
            size_t scan_start;
            size_t scan_end;
            
            matchcount = 0U;
            scan_start = 0U;
            scan_end = reccount;
            
            /* determine scan direction */
            if (filter->reverseorder != 0U)
            {
                /* reverse chronological scan */
                for (size_t i = scan_end; i > scan_start; --i)
                {
                    const mcel_record_header* header;
                    size_t idx;
                    
                    idx = i - 1U;
                    header = (const mcel_record_header*)recheaders[idx];
                    
                    if (record_matches_filter(header, filter) == true)
                    {
                        /* check if we've skipped enough for offset */
                        if (matchcount >= filter->offset)
                        {
                            size_t result_idx;
                            
                            result_idx = matchcount - filter->offset;
                            
                            /* check if we've hit the limit */
                            if (filter->limit == 0U || result_idx < filter->limit)
                            {
                                positions[result_idx] = idx;
                            }
                            else
                            {
                                result->hasmore = 1U;
                                break;
                            }
                        }
                        
                        ++matchcount;
                    }
                }
            }
            else
            {
                /* forward chronological scan */
                for (size_t i = scan_start; i < scan_end; ++i)
                {
                    const mcel_record_header* header;
                    
                    header = (const mcel_record_header*)recheaders[i];
                    
                    if (record_matches_filter(header, filter) == true)
                    {
                        /* check if we've skipped enough for offset */
                        if (matchcount >= filter->offset)
                        {
                            size_t result_idx;
                            
                            result_idx = matchcount - filter->offset;
                            
                            /* check if we've hit the limit */
                            if (filter->limit == 0U || result_idx < filter->limit)
                            {
                                positions[result_idx] = i;
                            }
                            else
                            {
                                result->hasmore = 1U;
                                break;
                            }
                        }
                        
                        ++matchcount;
                    }
                }
            }
            
            /* set result count */
            if (filter->limit > 0U && matchcount > filter->offset + filter->limit)
            {
                result->count = filter->limit;
            }
            else if (matchcount > filter->offset)
            {
                result->count = matchcount - filter->offset;
            }
            else
            {
                result->count = 0U;
            }
            
            result->recpositions = positions;
            result->totalmatches = matchcount;
            result->usedindex = 0U;
            res = true;
        }
    }
    
    return res;
}

bool mcel_query_execute(mcel_query_result* result, const void** recheaders, uint8_t** recpayloads, const size_t* payloadlens, 
    size_t reccount, const mcel_query_filter* filter, const mcel_index* index)
{
    MCEL_ASSERT(result != NULL);
    MCEL_ASSERT(recheaders != NULL);
    MCEL_ASSERT(filter != NULL);
    
    mcel_query_strategy strategy;
    uint64_t starttime;
    uint64_t endtime;
    bool res;
    
    (void)recpayloads;
    (void)payloadlens;
    res = false;
    
    if (result != NULL && recheaders != NULL && filter != NULL)
    {
        /* initialize result */
        qsc_memutils_clear((uint8_t*)result, sizeof(mcel_query_result));
        
        /* record start time */
        starttime = qsc_timestamp_epochtime_microseconds();
        
        /* select execution strategy */
        strategy = select_query_strategy(filter, index);
        
        /* execute query */
        switch (strategy)
        {
            case mcel_query_strategy_index_lookup:
            {
                res = execute_index_lookup(result, recheaders, reccount, filter, index);
                break;
            }
            case mcel_query_strategy_index_scan:
            {
                /* index scan not yet implemented, fall back to ledger scan */
                res = execute_ledger_scan(result, recheaders, reccount, filter);
                break;
            }
            case mcel_query_strategy_ledger_scan:
            {
                res = execute_ledger_scan(result, recheaders, reccount, filter);
                break;
            }
            default:
            {
                res = false;
                break;
            }
        }
        
        /* record end time */
        endtime = qsc_timestamp_epochtime_microseconds();
        
        if (res == true)
        {
            result->querytimeus = endtime - starttime;
        }
    }
    
    return res;
}

bool mcel_query_count(size_t* countout, const void** recheaders, size_t reccount, const mcel_query_filter* filter)
{
    MCEL_ASSERT(countout != NULL);
    MCEL_ASSERT(recheaders != NULL);
    MCEL_ASSERT(filter != NULL);
    
    bool res;
    
    res = false;
    
    if (countout != NULL && recheaders != NULL && filter != NULL)
    {
        size_t matchcount;
        
        matchcount = 0U;
        
        /* simple scan to count matches */
        for (size_t i = 0U; i < reccount; ++i)
        {
            const mcel_record_header* header;
            
            header = (const mcel_record_header*)recheaders[i];
            
            if (record_matches_filter(header, filter) == true)
            {
                ++matchcount;
            }
        }
        
        *countout = matchcount;
        res = true;
    }
    
    return res;
}

void mcel_query_filter_init(mcel_query_filter* filter)
{
    if (filter != NULL)
    {
        qsc_memutils_clear((uint8_t*)filter, sizeof(mcel_query_filter));
        filter->offset = MCEL_QUERY_OFFSET_DEFAULT;
        filter->limit = MCEL_QUERY_LIMIT_DEFAULT;
    }
}

void mcel_query_result_dispose(mcel_query_result* result)
{
    if (result != NULL)
    {
        if (result->recpositions != NULL)
        {
            qsc_memutils_alloc_free(result->recpositions);
        }
        
        qsc_memutils_clear((uint8_t*)result, sizeof(mcel_query_result));
    }
}
