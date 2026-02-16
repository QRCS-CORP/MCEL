#include "mclr_example.h"
#include "consoleutils.h"
#include "csp.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

static mclr_logging_state m_mclr_logging_state;
static mclr_receipt mclr_receipt_records[3U];
static mcel_store_callbacks m_mcel_store_callbacks;
static mclr_example_signature_keypair m_mclr_example_signature_keypair;
static mclr_example_storage m_mclr_example_storage;
static mclr_search_index m_search_index;
static void** m_loaded_headers = NULL;
static uint8_t** m_loaded_payloads = NULL;
static size_t* m_loaded_lens = NULL;
static size_t m_loaded_count = 0U;

static void* mclr_example_create_mock_header(uint64_t sequence, uint32_t type, uint64_t timestamp, uint8_t flags)
{
    /* create mock record header for testing */
    mcel_record_header* hdr;

    hdr = (mcel_record_header*)qsc_memutils_malloc(sizeof(mcel_record_header));

    if (hdr != NULL)
    {
        qsc_memutils_clear((uint8_t*)hdr, sizeof(mcel_record_header));
        hdr->sequence = sequence;
        hdr->type = type;
        hdr->timestamp = timestamp;
        hdr->flags = flags;
        hdr->keyid[0U] = (uint8_t)(sequence & 0xFFU);
        hdr->keyid[1U] = (uint8_t)((sequence >> 8U) & 0xFFU);
    }

    return hdr;
}

static uint8_t* mclr_example_create_mock_payload(uint64_t sequence, size_t* lenout)
{
    /* create mock payload for testing */
    MCLR_ASSERT(lenout != NULL);

    char body[128U] = { 0U };
    char seqstr[32U] = { 0U };
    uint8_t* payload;
    size_t bodylen;

    qsc_stringutils_uint64_to_string(sequence, seqstr, sizeof(seqstr));
    qsc_stringutils_copy_string(body, sizeof(body), "Test Event ");
    qsc_stringutils_concat_strings(body, sizeof(body), seqstr);
    bodylen = qsc_stringutils_string_size(body);

    payload = (uint8_t*)qsc_memutils_malloc(bodylen);

    if (payload != NULL)
    {
        qsc_memutils_copy(payload, (uint8_t*)body, bodylen);
        *lenout = bodylen;
    }

    return payload;
}

static bool mclr_example_load_mock_records(size_t count)
{
    /* load mock records (simulates reading from storage) */
    bool res;
    uint64_t basetime;
    size_t i;

    res = false;
    basetime = qsc_timestamp_epochtime_seconds();

    /* free any existing records */
    if (m_loaded_headers != NULL)
    {
        mclr_search_free_records(m_loaded_headers, m_loaded_payloads, m_loaded_lens, m_loaded_count);
        m_loaded_headers = NULL;
        m_loaded_payloads = NULL;
        m_loaded_lens = NULL;
        m_loaded_count = 0U;
    }

    /* allocate arrays */
    m_loaded_headers = (void**)qsc_memutils_malloc(count * sizeof(void*));

    if (m_loaded_headers != NULL)
    {
        m_loaded_payloads = (uint8_t**)qsc_memutils_malloc(count * sizeof(uint8_t*));

        if (m_loaded_payloads != NULL)
        {
            m_loaded_lens = (size_t*)qsc_memutils_malloc(count * sizeof(size_t));

            if (m_loaded_lens != NULL)
            {
                res = true;

                /* create diverse test records */
                for (i = 0U; i < count && res == true; ++i)
                {
                    uint32_t type;
                    uint8_t flags;
                    uint64_t timestamp;

                    /* vary event types (1, 2, 3 repeating) */
                    type = (uint32_t)((i % 3U) + 1U);

                    /* vary flags (0x00, 0x01, 0x02, 0x03 repeating) */
                    flags = (uint8_t)(i % 4U);

                    /* timestamps spread over time */
                    timestamp = basetime + (i * 60U);

                    m_loaded_headers[i] = mclr_example_create_mock_header(i + 1U, type, timestamp, flags);
                    m_loaded_payloads[i] = mclr_example_create_mock_payload(i + 1U, &m_loaded_lens[i]);

                    if (m_loaded_headers[i] == NULL || m_loaded_payloads[i] == NULL)
                    {
                        res = false;
                    }
                }
            }
            else
            {
                qsc_memutils_alloc_free(m_loaded_headers);
                qsc_memutils_alloc_free(m_loaded_payloads);
            }
        }
        else
        {
            qsc_memutils_alloc_free(m_loaded_headers);
        }

        if (res == true)
        {
            m_loaded_count = count;
        }
        else
        {
            mclr_search_free_records(m_loaded_headers, m_loaded_payloads, m_loaded_lens, count);
            m_loaded_headers = NULL;
            m_loaded_payloads = NULL;
            m_loaded_lens = NULL;
        }
    }

    return res;
}

static size_t mclr_example_build_sample_event(uint8_t* output, size_t outlen, uint8_t flags, uint64_t seq, uint64_t ctime, uint64_t epoch, 
    uint8_t suiteid, const char* body)
{
    MCLR_ASSERT(output != NULL);
    MCLR_ASSERT(outlen != 0U);
    MCLR_ASSERT(body != NULL);

    size_t blen;
    size_t need;

    mclr_example_aad_header hdr = {
        .flags = flags,
        .seq = seq,
        .utctime = ctime,
        .epoch = epoch,
        .suiteid = suiteid
    };

    need = 0U;
    blen = qsc_stringutils_string_size(body);
    need = sizeof(hdr) + blen;

    if (need <= outlen)
    {
        qsc_memutils_copy(output, &hdr, sizeof(hdr));
        qsc_memutils_copy(output + sizeof(hdr), body, blen);
    }

    return need;
}

static bool mclr_example_get_storage_path(char* fpath, size_t pathlen)
{
    bool res;

    qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
    qsc_folderutils_append_delimiter(fpath);
    qsc_stringutils_concat_strings(fpath, pathlen, MCLR_EXAMPLE_APP_PATH);
    res = qsc_folderutils_directory_exists(fpath);

    if (res == false)
    {
        res = qsc_folderutils_create_directory(fpath);
    }

    return res;
}

static bool mclr_example_make_directory(const char* fpath)
{
    bool res;

    res = qsc_folderutils_directory_exists(fpath);

    if (res != true)
    {
        res = qsc_folderutils_create_directory(fpath);
    }

    return res;
}

static bool mclr_example_build_path(void* context, char* output, size_t outlen, const uint8_t* location, size_t loclen)
{
    size_t slen;
    bool res;
    mclr_example_storage* sctx;

    res = false;
    sctx = (mclr_example_storage*)context;

    if (output != NULL && location != NULL && loclen != 0 && outlen != 0)
    {
        char tmpp[MCLR_EXAMPLE_MAX_PATH] = { 0U };

        res = mclr_example_make_directory(sctx->basepath);

        if (res == true)
        {
            int64_t pos;

            slen = qsc_stringutils_copy_string(tmpp, sizeof(tmpp), sctx->basepath);
            qsc_folderutils_append_delimiter(tmpp);
            ++slen;

            pos = qsc_stringutils_find_char(location, QSC_FOLDERUTILS_DELIMITER);

            if (pos > 0)
            {
                qsc_memutils_copy(tmpp + slen, location, pos);
                res = mclr_example_make_directory(tmpp);

                if (res == true)
                {
                    slen = qsc_stringutils_copy_string(output, outlen, m_mclr_example_storage.basepath);

                    if (slen != 0U)
                    {
                        qsc_folderutils_append_delimiter(output);
                        slen = qsc_stringutils_concat_strings(output, outlen, location);

                        if (slen != 0U)
                        {
                            res = (qsc_stringutils_concat_strings(output, outlen - slen, ".bin") != 0U);
                        }
                    }
                }
            }
        }
    }

    return res;
}

static bool mclr_example_store_size(void* context, const uint8_t* location, size_t loclen, size_t* length)
{
    MCLR_ASSERT(context != NULL);
    MCLR_ASSERT(location != NULL);
    MCLR_ASSERT(loclen != 0U);
    MCLR_ASSERT(length != NULL);

    char fpath[MCLR_EXAMPLE_MAX_PATH] = { 0U };
    mclr_example_storage* sctx;
    bool res;

    res = false;


    *length = 0;
    sctx = (mclr_example_storage*)context;

    if (mclr_example_build_path(sctx, fpath, sizeof(fpath), location, *length) == true)
    {
        if (qsc_fileutils_valid_path(fpath) == true)
        {
            *length = (uint64_t)qsc_fileutils_get_size(fpath);
            res = true;
        }
    }

    return res;
}

static bool mclr_example_store_read(void* context, const uint8_t* location, size_t loclen, uint8_t* output, size_t outlen, size_t* readlen)
{
    MCLR_ASSERT(context != NULL);
    MCLR_ASSERT(location != NULL);
    MCLR_ASSERT(loclen != 0U);
    MCLR_ASSERT(output != NULL);
    MCLR_ASSERT(outlen != 0U);
    MCLR_ASSERT(readlen != NULL);

    mclr_example_storage* sctx;
    char fpath[MCLR_EXAMPLE_MAX_PATH] = { 0U };
    bool res;

    res = false;
    sctx = (mclr_example_storage*)context;
    *readlen = 0;

    if (mclr_example_build_path(sctx, fpath, sizeof(fpath), location, loclen) == true)
    {
        if (qsc_fileutils_valid_path(fpath) == true)
        {
            FILE* fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_read, true);

            if (fp != NULL)
            {
                size_t r;

                r = qsc_fileutils_read(output, outlen, 0U, fp);
                qsc_fileutils_close(fp);

                *readlen = r;
            }
            else
            {
                /* empty file */
                res = true;
            }
        }
    }

    return true;
}

static bool mclr_example_store_write(void* context, const uint8_t* location, size_t loclen, const uint8_t* input, size_t inlen)
{
    MCLR_ASSERT(context != NULL);
    MCLR_ASSERT(location != NULL);
    MCLR_ASSERT(loclen != 0U);
    MCLR_ASSERT(input != NULL);
    MCLR_ASSERT(inlen != 0U);

    mclr_example_storage* sctx;
    char fpath[MCLR_EXAMPLE_MAX_PATH] = { 0U };
    size_t w;
    bool res;

    res = false;
    sctx = (mclr_example_storage*)context;

    if (mclr_example_build_path(sctx, fpath, sizeof(fpath), location, loclen) == true)
    {
        if (qsc_fileutils_valid_path(fpath) == true)
        {
            FILE* fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_write, true);

            if (fp != NULL)
            {
                w = qsc_fileutils_write((const char*)input, inlen, 0, fp);
                qsc_fileutils_close(fp);
                res = (w == inlen);
            }
        }
    }

    return res;
}

static bool mclr_example_store_append(void* context, const uint8_t* location, size_t loclen, const uint8_t* input, size_t inlen, uint64_t* position)
{
    MCLR_ASSERT(context != NULL);
    MCLR_ASSERT(location != NULL);
    MCLR_ASSERT(loclen != 0U);
    MCLR_ASSERT(input != NULL);
    MCLR_ASSERT(inlen != 0U);
    MCLR_ASSERT(position != NULL);

    mclr_example_storage* sctx;
    char fpath[MCLR_EXAMPLE_MAX_PATH] = { 0U };
    bool res;

    *position = 0;
    res = false;
    sctx = (mclr_example_storage*)context;

    if (mclr_example_build_path(sctx, fpath, sizeof(fpath), location, loclen) == true)
    {
        if (qsc_fileutils_valid_path(fpath) == true)
        {
            size_t w;

            w = qsc_fileutils_get_size(fpath);
            FILE* fp = qsc_fileutils_open(fpath, qsc_fileutils_mode_append, true);

            if (fp != NULL)
            {
                if (qsc_fileutils_seekto(fp, w) == true)
                {
                    /* append */
                    w = qsc_fileutils_write(input, inlen, w, fp);
                    qsc_fileutils_close(fp);

                    if (w == inlen)
                    {
                        *position = (uint64_t)w;
                        res = true;
                    }
                }
            }
        }
    }

    return res;
}

static void mclr_example_make_store_callbacks(mcel_store_callbacks* callstore, mclr_example_storage* sctx)
{
    MCLR_ASSERT(callstore != NULL);
    MCLR_ASSERT(sctx != NULL);

    callstore->context = sctx;
    callstore->size = mclr_example_store_size;
    callstore->read = mclr_example_store_read;
    callstore->write = mclr_example_store_write;
    callstore->append = mclr_example_store_append;
}

static bool mclr_example_rng_generate(uint8_t* output, size_t length)
{
    return qsc_csp_generate(output, length);
}

mclr_errors mclr_example_append_record_test()
{
    /* append evidence/audit events  */
    const uint8_t reckeyid[MCEL_RECORD_KEYID_SIZE] = { 0x01 };
    uint8_t payload[512U] = { 0U };
    size_t paylen;
    uint64_t ctime;
    uint8_t suiteid;
    uint64_t epoch;
    mclr_errors err;

    epoch = 0U;
    suiteid = MCEL_PARAMETER_SET;
    ctime = qsc_timestamp_datetime_utc();

    paylen = mclr_example_build_sample_event(payload, sizeof(payload), 0U, 1U, ctime, epoch, suiteid,
        "ingest: case=ABC evidence=E1 actor=alice sha3_256=... policy=chain-of-custody");

    err = mclr_event_append(&m_mclr_logging_state, reckeyid, 1U, ctime, 1U, 0U, payload, paylen, &mclr_receipt_records[0U]);

    if (err == mclr_error_none)
    {
        paylen = mclr_example_build_sample_event(payload, sizeof(payload), 0U, 2U, ctime + 10U, epoch, suiteid,
            "access: case=ABC evidence=E1 actor=bob reason=audit ticket=INC-10293");

        err = mclr_event_append(&m_mclr_logging_state, reckeyid, 2U, ctime + 10U, 2U, 0U, payload, paylen, &mclr_receipt_records[1U]);

        if (err == mclr_error_none)
        {
            paylen = mclr_example_build_sample_event(payload, sizeof(payload), 0U, 3U, ctime + 20U, epoch, suiteid,
                "transfer: case=ABC evidence=E1 from=alice to=lab1 method=sealed-bag witness=carol");

            err = mclr_event_append(&m_mclr_logging_state, reckeyid, 3U, ctime + 20, 3U, 0U, payload, paylen, &mclr_receipt_records[2U]);

        }
    }

    if (err != mclr_error_none)
    {
        mclr_ledger_close(&m_mclr_logging_state);
    }

    return err;
}

mclr_errors mclr_example_initialization_test()
{
    const uint8_t nsid[] = { 'E','V','L','O','G','-','T','E','S','T','-','0','1' };
    mclr_errors err;

    /* initialize implementation variables */
    qsc_memutils_clear(mclr_receipt_records, sizeof(mclr_receipt) * 3U);
    qsc_memutils_clear(&m_mcel_store_callbacks, sizeof(mcel_store_callbacks));
    qsc_memutils_clear(&m_mclr_example_signature_keypair, sizeof(mclr_example_signature_keypair));
    qsc_memutils_clear(&m_mclr_example_storage, sizeof(mclr_example_storage));

    /* generate signing keypair */
    mcel_signature_generate_keypair(m_mclr_example_signature_keypair.verkey, m_mclr_example_signature_keypair.sigkey, mclr_example_rng_generate);

    /* setup store callbacks */
    qsc_memutils_clear(&m_mclr_example_storage, sizeof(mclr_example_storage));

    mclr_example_get_storage_path(m_mclr_example_storage.basepath, sizeof(m_mclr_example_storage.basepath));
    mclr_example_make_store_callbacks(&m_mcel_store_callbacks, &m_mclr_example_storage);

    /* init mclr */
    err = mclr_ledger_initialize(&m_mclr_logging_state, &m_mcel_store_callbacks, nsid, sizeof(nsid), m_mclr_example_signature_keypair.verkey,
        MCEL_ASYMMETRIC_VERIFY_KEY_SIZE, m_mclr_example_signature_keypair.sigkey, mclr_startup_verify_or_create);

    return err;
}

mclr_errors mclr_example_block_seal_test(uint8_t blkroot[MCEL_BLOCK_HASH_SIZE], uint8_t reccommits[3U * MCEL_BLOCK_HASH_SIZE])
{
    /* seal a block from those record commitments */
    uint8_t blkcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t* blkbuf;
    uint64_t blkpos;
    size_t blksz;
    mclr_errors err;

    mcel_block_header bhdr = {
        .version = MCEL_BLOCK_VERSION,
        .block_sequence = 1U,
        .first_record_seq = 1U,
        .timestamp = qsc_timestamp_datetime_utc() + 30U,
        .record_count = 3U,
        .flags = 0U
    };

    err = mclr_error_invalid_input;
    blkpos = 0U;

    for (size_t i = 0U; i < 3U; ++i)
    {
        qsc_memutils_copy(reccommits + (i * MCEL_BLOCK_HASH_SIZE), mclr_receipt_records[i].record_commit, MCEL_BLOCK_HASH_SIZE);
    }

    blksz = mclr_block_encoded_size(3U);

    if (blksz != 0U)
    {
        blkbuf = (uint8_t*)qsc_memutils_malloc(blksz);

        if (blkbuf != NULL)
        {
            qsc_memutils_clear(blkbuf, blksz);
            err = mclr_block_seal(&m_mclr_logging_state, &bhdr, reccommits, 3U, blkbuf, blksz, blkroot, blkcommit, &blkpos);

            qsc_memutils_alloc_free(blkbuf);
        }
    }

    if (err != mclr_error_none)
    {
        mclr_ledger_close(&m_mclr_logging_state);
    }

    return err;
}

mclr_errors mclr_example_checkpoint_seal_test(uint8_t blkroot[MCEL_BLOCK_HASH_SIZE], uint8_t bundle[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE])
{
    /* seal a checkpoint for that block root */
    mclr_checkpoint_receipt chk = { 0U };
    const uint8_t chk_keyid[MCEL_CHECKPOINT_KEYID_SIZE] = { 0x03U };
    uint64_t ctime;
    mclr_errors err;

    ctime = qsc_timestamp_datetime_utc() + 40U;
    err = mclr_checkpoint_seal(&m_mclr_logging_state, chk_keyid, 1U, 1U, ctime, 3U, 0U, blkroot, bundle, MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE, &chk);

    if (err != mclr_error_none)
    {
        mclr_ledger_close(&m_mclr_logging_state);
    }

    return err;
}

mclr_errors mclr_example_export_checkpoint_test(uint8_t blkroot[MCEL_BLOCK_HASH_SIZE], uint8_t bundle[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE])
{
    /* export checkpoint bundle */
    mcel_checkpoint_header vhdr = { 0U };
    uint8_t vcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t vblkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
    uint8_t vprev[MCEL_BLOCK_HASH_SIZE] = { 0U };
    char fpath[MCLR_EXAMPLE_MAX_PATH] = { 0U };
    mclr_errors err;

    qsc_stringutils_copy_string(fpath, sizeof(fpath), m_mclr_example_storage.basepath);
    qsc_folderutils_append_delimiter(fpath);
    qsc_stringutils_concat_strings(fpath, sizeof(fpath), "mclr_checkpoint_0001.mcel");
    err = mclr_checkpoint_export_bundle(fpath, bundle, MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE);

    /* verify checkpoint bundle */
    err = mclr_checkpoint_verify_bundle(bundle, MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE, m_mclr_example_signature_keypair.verkey, 
        MCEL_ASYMMETRIC_VERIFY_KEY_SIZE, vcommit, &vhdr, vblkroot, vprev);

    if (err != mclr_error_none)
    {
        mclr_ledger_close(&m_mclr_logging_state);
    }

    return err;
}

mclr_errors mclr_example_inclusion_proof_test(uint8_t blkroot[MCEL_BLOCK_HASH_SIZE], uint8_t bundle[MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE], uint8_t reccommits[3U * MCEL_BLOCK_HASH_SIZE])
{
    /* inclusion proof for record #2 */
    mclr_inclusion_proof ip = { 0U };
    uint8_t pbuf[1024U] = { 0U };
    mclr_errors err;

    err = mclr_inclusion_prove(blkroot, reccommits, 3U, 1U, pbuf, sizeof(pbuf), &ip);

    if (err == mclr_error_none)
    {
        err = mclr_inclusion_verify(&ip);
    }

    return err;
}

void mclr_example_cleanup()
{
    char fpath[MCLR_EXAMPLE_MAX_PATH] = { 0U };

    mclr_ledger_close(&m_mclr_logging_state);
    qsc_memutils_clear(mclr_receipt_records, sizeof(mclr_receipt) * 3U);
    qsc_memutils_clear(&m_mcel_store_callbacks, sizeof(mcel_store_callbacks));
    qsc_memutils_clear(&m_mclr_example_signature_keypair, sizeof(mclr_example_signature_keypair));

    mclr_example_build_path(&m_mclr_example_storage, fpath, sizeof(fpath), MCEL_STORE_LOC_BLOCKS, sizeof(MCEL_STORE_LOC_BLOCKS));

    if (qsc_fileutils_exists(fpath) == true)
    {
        qsc_fileutils_delete(fpath);
        qsc_memutils_clear(fpath, sizeof(fpath));
    }

    mclr_example_build_path(&m_mclr_example_storage, fpath, sizeof(fpath), MCEL_STORE_LOC_CHECKPOINTS, sizeof(MCEL_STORE_LOC_CHECKPOINTS));

    if (qsc_fileutils_exists(fpath) == true)
    {
        qsc_fileutils_delete(fpath);
        qsc_memutils_clear(fpath, sizeof(fpath));
    }

    mclr_example_build_path(&m_mclr_example_storage, fpath, sizeof(fpath), MCEL_STORE_LOC_HEAD, sizeof(MCEL_STORE_LOC_HEAD));

    if (qsc_fileutils_exists(fpath) == true)
    {
        qsc_fileutils_delete(fpath);
        qsc_memutils_clear(fpath, sizeof(fpath));
    }

    mclr_example_build_path(&m_mclr_example_storage, fpath, sizeof(fpath), MCEL_STORE_LOC_RECORDS, sizeof(MCEL_STORE_LOC_RECORDS));

    if (qsc_fileutils_exists(fpath) == true)
    {
        qsc_fileutils_delete(fpath);
        qsc_memutils_clear(fpath, sizeof(fpath));
    }

    qsc_stringutils_copy_string(fpath, sizeof(fpath), m_mclr_example_storage.basepath);
    qsc_folderutils_append_delimiter(fpath);
    qsc_stringutils_concat_strings(fpath, sizeof(fpath), "mclr_checkpoint_0001.mcel");

    if (qsc_fileutils_exists(fpath) == true)
    {
        qsc_fileutils_delete(fpath);
        qsc_memutils_clear(fpath, sizeof(fpath));
    }

    qsc_memutils_clear(&m_mclr_example_storage, sizeof(mclr_example_storage));
}

mclr_errors mclr_example_search_index_create_test(void)
{
    mclr_errors err;

    err = mclr_error_none;

    /* create index with all three index types */
    err = mclr_search_index_create(&m_search_index, true, true);

    if (err == mclr_error_none)
    {
        /* load mock records */

        if (mclr_example_load_mock_records(12U) == true)
        {
            /* build indices */
            err = mclr_search_index_build(&m_search_index, (const void**)m_loaded_headers, (const uint8_t**)m_loaded_payloads, m_loaded_lens, m_loaded_count);

            if (err == mclr_error_none)
            {
                /* verify index integrity */
                err = mclr_search_index_verify(&m_search_index);
            }
            else
            {
                err = mclr_error_initialization;
            }
        }
        else
        {
            err = mclr_error_initialization;
        }
    }
    else
    {
        err = mclr_error_initialization;
    }

    return err;
}

mclr_errors mclr_example_search_query_basic_test(void)
{
    mclr_search_filter filter;
    mclr_search_result result;
    mclr_errors err;

    err = mclr_error_none;

    if (m_loaded_count != 0U)
    {
        /* search by event type */
        mclr_search_filter_init(&filter);
        mclr_search_filter_set_event_type(&filter, 2U);

        err = mclr_search_execute(&m_search_index, &filter, &result);

        if (err == mclr_error_none)
        {
            char msg[256U] = { 0U };
            size_t i;

            /* display first few results */
            for (i = 0U; i < result.mcelresult.count && i < 3U; ++i)
            {
                const mcel_record_header* hdr;

                err = mclr_search_result_get_header(&result, i, &hdr);

                if (err == mclr_error_none)
                {
                    break;
                }
            }

            mclr_search_result_dispose(&result);
        }
    }
    else
    {
        err = mclr_error_initialization;
    }

    /* search by flags */
    if (err == mclr_error_none)
    {
        char msg[256U] = { 0U };

        /* search for records with flag 0x02 */
        mclr_search_filter_init(&filter);
        mclr_search_filter_set_flags(&filter, 0x02U, 0x00U);

        err = mclr_search_execute(&m_search_index, &filter, &result);

        if (err == mclr_error_none)
        {
            mclr_search_result_dispose(&result);
        }
    }

    /* count query */
    if (err == mclr_error_none)
    {
        size_t count;
        char msg[256U] = { 0U };

        /* count records of type 1 */
        mclr_search_filter_init(&filter);
        mclr_search_filter_set_event_type(&filter, 1U);

        err = mclr_search_count(&m_search_index, &filter, &count);
    }

    return err;
}

mclr_errors mclr_example_search_query_advanced_test(void)
{
    mclr_search_filter filter;
    mclr_search_result result;
    uint64_t basetime;
    mclr_errors err;

    err = mclr_error_none;

    if (m_loaded_count != 0U)
    {
        basetime = qsc_timestamp_epochtime_seconds();

        /* complex multi-criteria query: type=2, timestamp range, flags */
        mclr_search_filter_init(&filter);
        mclr_search_filter_set_event_type(&filter, 2U);
        mclr_search_filter_set_timerange(&filter, basetime, basetime + 600U);
        mclr_search_filter_set_flags(&filter, 0x02U, 0x00U);

        err = mclr_search_execute(&m_search_index, &filter, &result);
        mclr_search_result_dispose(&result);
    }
    else
    {
        err = mclr_error_initialization;
    }

    /* pagination */
    if (err == mclr_error_none)
    {
        char msg[256U] = { 0U };

        /* paginated query (offset=2, limit=3) */
        mclr_search_filter_init(&filter);
        mclr_search_filter_set_event_type(&filter, 1U);
        mclr_search_filter_set_pagination(&filter, 2U, 3U);

        err = mclr_search_execute(&m_search_index, &filter, &result);

        if (err == mclr_error_none)
        {
            mclr_search_result_dispose(&result);
        }
    }

    /* reverse chronological ordering */
    if (err == mclr_error_none)
    {
        size_t i;

        /* reverse chronological query */
        mclr_search_filter_init(&filter);
        mclr_search_filter_set_ordering(&filter, true);
        mclr_search_filter_set_pagination(&filter, 0U, 5U);

        err = mclr_search_execute(&m_search_index, &filter, &result);

        if (err == mclr_error_none)
        {
            for (i = 0U; i < result.mcelresult.count && i < 5U; ++i)
            {
                const mcel_record_header* hdr;

                err = mclr_search_result_get_header(&result, i, &hdr);
            }

            mclr_search_result_dispose(&result);
        }
    }

    return err;
}

mclr_errors mclr_example_search_index_update_test(void)
{
    void** tempheaders;
    size_t* templens;
    uint8_t** temppayloads;
    uint64_t basetime;
    size_t i;
    size_t newcount;
    size_t oldcount;
    size_t totalcount;
    bool allocok;
    mclr_errors err;

    err = mclr_error_initialization; 

    if (m_loaded_count != 0U)
    {
        /* save old count */
        oldcount = m_loaded_count;
        newcount = 5U;
        totalcount = oldcount + newcount;
        basetime = qsc_timestamp_epochtime_seconds() + 1000U;

        /* expand arrays using realloc */
        tempheaders = (void**)qsc_memutils_realloc(m_loaded_headers, totalcount * sizeof(void*));

        if (tempheaders != NULL)
        {
            m_loaded_headers = tempheaders;

            temppayloads = (uint8_t**)qsc_memutils_realloc(m_loaded_payloads, totalcount * sizeof(uint8_t*));

            if (temppayloads != NULL)
            {
                m_loaded_payloads = temppayloads;

                templens = (size_t*)qsc_memutils_realloc(m_loaded_lens, totalcount * sizeof(size_t));

                if (templens != NULL)
                {
                    m_loaded_lens = templens;

                    /* create new records in expanded arrays */
                    allocok = true;

                    for (i = 0U; i < newcount && allocok == true; ++i)
                    {
                        uint64_t seq;
                        size_t idx;

                        seq = oldcount + i + 1U;
                        idx = oldcount + i;

                        m_loaded_headers[idx] = mclr_example_create_mock_header(seq, (uint32_t)((i % 3U) + 1U), basetime + (i * 60U), (uint8_t)(i % 4U));
                        m_loaded_payloads[idx] = mclr_example_create_mock_payload(seq, &m_loaded_lens[idx]);

                        if (m_loaded_headers[idx] == NULL || m_loaded_payloads[idx] == NULL)
                        {
                            allocok = false;
                        }
                    }

                    if (allocok == true)
                    {
                        char buf[256U] = { 0U };

                        /* update global count */
                        m_loaded_count = totalcount;
                        m_search_index.recheaders = (const void**)m_loaded_headers;
                        m_search_index.recpayloads = (const uint8_t**)m_loaded_payloads;
                        m_search_index.payloadlens = m_loaded_lens;

                        /* update indices incrementally with new records only */
                        err = mclr_search_index_update(&m_search_index, (const void**)&m_loaded_headers[oldcount], 
                            (const uint8_t**)&m_loaded_payloads[oldcount], (const size_t*)&m_loaded_lens[oldcount], newcount);

                        if (err == mclr_error_none)
                        {
                            mclr_search_filter filter;
                            mclr_search_result result;

                            /* test query on updated index */
                            mclr_search_filter_init(&filter);
                            mclr_search_filter_set_event_type(&filter, 2U);

                            err = mclr_search_execute(&m_search_index, &filter, &result);

                            if (err == mclr_error_none)
                            {
                                mclr_search_result_dispose(&result);
                                err = mclr_error_none;
                            }
                        }
                    }
                }
            }
        }
    }

    return err;
}

mclr_errors mclr_example_search_integration_test(void)
{
    mclr_errors err;

    err = mclr_error_none;

    /* index creation */
    err = mclr_example_search_index_create_test();

    /* basic queries */
    if (err == mclr_error_none)
    {
        err = mclr_example_search_query_basic_test();
    }

    /* advanced queries */
    if (err == mclr_error_none)
    {
        err = mclr_example_search_query_advanced_test();
    }

    /* index updates */
    if (err == mclr_error_none)
    {
        err = mclr_example_search_index_update_test();
    }

    return err;
}

void mclr_example_search_cleanup(void)
{
    /* dispose search index */
    mclr_search_index_dispose(&m_search_index);

    /* free loaded records */
    if (m_loaded_headers != NULL)
    {
        mclr_search_free_records(m_loaded_headers, m_loaded_payloads, m_loaded_lens, m_loaded_count);
        m_loaded_headers = NULL;
        m_loaded_payloads = NULL;
        m_loaded_lens = NULL;
        m_loaded_count = 0U;
    }
}