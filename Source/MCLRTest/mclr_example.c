#include "mclr_example.h"
#include "csp.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

mclr_logging_state m_mclr_logging_state;
mclr_receipt mclr_receipt_records[3U];
mcel_store_callbacks m_mcel_store_callbacks;
mclr_example_signature_keypair m_mclr_example_signature_keypair;
mclr_example_storage m_mclr_example_storage;

static size_t mclr_example_build_sample_event(uint8_t* output, size_t outlen, uint8_t flags, uint64_t seq, uint64_t ctime, 
    uint64_t epoch, uint8_t suiteid, const char* body)
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
