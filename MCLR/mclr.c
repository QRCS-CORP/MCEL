#include "mclr.h"
#include "fileutils.h"
#include "memutils.h"
#include "merkle.h"

static void mclr_record_header_init(mcel_record_header* header, const uint8_t* keyid, uint64_t sequence, uint64_t timestamp, uint32_t type, uint8_t flags, uint32_t payloadlen)
{
    MCLR_ASSERT(header != NULL);
    MCLR_ASSERT(keyid != NULL);

    qsc_memutils_clear(header, sizeof(mcel_record_header));
    qsc_memutils_copy(header->keyid, keyid, MCEL_RECORD_KEYID_SIZE);
    header->sequence = sequence;
    header->timestamp = timestamp;
    header->payload_len = payloadlen;
    header->type = type;
    header->flags = flags;
    header->version = MCEL_RECORD_VERSION;
}

static void mclr_checkpoint_header_init(mcel_checkpoint_header* header, const uint8_t* keyid, uint64_t chksequence, uint64_t firstrecordseq,
    uint64_t timestamp, uint32_t recordcount, uint8_t flags)
{
    MCLR_ASSERT(header != NULL);
    MCLR_ASSERT(keyid != NULL);

    qsc_memutils_clear(header, sizeof(mcel_checkpoint_header));
    qsc_memutils_copy(header->keyid, keyid, MCEL_CHECKPOINT_KEYID_SIZE);

    header->chk_sequence = chksequence;
    header->first_record_seq = firstrecordseq;
    header->timestamp = timestamp;
    header->record_count = recordcount;
    header->flags = flags;
    header->version = MCEL_CHECKPOINT_VERSION;
}

mclr_errors mclr_block_add_commit(mclr_block_builder* bldr, const uint8_t* commit)
{
    MCLR_ASSERT(bldr != NULL);
    MCLR_ASSERT(commit != NULL);

    mclr_errors res;

    res = mclr_error_none;

    if (bldr != NULL && commit != NULL && bldr->commits != NULL && bldr->capacity != 0U)
    {
        if (bldr->count < bldr->capacity)
        {
            uint8_t* dst = bldr->commits + (bldr->count * (size_t)MCEL_BLOCK_HASH_SIZE);
            qsc_memutils_copy(dst, commit, (size_t)MCEL_BLOCK_HASH_SIZE);
            ++bldr->count;
        }
        else
        {
            res = mclr_error_initialization;
        }
    }

    return res;
}

mclr_errors mclr_block_begin(mclr_block_builder* bldr, uint8_t* commits, size_t capacity)
{
    MCLR_ASSERT(bldr != NULL);
    MCLR_ASSERT(commits != NULL);
    MCLR_ASSERT(capacity != 0U);

    mclr_errors res;

    res = mclr_error_none;

    if (bldr != NULL && commits != NULL && capacity != 0U)
    {
        qsc_memutils_clear(bldr, sizeof(*bldr));
        bldr->commits = commits;
        bldr->capacity = capacity;
        bldr->count = 0U;

        qsc_memutils_clear(commits, capacity * (size_t)MCEL_BLOCK_HASH_SIZE);
    }
    else
    {
        res = mclr_error_invalid_input;
    }

    return res;
}

size_t mclr_block_encoded_size(size_t reccount)
{
    return mcel_block_encoded_size(reccount);
}

mclr_errors mclr_block_finalize(mclr_logging_state* state, const mclr_block_builder* bldr, uint8_t* blockbuf, size_t blockbuflen,
    uint8_t* outblkroot, uint8_t* outblkcommit, uint64_t* outpos)
{
    MCLR_ASSERT(state != NULL);
    MCLR_ASSERT(bldr != NULL);
    MCLR_ASSERT(blockbuf != NULL);
    MCLR_ASSERT(blockbuflen != 0U);
    MCLR_ASSERT(outblkroot != NULL);
    MCLR_ASSERT(outblkcommit != NULL);

    mclr_errors res;

    if (state != NULL && bldr != NULL && blockbuf != NULL && blockbuflen != 0U && outblkroot != NULL && outblkcommit != NULL)
    {
        if (bldr->commits != NULL && bldr->count != 0U)
        {
            const size_t req = mcel_block_encoded_size(bldr->count);

            if (req != 0U && blockbuflen >= req)
            {
                if (mcel_ledger_seal_block(&state->ledger, outblkroot, outblkcommit, &bldr->header, bldr->commits, bldr->count, blockbuf, blockbuflen, outpos) == true)
                {
                    res = mclr_error_none;
                }
                else
                {
                    res = mclr_error_chain_seal;
                }
            }
            else
            {
                res = mclr_error_chain_seal;
            }
        }
        else
        {
            res = mclr_error_record_append;
        }
    }
    else
    {
        res = mclr_error_invalid_input;
    }

    return res;
}

mclr_errors mclr_block_seal(mclr_logging_state* state, const mcel_block_header* header, const uint8_t* reccommits, size_t reccount, uint8_t* blockbuf,
    size_t blockbuflen, uint8_t* outblkroot, uint8_t* outblkcommit, uint64_t* outpos)
{
    MCLR_ASSERT(state != NULL);
    MCLR_ASSERT(header != NULL);
    MCLR_ASSERT(reccommits != NULL);
    MCLR_ASSERT(reccount != 0U);
    MCLR_ASSERT(blockbuf != NULL);
    MCLR_ASSERT(blockbuflen != 0U);
    MCLR_ASSERT(outblkroot != NULL);
    MCLR_ASSERT(outblkcommit != NULL);

    mclr_errors res;

    if (state != NULL && header != NULL && reccommits != NULL && reccount != 0U && blockbuf != NULL && blockbuflen != 0U && outblkroot != NULL && outblkcommit != NULL)
    {
        /* ensure the caller supplied a buffer large enough to encode the sealed block */
        const size_t req = mcel_block_encoded_size(reccount);

        if (req != 0U && blockbuflen >= req)
        {
            qsc_memutils_clear(outblkroot, MCEL_BLOCK_HASH_SIZE);
            qsc_memutils_clear(outblkcommit, MCEL_BLOCK_HASH_SIZE);

            if (mcel_ledger_seal_block(&state->ledger, outblkroot, outblkcommit, header, reccommits, reccount, blockbuf, blockbuflen, outpos) == true)
            {
                res = mclr_error_none;
            }
            else
            {
                res = mclr_error_chain_seal;
            }
        }
        else
        {
            res = mclr_error_chain_seal;
        }
    }
    else
    {
        res = mclr_error_invalid_input;
    }

    return res;
}

mclr_errors mclr_block_set_header(mclr_block_builder* bldr, const mcel_block_header* header)
{
    MCLR_ASSERT(bldr != NULL);
    MCLR_ASSERT(header != NULL);

    mclr_errors res;

    if (bldr != NULL && header != NULL)
    {
        qsc_memutils_copy(&bldr->header, header, sizeof(mcel_block_header));
        res = mclr_error_none;
    }
    else
    {
        res = mclr_error_invalid_input;
    }

    return res;
}

mclr_errors mclr_checkpoint_build_audit_path(mclr_logging_state* state, uint64_t fromchkseq, uint64_t tochkseq, uint8_t* bundlebuf,
    size_t bundlebuflen, mcel_checkpoint_audit_item* items, size_t* itemcount)
{
    MCLR_ASSERT(state != NULL);
    MCLR_ASSERT(bundlebuf != NULL);
    MCLR_ASSERT(bundlebuflen != 0U);
    MCLR_ASSERT(items != NULL);
    MCLR_ASSERT(itemcount != NULL);

    mclr_errors res;

    res = mclr_error_none;

    if (state != NULL && bundlebuf != NULL && bundlebuflen != 0U && items != NULL && itemcount != NULL)
    {
        if (fromchkseq != 0U && tochkseq != 0U && fromchkseq <= tochkseq)
        {
            if (state->store.size != NULL && state->store.read != NULL)
            {
                const uint8_t* logloc = (const uint8_t*)MCEL_STORE_LOC_CHECKPOINTS;
                const size_t logloclen = sizeof(MCEL_STORE_LOC_CHECKPOINTS) - 1U;
                uint64_t loglen64;

                loglen64 = 0U;

                if (state->store.size(state->store.context, logloc, logloclen, &loglen64) == true)
                {
                    if (loglen64 != 0U)
                    {
                        const size_t loglen = (size_t)loglen64;
                        const size_t bundsz = (size_t)MCEL_CHECKPOINT_BUNDLE_ENCODED_SIZE;

                        if (bundsz != 0U && (loglen % bundsz) == 0U)
                        {
                            const uint64_t total_bundles = (uint64_t)(loglen / bundsz);

                            /* mcel checkpoint sequences are treated as 1-based in mclr */
                            if (fromchkseq <= total_bundles && tochkseq <= total_bundles)
                            {
                                const size_t want = (size_t)(tochkseq - fromchkseq + 1U);

                                /* because the mcel store read callback reads whole objects, we must read the whole log */
                                if (*itemcount >= want && bundlebuflen >= loglen)
                                {
                                    size_t outread;

                                    outread = 0U;

                                    if (state->store.read(state->store.context, logloc, logloclen, bundlebuf, loglen, &outread) == true)
                                    {
                                        if (outread >= loglen)
                                        {
                                            /* slice requested range into items, ordered from oldest to newest */
                                            const size_t start_idx = (size_t)(fromchkseq - 1U);

                                            for (size_t i = 0U; i < want; ++i)
                                            {
                                                const uint8_t* bundle = bundlebuf + ((start_idx + i) * bundsz);

                                                items[i].bundle = bundle;
                                                items[i].bundlelen = bundsz;
                                            }

                                            /* optional: sanity check that each bundle decodes to the expected checkpoint sequence */
                                            for (size_t i = 0U; i < want; ++i)
                                            {
                                                uint8_t chkcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
                                                uint8_t blkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
                                                uint8_t prevcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
                                                mcel_checkpoint_header hdr = { 0U };

                                                if (mcel_checkpoint_bundle_verify(chkcommit, &hdr, blkroot, prevcommit, items[i].bundle, items[i].bundlelen, state->pubkey) == false)
                                                {
                                                    res = mclr_error_integrity_failure;
                                                    break;
                                                }

                                                /* expected sequence for this slot */
                                                const uint64_t expseq = fromchkseq + (uint64_t)i;

                                                if (hdr.chk_sequence != expseq)
                                                {
                                                    res = mclr_error_integrity_failure;
                                                    break;
                                                }
                                            }

                                            if (res == mclr_error_none)
                                            {
                                                *itemcount = want;
                                            }
                                        }
                                        else
                                        {
                                            res = mclr_error_storage_failure;
                                        }
                                    }
                                    else
                                    {
                                        res = mclr_error_storage_failure;
                                    }
                                }
                                else
                                {
                                    res = mclr_error_storage_failure;
                                }
                            }
                            else
                            {
                                res = mclr_error_integrity_failure;
                            }
                        }
                        else
                        {
                            res = mclr_error_integrity_failure;
                        }
                    }
                    else
                    {
                        /* no checkpoints stored */
                        *itemcount = 0U;
                        res = mclr_error_none;
                    }
                }
                else
                {
                    res = mclr_error_storage_failure;
                }
            }
            else
            {
                res = mclr_error_storage_failure;
            }
        }
        else
        {
            res = mclr_error_integrity_failure;
        }
    }
    else
    {
        res = mclr_error_invalid_input;
    }

    return res;
}

size_t mclr_checkpoint_bundle_encoded_size(size_t siglen)
{
    MCLR_ASSERT(siglen != 0U);

    return mcel_checkpoint_bundle_encoded_size(siglen);
}

mclr_errors mclr_checkpoint_get_head_commit(mclr_logging_state* state, uint8_t* outcommit)
{
    MCLR_ASSERT(state != NULL);
    MCLR_ASSERT(outcommit != NULL);

    mclr_errors res;

    if (state != NULL && outcommit != NULL)
    {
        mcel_checkpoint_header hdr = { 0U };

        qsc_memutils_clear(outcommit, MCEL_BLOCK_HASH_SIZE);

        if (mcel_ledger_get_checkpoint_head(&state->ledger, outcommit, &hdr) == true)
        {
            res = mclr_error_none;
        }
        else
        {
            /* empty ledger state */
            res = mclr_error_integrity_failure;
        }
    }
    else
    {
        res = mclr_error_invalid_input;
    }

    return res;
}

mclr_errors mclr_checkpoint_export_bundle(const char* filepath, const uint8_t* bundle, size_t bundlelen)
{
    MCLR_ASSERT(filepath != NULL);
    MCLR_ASSERT(bundle != NULL);
    MCLR_ASSERT(bundlelen != 0U);

    mclr_errors err;

    if (filepath != NULL && bundle != NULL && bundlelen != 0U)
    {
        if (qsc_fileutils_valid_path(filepath) == true)
        {
            FILE* fp = fopen(filepath, "wb");

            if (fp != NULL)
            {
                const size_t wlen = qsc_fileutils_write((const char*)bundle, bundlelen, 0, fp);

                fclose(fp);

                if (wlen == bundlelen)
                {
                    err = mclr_error_none;
                }
                else
                {
                    err = mclr_error_storage_failure;
                }
            }
            else
            {
                err = mclr_error_storage_failure;
            }
        }
        else
        {
            err = mclr_error_storage_failure;
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }

    return err;
}

mclr_errors mclr_checkpoint_export_log(mclr_logging_state* state, const char* filepath, uint8_t* iobuf, size_t iobuflen, size_t* outlen)
{
    MCLR_ASSERT(state != NULL);
    MCLR_ASSERT(filepath != NULL);
    MCLR_ASSERT(iobuf != NULL);
    MCLR_ASSERT(iobuflen != 0U);
    MCLR_ASSERT(outlen != NULL);

    mclr_errors res;
    uint64_t loglen64;
    size_t loglen;
    size_t outread;

    res = mclr_error_none;
    loglen64 = 0U;
    loglen = 0U;
    outread = 0U;

    if (state != NULL && filepath != NULL && iobuf != NULL && iobuflen != 0U && outlen != NULL)
    {
        *outlen = 0U;

        if (state->store.size != NULL && state->store.read != NULL && qsc_fileutils_valid_path(filepath) == true)
        {
            const uint8_t* logloc = (const uint8_t*)MCEL_STORE_LOC_CHECKPOINTS;
            const size_t logloclen = sizeof(MCEL_STORE_LOC_CHECKPOINTS) - 1U;

            if (state->store.size(state->store.context, logloc, logloclen, &loglen64) == false)
            {
                res = mclr_error_storage_failure;
            }
            else if (loglen64 == 0U)
            {
                /* empty log, write an empty file */
                FILE* fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_write, true);

                if (fp != NULL)
                {
                    qsc_fileutils_close(fp);
                    *outlen = 0U;
                }
                else
                {
                    res = mclr_error_storage_failure;
                }
            }
            else
            {
                loglen = (size_t)loglen64;

                if (loglen <= iobuflen)
                {
                    if (state->store.read(state->store.context, logloc, logloclen, iobuf, loglen, &outread) == true)
                    {
                        if (outread >= loglen)
                        {
                            FILE* fp = qsc_fileutils_open(filepath, qsc_fileutils_mode_write, true);

                            if (fp != NULL)
                            {
                                const size_t wlen = qsc_fileutils_write((const char*)iobuf, loglen, 0, fp);

                                qsc_fileutils_close(fp);

                                if (wlen == loglen)
                                {
                                    *outlen = wlen;
                                }
                                else
                                {
                                    res = mclr_error_storage_failure;
                                }
                            }
                            else
                            {
                                res = mclr_error_storage_failure;
                            }
                        }
                        else
                        {
                            res = mclr_error_storage_failure;
                        }
                    }
                    else
                    {
                        res = mclr_error_storage_failure;
                    }
                }
                else
                {
                    res = mclr_error_storage_failure;
                }
            }
        }
        else
        {
            res = mclr_error_storage_failure;
        }
    }
    else
    {
        res = mclr_error_invalid_input;
    }

    return res;
}

mclr_errors mclr_checkpoint_get_head(mclr_logging_state* state, uint8_t* commit, mcel_checkpoint_header* header)
{
    MCLR_ASSERT(state != NULL);
    MCLR_ASSERT(commit != NULL);
    MCLR_ASSERT(header != NULL);

    mclr_errors res;

    if (state != NULL && commit != NULL && header != NULL)
    {
        if (mcel_ledger_get_checkpoint_head(&state->ledger, commit, header) == true)
        {
            res = mclr_error_none;
        }
        else
        {
            res = mclr_error_integrity_failure;
        }
    }
    else
    {
        res = mclr_error_invalid_input;
    }

    return res;
}

mclr_errors mclr_checkpoint_import_bundle(const char* filepath, uint8_t* outbuf, size_t outbuflen, size_t* outlen)
{
    MCLR_ASSERT(filepath != NULL);
    MCLR_ASSERT(outbuf != NULL);
    MCLR_ASSERT(outbuflen != 0U);
    MCLR_ASSERT(outlen != NULL);

    mclr_errors err;

    *outlen = 0U;

    if (filepath != NULL && outbuf == NULL && outbuflen == 0U && outlen == NULL)
    {
        if (qsc_fileutils_valid_path(filepath) == true && qsc_fileutils_exists(filepath) == true)
        {
            const size_t flen = qsc_fileutils_get_size(filepath);

            if (flen != 0U && flen <= outbuflen)
            {
                const size_t rlen = qsc_fileutils_copy_file_to_object(filepath, outbuf, outbuflen);

                if (rlen == flen)
                {
                    err = mclr_error_none;
                    *outlen = rlen;
                }
                else
                {
                    err = mclr_error_storage_failure;
                }
            }
            else
            {
                err = mclr_error_storage_failure;
            }
        }
        else
        {
            err = mclr_error_storage_failure;
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }

    return err;
}

mclr_errors mclr_checkpoint_seal(mclr_logging_state* state, const uint8_t* chkeyid, uint64_t chksequence, uint64_t firstrecseq, uint64_t timestamp,
    uint32_t reccount, uint8_t chkflags, const uint8_t* blkroot, uint8_t* bundlebuf, size_t bundlebuflen, mclr_checkpoint_receipt* outchk)
{
    MCLR_ASSERT(state != NULL);
    MCLR_ASSERT(chkeyid != NULL);
    MCLR_ASSERT(blkroot != NULL);
    MCLR_ASSERT(bundlebuf != NULL);
    MCLR_ASSERT(bundlebuflen != 0U);
    MCLR_ASSERT(outchk != NULL);

    mclr_errors err;

    if (state != NULL && chkeyid != NULL && blkroot != NULL && bundlebuf != NULL && bundlebuflen != 0U && outchk != NULL)
    {
        const size_t req = mcel_checkpoint_bundle_encoded_size((size_t)MCEL_ASYMMETRIC_SIGNATURE_SIZE);

        if (req != 0U && bundlebuflen >= req)
        {
            mcel_checkpoint_header hdr = { 0U };
            uint8_t chkcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
            uint64_t outpos;

            outpos = 0U;
            mclr_checkpoint_header_init(&hdr, chkeyid, chksequence, firstrecseq, timestamp, reccount, chkflags);

            if (mcel_ledger_seal_checkpoint(&state->ledger, chkcommit, &hdr, blkroot, state->sigkey, bundlebuf, bundlebuflen, &outpos) == true)
            {
                qsc_memutils_clear(outchk, sizeof(mclr_checkpoint_receipt));
                qsc_memutils_copy(outchk->check_commit, chkcommit, MCEL_BLOCK_HASH_SIZE);
                outchk->chkplogpos = outpos;
                qsc_memutils_copy(&outchk->header, &hdr, sizeof(hdr));

                /* treat the bundle as fixed-size encoded, matching the required size for the signature */
                outchk->bundlelen = mcel_checkpoint_bundle_encoded_size((size_t)MCEL_ASYMMETRIC_SIGNATURE_SIZE);
                err = mclr_error_none;
            }
            else
            {
                err = mclr_error_chain_seal;
            }
        }
        else
        {
            err = mclr_error_chain_seal;
        }
    }
    else
    {
        err = mclr_error_chain_seal;
    }

    return err;
}

mclr_errors mclr_checkpoint_verify_bundle(const uint8_t* bundle, size_t bundlelen, const uint8_t* sigpubkey, size_t sigpubkeylen, uint8_t* outchkcommit,
    mcel_checkpoint_header* outhdr, uint8_t* outblkroot, uint8_t* outprevcommit)
{
    MCLR_ASSERT(bundle != NULL);
    MCLR_ASSERT(sigpubkey != NULL);
    MCLR_ASSERT(outchkcommit != NULL);
    MCLR_ASSERT(outhdr != NULL);
    MCLR_ASSERT(outblkroot != NULL);
    MCLR_ASSERT(outprevcommit != NULL);

    mclr_errors err;

    if (bundle != NULL && bundlelen != 0U && sigpubkey != NULL && outchkcommit != NULL &&
        outhdr != NULL && outblkroot != NULL && outprevcommit != NULL)
    {
        if (sigpubkeylen == (size_t)MCEL_ASYMMETRIC_VERIFY_KEY_SIZE)
        {
            qsc_memutils_clear(outchkcommit, MCEL_BLOCK_HASH_SIZE);
            qsc_memutils_clear(outhdr, sizeof(mcel_checkpoint_header));
            qsc_memutils_clear(outblkroot, MCEL_BLOCK_HASH_SIZE);
            qsc_memutils_clear(outprevcommit, MCEL_BLOCK_HASH_SIZE);

            if (mcel_checkpoint_bundle_verify(outchkcommit, outhdr, outblkroot, outprevcommit, bundle, bundlelen, sigpubkey) == true)
            {
                err = mclr_error_none;
            }
            else
            {
                err = mclr_error_integrity_failure;
            }
        }
        else
        {
            err = mclr_error_authentication;
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }

    return err;
}

mclr_errors mclr_checkpoint_verify_chain(const mcel_checkpoint_audit_item* items, size_t itemcount, const uint8_t* sigpubkey, size_t sigpubkeylen, uint8_t* outheadcommit)
{
    MCLR_ASSERT(items != NULL);
    MCLR_ASSERT(itemcount != 0U);
    MCLR_ASSERT(sigpubkey != NULL);
    MCLR_ASSERT(sigpubkeylen != 0U);
    MCLR_ASSERT(outheadcommit != NULL);

    mclr_errors err;

    if (items != NULL && itemcount != 0U && sigpubkey != NULL && outheadcommit != NULL)
    {
        if (sigpubkeylen == (size_t)MCEL_ASYMMETRIC_VERIFY_KEY_SIZE)
        {
            qsc_memutils_clear(outheadcommit, MCEL_BLOCK_HASH_SIZE);

            /* fast path: MCEL provides a whole-audit verification routine */
            if (mcel_checkpoint_audit_path_verify(outheadcommit, items, itemcount, sigpubkey) == false)
            {
                uint8_t prevcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
                mcel_checkpoint_header prevhdr = { 0U };
                bool haveprev;

                haveprev = false;

                for (size_t i = 0; i < itemcount; ++i)
                {
                    uint8_t curcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
                    uint8_t curblkroot[MCEL_BLOCK_HASH_SIZE] = { 0U };
                    uint8_t curprevcommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
                    mcel_checkpoint_header curhdr = { 0U };

                    if (mcel_checkpoint_bundle_verify(curcommit, &curhdr, curblkroot, curprevcommit, items[i].bundle, items[i].bundlelen, sigpubkey) == false)
                    {
                        err = mclr_error_integrity_failure;
                        break;
                    }

                    if (haveprev)
                    {
                        if (mcel_checkpoint_chain_link_verify(prevcommit, curprevcommit, &prevhdr, &curhdr) == false)
                        {
                            err = mclr_error_integrity_failure;
                            break;
                        }
                    }

                    qsc_memutils_copy(prevcommit, curcommit, MCEL_BLOCK_HASH_SIZE);
                    qsc_memutils_copy(&prevhdr, &curhdr, sizeof(curhdr));
                    haveprev = true;
                }

                if (haveprev == true)
                {
                    qsc_memutils_copy(outheadcommit, prevcommit, MCEL_BLOCK_HASH_SIZE);
                    err = mclr_error_none;
                }
            }
            else
            {
                err = mclr_error_none;
            }
        }
        else
        {
            err = mclr_error_authentication;
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }

    return err;
}

const char* mclr_error_to_string(mclr_errors err)
{
    const char* res;

    res = NULL;

    if ((size_t)err < MCLR_ERROR_STRING_DEPTH)
    {
        res = MCLR_ERROR_STRINGS[(size_t)err];
    }

    return res;
}

mclr_errors mclr_event_append(mclr_logging_state* state, const uint8_t* reckeyid, uint64_t sequence, uint64_t timestamp, uint32_t eventtype, uint8_t flags,
    const uint8_t* payload, size_t payloadlen, mclr_receipt* outreceipt)
{
    MCLR_ASSERT(state != NULL);
    MCLR_ASSERT(reckeyid != NULL);
    MCLR_ASSERT(outreceipt != NULL);

    mclr_errors res;

    if (state != NULL && reckeyid != NULL && outreceipt != NULL)
    {
        if (payloadlen <= (size_t)MCEL_PAYLOAD_MAX_SIZE)
        {
            mcel_record_header hdr = { 0U };
            uint8_t reccommit[MCEL_BLOCK_HASH_SIZE] = { 0U };
            uint64_t outpos = 0U;

            mclr_record_header_init(&hdr, reckeyid, sequence, timestamp, eventtype, flags, (uint32_t)payloadlen);
            qsc_memutils_clear(reccommit, sizeof(reccommit));

            if (mcel_ledger_append_record(&state->ledger, reccommit, &outpos, &hdr, payload, payloadlen) == true)
            {
                qsc_memutils_clear(outreceipt, sizeof(mclr_receipt));
                qsc_memutils_copy(outreceipt->record_commit, reccommit, MCEL_BLOCK_HASH_SIZE);

                outreceipt->rcrdlogpos = outpos;
                outreceipt->sequence = sequence;
                outreceipt->timestamp = timestamp;
                outreceipt->type = eventtype;
                outreceipt->flags = flags;

                res = mclr_error_none;
            }
            else
            {
                res = mclr_error_record_append;
            }
        }
        else
        {
            res = mclr_error_record_append;
        }
    }
    else
    {
        res = mclr_error_invalid_input;
    }

    return res;
}

size_t mclr_inclusion_proof_size(size_t leafcount)
{
    MCLR_ASSERT(leafcount != 0U);

    size_t res;

    res = mcel_merkle_proof_size(leafcount);

    return res;
}

mclr_errors mclr_inclusion_prove(const uint8_t* merkleroot, const uint8_t* leaves, size_t count, size_t index, uint8_t* proofbuf,
    size_t proofbuflen, mclr_inclusion_proof* outproof)
{
    MCLR_ASSERT(merkleroot != NULL);
    MCLR_ASSERT(leaves != NULL);
    MCLR_ASSERT(count != 0U);
    MCLR_ASSERT(index < count);
    MCLR_ASSERT(proofbuf != NULL);
    MCLR_ASSERT(outproof != NULL);

    mclr_errors err;

    if (merkleroot != NULL && leaves != NULL && count != 0U && proofbuf != NULL && outproof != NULL)
    {
        if (index < count)
        {
            const size_t req = mcel_merkle_proof_size(count);

            if (req != 0U && proofbuflen >= req)
            {
                if (mcel_merkle_prove_member(proofbuf, req, leaves, count, index) == true)
                {
                    qsc_memutils_clear(outproof, sizeof(mclr_inclusion_proof));
                    qsc_memutils_copy(outproof->merkle_root, merkleroot, MCEL_BLOCK_HASH_SIZE);
                    qsc_memutils_copy(outproof->leaf_commit, leaves + (index * (size_t)MCEL_BLOCK_HASH_SIZE), MCEL_BLOCK_HASH_SIZE);

                    outproof->leafcount = count;
                    outproof->leafindex = index;
                    outproof->proof = proofbuf;
                    outproof->proof_len = req;

                    err = mclr_error_none;
                }
                else
                {
                    err = mclr_error_integrity_failure;
                }
            }
            else
            {
                err = mclr_error_record_append;
            }
        }
        else
        {
            err = mclr_error_record_append;
        }
    }
    else
    {
        err = mclr_error_invalid_input;
    }

    return err;
}

mclr_errors mclr_inclusion_verify(const mclr_inclusion_proof* proof)
{
    MCLR_ASSERT(proof != NULL);
    MCLR_ASSERT(proof->proof != NULL);
    MCLR_ASSERT(proof->proof_len != 0U);
    MCLR_ASSERT(proof->leafcount != 0U);
    MCLR_ASSERT(proof->leafindex < proof->leafcount);

    mclr_errors err;

    if (proof != NULL && proof->proof != NULL && proof->proof_len != 0U && proof->leafcount != 0U && proof->leafindex < proof->leafcount)
    {
        if (mcel_merkle_member_verify(proof->merkle_root, proof->leaf_commit, proof->proof, proof->proof_len, proof->leafcount, proof->leafindex) == true)
        {
            err = mclr_error_none;
        }
        else
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

void mclr_ledger_close(mclr_logging_state* state)
{
    MCLR_ASSERT(state != NULL);

    if (state != NULL)
    {
        qsc_memutils_clear(&state->ledger, sizeof(mcel_ledger_state));
        qsc_memutils_clear(&state->store, sizeof(mcel_store_callbacks));
        state->pubkey = NULL;
        state->pubkeylen = 0U;
        state->sigkey = NULL;
        qsc_memutils_clear(state->nsid, MCEL_LEDGER_NAMESPACE_ID_MAX);
        state->nsidlen = 0U;
        qsc_memutils_clear(state->headbuf, MCLR_HEADBUF_SIZE);
    }
}

mclr_errors mclr_ledger_initialize(mclr_logging_state* state, const mcel_store_callbacks* store, const uint8_t* nsid, size_t nsidlen, const uint8_t* pubkey,
    size_t pubkeylen, const void* sigkey, mclr_startup_mode mode)
{
    MCLR_ASSERT(state != NULL);
    MCLR_ASSERT(store != NULL);
    MCLR_ASSERT(nsid != NULL);
    MCLR_ASSERT(pubkey != NULL);

    mclr_errors res;

    if (state != NULL && store != NULL && nsid != NULL && pubkey != NULL)
    {
        if (nsidlen <= MCEL_LEDGER_NAMESPACE_ID_MAX && pubkeylen == (size_t)MCEL_ASYMMETRIC_VERIFY_KEY_SIZE)
        {
            qsc_memutils_clear(state, sizeof(mclr_logging_state));
            qsc_memutils_copy(&state->store, store, sizeof(mcel_store_callbacks));
            qsc_memutils_copy(state->nsid, nsid, nsidlen);

            state->nsidlen = nsidlen;
            state->pubkey = pubkey;
            state->pubkeylen = pubkeylen;
            state->sigkey = sigkey;

            if (mcel_ledger_initialize(&state->ledger, &state->store, state->nsid, state->nsidlen, state->pubkey, state->headbuf, sizeof(state->headbuf)) == true)
            {
                if (mode == mclr_startup_verify_existing)
                {
                    /* in verify_existing, require that a checkpoint head exists */
                    uint8_t commit[MCEL_BLOCK_HASH_SIZE] = { 0U };
                    mcel_checkpoint_header header = { 0U };

                    if (mcel_ledger_get_checkpoint_head(&state->ledger, commit, &header) == true)
                    {
                        /* verify stored head (and optional audit path later, if supplied) */
                        if (mcel_ledger_verify_integrity(&state->ledger, state->headbuf, sizeof(state->headbuf), NULL, 0U) == true)
                        {
                            res = mclr_error_none;
                        }
                        else
                        {
                            res = mclr_error_integrity_failure;
                        }                        
                    }
                    else
                    {
                        res = mclr_error_initialization;
                    }
                }
                else if (mode == mclr_startup_verify_or_create)
                {
                    /* MCEL treats a missing head as a valid empty ledger, so only fail on real integrity errors */
                    if (mcel_ledger_verify_integrity(&state->ledger, state->headbuf, sizeof(state->headbuf), NULL, 0U) == true)
                    {
                        res = mclr_error_none;
                    }
                    else
                    {
                        res = mclr_error_integrity_failure;
                    }
                }
                else
                {
                    res = mclr_error_none;
                }
            }
            else
            {
                res = mclr_error_initialization;
            }
        }
        else
        {
            res = mclr_error_initialization;
        }
    }
    else
    {
        res = mclr_error_invalid_input;
    }

    return res;
}

mclr_errors mclr_ledger_rotate_signing_key(mclr_logging_state* state, const void* sigkey, const uint8_t* pubkey, size_t pubkeylen)
{
    MCLR_ASSERT(state != NULL);
    MCLR_ASSERT(sigkey != NULL);

    mclr_errors res;

    res = mclr_error_none;

    if (state != NULL && sigkey != NULL && pubkey != NULL)
    {
        /* update signing key */
        state->sigkey = sigkey;

        if (pubkeylen != (size_t)MCEL_ASYMMETRIC_VERIFY_KEY_SIZE)
        {
            res = mclr_error_authentication;
        }
        else
        {
            state->pubkey = pubkey;
            state->pubkeylen = pubkeylen;
        }
    }
    else
    {
        res = mclr_error_invalid_input;
    }

    return res;
}

mclr_errors mclr_ledger_verify_integrity(mclr_logging_state* state, const mcel_checkpoint_audit_item* audit, size_t auditcount)
{
    MCLR_ASSERT(state != NULL);

    mclr_errors res;

    if (state != NULL)
    {
        if (mcel_ledger_verify_integrity(&state->ledger, state->headbuf, sizeof(state->headbuf), audit, auditcount) == true)
        {
            res = mclr_error_none;
        }
        else
        {
            res = mclr_error_integrity_failure;
        }
    }
    else
    {
        res = mclr_error_invalid_input;
    }

    return res;
}
