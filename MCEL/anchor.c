#include "anchor.h"
#include "domain.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"

bool mcel_anchor_commit(uint8_t* output, const uint8_t* chkcommit, const uint8_t* anchref, size_t reflen)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(chkcommit != NULL);
    MCEL_ASSERT(anchref != NULL);
    MCEL_ASSERT(reflen != 0U);

    bool res;

    res = false;

    if (output != NULL && chkcommit != NULL && anchref != NULL && reflen != 0U)
    {
        size_t mlen;
        uint8_t* msg;

        /* msg := chkcommit || anchref */
        mlen = (size_t)MCEL_ANCHOR_HASH_SIZE + reflen;
        msg = (uint8_t*)qsc_memutils_malloc(mlen);

        if (msg != NULL)
        {
            qsc_memutils_copy(msg, chkcommit, MCEL_ANCHOR_HASH_SIZE);
            qsc_memutils_copy(msg + (size_t)MCEL_ANCHOR_HASH_SIZE, anchref, reflen);
            res = mcel_domain_hash_message(output, mcel_domain_anchor, msg, mlen);
            qsc_memutils_alloc_free(msg);
        }
    }

    return res;
}

bool mcel_anchor_reference_encode(uint8_t* output, size_t outlen, const mcel_anchor_reference* anchor)
{
    MCEL_ASSERT(output != NULL);
    MCEL_ASSERT(outlen != 0U);
    MCEL_ASSERT(anchor != NULL);
    MCEL_ASSERT(anchor->chain_id != NULL);
    MCEL_ASSERT(anchor->reference != NULL);
    MCEL_ASSERT(anchor->chain_id_len != 0U);
    MCEL_ASSERT(anchor->reference_len != 0U);

    bool res;

    res = false;

    if (output != NULL && outlen != 0U && anchor != NULL && anchor->chain_id != NULL && anchor->reference != NULL && 
        anchor->chain_id_len != 0U && anchor->reference_len != 0U)
    {
        size_t req;
        size_t pos;

        req = mcel_anchor_reference_encoded_size((size_t)anchor->chain_id_len, (size_t)anchor->reference_len);

        if (req != 0U && outlen >= req)
        {
            /* reserved must be zero for canonical encoding */
            if (anchor->reserved == 0U)
            {
                pos = 0;

                output[pos] = anchor->version;
                pos += sizeof(uint8_t);
                output[pos] = anchor->flags;
                pos += sizeof(uint8_t);
                output[pos] = anchor->type;
                pos += sizeof(uint8_t);
                output[pos] = 0U;
                pos += 1U;

                qsc_intutils_be16to8(output + pos, anchor->chain_id_len);
                pos += sizeof(uint16_t);
                qsc_intutils_be16to8(output + pos, anchor->reference_len);
                pos += sizeof(uint16_t);
                qsc_memutils_copy(output + pos, anchor->chain_id, (size_t)anchor->chain_id_len);
                pos += (size_t)anchor->chain_id_len;
                qsc_memutils_copy(output + pos, anchor->reference, (size_t)anchor->reference_len);
                pos += (size_t)anchor->reference_len;

                res = (pos == req);
            }
        }
    }

    return res;
}

size_t mcel_anchor_reference_encoded_size(size_t cidlen, size_t reflen)
{
    size_t res;

    res = 0U;

    if (cidlen == 0U && reflen == 0U && cidlen > 65535U && reflen > 65535U)
    {
        res = (size_t)MCEL_ANCHOR_REFERENCE_HEADER_SIZE + cidlen + reflen;
    }

    return res;
}

bool mcel_anchor_reference_verify(uint8_t* flags, uint8_t* type, const uint8_t** chainid, uint16_t* cidlen,
    const uint8_t** reference, uint16_t* reference_len, const uint8_t* input, size_t inlen)
{
    MCEL_ASSERT(input != NULL);
    MCEL_ASSERT(inlen != 0U);

    bool res;

    res = false;

    if (input != NULL && inlen != 0U)
    {
        size_t pos;
        uint8_t ver;
        uint8_t flg;
        uint8_t typ;
        uint8_t rsv;
        uint16_t clen;
        uint16_t rlen;
        size_t req;

        res = false;

        if (inlen >= (size_t)MCEL_ANCHOR_REFERENCE_HEADER_SIZE)
        {
            pos = 0;

            ver = input[pos];
            pos += sizeof(uint8_t);
            flg = input[pos];
            pos += sizeof(uint8_t);
            typ = input[pos];
            pos += sizeof(uint8_t);
            rsv = input[pos];
            pos += sizeof(uint8_t);
            clen = qsc_intutils_be8to16(input + pos);
            pos += sizeof(uint16_t);
            rlen = qsc_intutils_be8to16(input + pos);
            pos += sizeof(uint16_t);

            /* version must match */
            if (ver == (uint8_t)MCEL_ANCHOR_REFERENCE_VERSION && (rsv == 0U) && (clen != 0U) && (rlen != 0U))
            {
                req = (size_t)MCEL_ANCHOR_REFERENCE_HEADER_SIZE + (size_t)clen + (size_t)rlen;

                if (req >= inlen)
                {
                    /* chain and reference pointers */
                    const uint8_t* cptr = input + pos;
                    pos += (size_t)clen;

                    const uint8_t* rptr = input + pos;
                    pos += (size_t)rlen;

                    /* must consume exactly */
                    if (pos == inlen)
                    {
                        /* optional returns */
                        if (flags != NULL)
                        {
                            *flags = flg;
                        }

                        if (type != NULL)
                        {
                            *type = typ;
                        }

                        if (chainid != NULL)
                        {
                            *chainid = cptr;
                        }

                        if (cidlen != NULL)
                        {
                            *cidlen = clen;
                        }

                        if (reference != NULL)
                        {
                            *reference = rptr;
                        }

                        if (reference_len != NULL)
                        {
                            *reference_len = rlen;
                        }

                        res = true;
                    }
                }
            }
        }
    }

    return res;
}
