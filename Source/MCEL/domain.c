#include "domain.h"
#include "sha3.h"

const char* mcel_domain_to_name(mcel_domain_types domain)
{
    const char* res;

    if (domain > 0U && domain < MCEL_DOMAIN_STRING_DEPTH)
    {
        res = USBL_DOMAIN_NAME_STRINGS[(size_t)domain];
    }
    else
    {
        res = USBL_DOMAIN_NAME_STRINGS[0U];
    }

    return res;
}

bool mcel_domain_hash_message(uint8_t* output, mcel_domain_types domain, const uint8_t* msg, size_t msglen)
{
    MCEL_ASSERT(output != NULL);

    bool res;

    res = false;

    if (output != NULL && domain != mcel_domain_none)
    {
        const char* dcust;

        dcust = mcel_domain_to_name(domain);
        qsc_cshake256_compute(output, MCEL_DOMAIN_HASH_SIZE, msg, msglen, (const uint8_t*)MCEL_DOMAIN_NAME_STRING, sizeof(MCEL_DOMAIN_NAME_STRING) - 1U, (const uint8_t*)dcust, MCEL_DOMAIN_STRING_WIDTH - 1U);
        res = true;
    }

    return res;
}
