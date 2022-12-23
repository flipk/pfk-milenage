
#include "auth-alg-base.h"
#include <assert.h>

/* KDF function : TS.33220 cluase B.2.0 */
void AuthAlgBase :: kdf_common(const KEY_t ck, const KEY_t ik,
                               const params_t  &params,
                               FC_t  fc,  KDF_t output)
{
    unsigned char  key[sizeof(KEY_t) * 2];
    memcpy(key,                 ck, sizeof(KEY_t));
    memcpy(key + sizeof(KEY_t), ik, sizeof(KEY_t));

    mbedtls_md_hmac_starts( &ctx, key, sizeof(key));

    // first add the cost factor.
    mbedtls_md_hmac_update( &ctx, &fc, 1 );

    for (int ind = 0; ind < params.count; ind++)
    {
        const param *p = &params.params[ind];
        uint16_t lenbuf = htobe16(p->len);
#if 0
        printf("adding param %d : %02x %02x   ",
               ind,
               ((unsigned char *)(&lenbuf))[0],
               ((unsigned char *)(&lenbuf))[1]);
        for (int i = 0; i < p->len; i++)
            printf("%02x ", (unsigned char) p->buf[i]);
        printf("\n");
#endif

        mbedtls_md_hmac_update( &ctx, (unsigned char *)p->buf, p->len );
        mbedtls_md_hmac_update( &ctx, (unsigned char *)&lenbuf,     2 );
    }

    mbedtls_md_hmac_finish( &ctx, output);
}

/* TS33.501 Annex A.2 : Kausf derviation function */
void AuthAlgBase :: kdf_kausf(const KEY_t ck, const KEY_t ik,
                              const std::string &sn_name,
                              const AUTN_t  &autn,
                              KAUSF_t  kausf)
{
    params_t   params;
    SQN_t      sqnak;

    params.add((const uint8_t*) sn_name.c_str(), sn_name.size());
    autn.get_sqnak(sqnak);
    params.add(sqnak, sizeof(SQN_t));

    KDF_t kdf_output;
    kdf_common(ck, ik, params, fc_kausf_derivation, kdf_output);

    assert(sizeof(KDF_t) == sizeof(KAUSF_t));
    memcpy(kausf, kdf_output, sizeof(KAUSF_t));
}

/* TS33.501 Annex A.4 : RES* and XRES* derivation function */
void AuthAlgBase :: kdf_resstar(const KEY_t ck, const KEY_t ik,
                                const std::string &sn_name,
                                const RAND_t  rand,
                                const RES16_t res, size_t reslen,
                                RESstar_t  resStar, size_t &resStarlen)
{
    assert(resStarlen >= 16);

    params_t  params;

    params.add((const uint8_t*) sn_name.c_str(), sn_name.size());
    params.add(rand,  sizeof(RAND_t));
    params.add(res,   reslen);

    KDF_t  kdf_output;
    kdf_common(ck, ik, params, fc_res_star_derivation, kdf_output);

    // spec says we only take the 2nd half.  (!)
    memcpy(resStar, kdf_output + 16, 16);
    resStarlen = 16;
}
