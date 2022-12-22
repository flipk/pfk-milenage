
#include "auth-alg-base.h"
#include <assert.h>

AuthAlgBase :: AuthAlgBase( K_t _k )
{
    memcpy(k, _k, sizeof(k));
    mbedtls_md_init( &ctx );

    const mbedtls_md_info_t *md_info;
    md_info = mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );
    if (!md_info)
    {
        printf("failure initializing mbedtls\n");
    }

    mbedtls_md_setup( &ctx, md_info, /*hmac*/ 1 );

    assert(mbedtls_md_get_size(md_info) == sizeof(KDF_t));
}

AuthAlgBase :: ~AuthAlgBase(void)
{
    mbedtls_md_free( &ctx );
}

bool AuthAlgBase :: authenticate( const RAND_t rand,
                                  const AUTN_t autn,
                                  AK_t ak,
                                  SQN_t sqn,
                                  AMF_t amf,
                                  MAC_t mac_a,
                                  RES16_t res,
                                  size_t  *res_len,
                                  KEY_t  ck,
                                  KEY_t  ik)
{
    int ind;

    if (f2345(rand, res, res_len, ck, ik, ak) == false)
        return false;

    for (ind = 0; ind < sizeof(SQN_t); ind++)
        sqn[ind] = autn[ind] ^ ak[ind];
    amf[0] = autn[sizeof(SQN_t)];
    amf[1] = autn[sizeof(SQN_t)+1];

    f1(rand, sqn, amf, mac_a);
    if (memcmp(autn + sizeof(SQN_t) + sizeof(AMF_t),
               mac_a, sizeof(MAC_t)) == 0)
        return true;

    return false;
}


bool AuthAlgBase :: authenticate_s( const RAND_t rand,
                                    const AUTS_t auts,
                                    AK_t akstar,
                                    SQN_t sqn,
                                    MAC_t mac_s,
                                    RES16_t res,
                                    size_t  *res_len,
                                    KEY_t  ck,
                                    KEY_t  ik)
{
    int ind;
    AMF_t  amfstar;

    // the ak arg to this func is overwritten later...
    if (f2345(rand, res, res_len, ck, ik, akstar) == false)
        return false;

    // ...right here.
    f5star(rand, akstar);

    for (ind = 0; ind < sizeof(SQN_t); ind++)
        sqn[ind] = auts[ind] ^ akstar[ind];
    amfstar[0] = 0;
    amfstar[1] = 0;

    f1star(rand, sqn, amfstar, mac_s);
    if (memcmp(auts + sizeof(SQN_t), mac_s, sizeof(MAC_t)) == 0)
        return true;

    return false;
}

bool AuthAlgBase :: generate( const RAND_t rand,
                              const SQN_t sqn,
                              AK_t ak,
                              AMF_t amf,
                              MAC_t mac_a,
                              RES16_t res,
                              size_t *res_len,
                              KEY_t ck,
                              KEY_t ik,
                              AUTN_t autn )
{
    int ind;

    if (f2345(rand, res, res_len, ck, ik, ak) == false)
        return false;

    amf[0] = 0x80;
    amf[1] = 0x00;

    f1(rand, sqn, amf, mac_a);

    make_autn(ak, sqn, amf, mac_a, autn);

    return true;
}

bool AuthAlgBase :: generate_s( const RAND_t rand,
                                const SQN_t sqn,
                                AK_t akstar,
                                AMF_t amfstar,
                                MAC_t mac_s,
                                RES16_t res,
                                size_t *res_len,
                                KEY_t ck,
                                KEY_t ik,
                                AUTS_t auts )
{
    int ind;

    // the ak arg is overwritten later...
    if (f2345(rand, res, res_len, ck, ik, akstar) == false)
        return false;

    // ...right here.
    f5star(rand, akstar);

    amfstar[0] = 0x00;
    amfstar[1] = 0x00;

    f1star(rand, sqn, amfstar, mac_s);

    make_auts(akstar, sqn, mac_s, auts);

    return true;
}
