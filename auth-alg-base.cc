
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
                                  const AUTN_t &autn,
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

    autn.get_sqn(ak, sqn);
    autn.get_amf(amf);

    f1(rand, sqn, amf, mac_a);

    return autn.validate_mac(mac_a);
}


bool AuthAlgBase :: authenticate_s( const RAND_t rand,
                                    const AUTS_t &auts,
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

    auts.get_sqn(akstar, sqn);
    amfstar[0] = 0;
    amfstar[1] = 0;

    f1star(rand, sqn, amfstar, mac_s);
    return auts.validate_mac(mac_s);
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
                              AUTN_t &autn )
{
    int ind;

    if (f2345(rand, res, res_len, ck, ik, ak) == false)
        return false;

    amf[0] = 0x80;
    amf[1] = 0x00;

    f1(rand, sqn, amf, mac_a);

    autn.set_sqn(ak, sqn);
    autn.set_amf(amf);
    autn.set_mac(mac_a);

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
                                AUTS_t &auts )
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

    auts.set_sqn(akstar, sqn);
    auts.set_mac(mac_s);

    return true;
}
