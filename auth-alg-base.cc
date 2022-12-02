
#include "auth-alg-base.h"

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

    for (ind = 0; ind < 6; ind++)
        sqn[ind] = autn[ind] ^ ak[ind];
    amf[0] = autn[6];
    amf[1] = autn[7];

    f1(rand, sqn, amf, mac_a);
    if (memcmp(autn + 8, mac_a, sizeof(MAC_t)) == 0)
        return true;

    return false;
}


bool AuthAlgBase :: authenticate_s( const RAND_t rand,
                                    const AUTS_t auts,
                                    AK_t ak,
                                    SQN_t sqn,
                                    MAC_t mac_s,
                                    RES16_t res,
                                    size_t  *res_len,
                                    KEY_t  ck,
                                    KEY_t  ik)
{
    int ind;
    AMF_t  amf;

    if (f2345(rand, res, res_len, ck, ik, ak) == false)
        return false;

    f5star(rand, ak);

    for (ind = 0; ind < 6; ind++)
        sqn[ind] = auts[ind] ^ ak[ind];
    amf[0] = 0;
    amf[1] = 0;

    f1star(rand, sqn, amf, mac_s);
    if (memcmp(auts + 6, mac_s, sizeof(MAC_t)) == 0)
        return true;

    return false;
}
