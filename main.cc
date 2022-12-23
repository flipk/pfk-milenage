
#include "Milenage35206.h"
#include "xor34108.h"
#include <stdio.h>

// NOTE that 3GPP TS 34.108 15.2.0 8.2 defines a default K.
AuthAlgBase::K_t my_k = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

Milenage35206::OP_t my_op = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

std::string sn_name = "5G:mnc001.mcc001.3gppnetwork.org";

AuthAlgBase::RAND_t my_rand = {
    0xf8, 0x7a, 0x8a, 0x8c, 0xd9, 0x4d, 0xe5, 0x2e,
    0xb4, 0xd9, 0x60, 0xea, 0x52, 0xf6, 0x64, 0xde
};

AuthAlgBase::SQN_t my_sqn = {
    0x00, 0x00, 0x00, 0x00, 0x5a, 0x82
};

AuthAlgBase::AUTN_t  autn_mil = {
    0xeb, 0x8a, 0xb7, 0x5a, 0xee, 0xb9, 0x80, 0x00,
    0x40, 0xf4, 0x7e, 0xfe, 0xab, 0xc3, 0x46, 0x23
};

AuthAlgBase::AUTS_t  auts_mil = {
    0xa0, 0x54, 0xcd, 0xa1, 0x23, 0x69,
    0xe1, 0xf6, 0x53, 0x3a, 0xf5, 0x30, 0xc8, 0xc0
};

AuthAlgBase::AUTN_t  autn_xor = {
    0x8f, 0xdd, 0x48, 0xe3, 0x73, 0x3e, 0x80, 0x00,
    0xf8, 0x7b, 0x88, 0x8f, 0x87, 0xca, 0x63, 0x29
};

AuthAlgBase::AUTS_t  auts_xor = {
    0x8f, 0xdd, 0x48, 0xe3, 0x73, 0x3e,
    0xf8, 0x7b, 0x88, 0x8f, 0x87, 0xca, 0xe3, 0x29
};

#if 0
  "servingNetworkName": "5G:mnc001.mcc001.3gppnetwork.org",
  "encPermanentKey":    "000102030405060708090a0b0c0d0e0f",
  "sqn":      "000000005a82"
  "encOpcKey":"69d5c2eb2e2e624750541d3bbc692ba5"
  "rand": "f87a8a8cd94de52eb4d960ea52f664de",
  "autn": "eb8ab75aeeb9800040f47efeabc34623"
  "auts": "a054cda12369e1f6533af530c8c0"
  "kausf":        "b631fe100c0cfa577cbcd16087d5349468aba134ac2042e57bbb4c978586ef91"
  "xresStar":     "57e71328a395de5705a9799d09994b31"
  ak : eb8ab75ab43b
  res : f87c371980cc3b21
#endif

static void printhex(const char *name, const uint8_t *bytes, int len)
{
    printf("%12s[%2d] =", name, len);
    for (int ind = 0; ind < len; ind++)
        printf(" %02x", bytes[ind]);
    printf("\n");
}
#define PRT(v,l)  printhex(#v, v, l)

static void test_gen(AuthAlgBase *a,
                     const AuthAlgBase::RAND_t  rand,
                     const AuthAlgBase::SQN_t   sqn )
{
    AuthAlgBase::RES16_t   res;
    size_t                 res_len;
    AuthAlgBase::KEY_t     ck, ik;
    AuthAlgBase::AK_t      ak;
    AuthAlgBase::AK_t      akstar;
    AuthAlgBase::AMF_t     amf;
    AuthAlgBase::MAC_t     mac_a;
    AuthAlgBase::MAC_t     mac_s;
    AuthAlgBase::AUTN_t    autn;
    AuthAlgBase::AUTS_t    auts;
    AuthAlgBase::KAUSF_t   kausf;
    AuthAlgBase::RESstar_t resStar;
    size_t                 resStarlen;

    PRT(rand, 16);
    PRT(sqn, 6);

    res_len = sizeof(res);
    if (a->generate(rand, sqn, ak, amf, mac_a, res, &res_len,
                    ck, ik, autn) == false)
    {
        printf("\nERROR: GENERATE FAILED\n");
    }

    PRT(ak, 6);
    PRT(amf, 2);
    PRT(mac_a, 8);
    PRT(res, res_len);
    PRT(ck, 16);
    PRT(ik, 16);
    PRT(autn.autn, 16);

    a->kdf_kausf(ck, ik, sn_name, autn, kausf);
    resStarlen = sizeof(resStar);
    a->kdf_resstar(ck, ik, sn_name, rand, res, res_len,
                   resStar, resStarlen);

    PRT(kausf, 32);
    PRT(resStar, resStarlen);

    res_len = sizeof(res);
    if (a->generate_s(rand, sqn, akstar, amf, mac_s, res, &res_len,
                      ck, ik, auts) == false)
    {
        printf("\nERROR: GENERATE_S FAILED\n");
    }

    PRT(akstar, 6);
    PRT(amf, 2);
    PRT(mac_s, 8);
    PRT(res, res_len);
    PRT(ck, 16);
    PRT(ik, 16);
    PRT(auts.auts, 14);

    a->kdf_kausf(ck, ik, sn_name, autn, kausf);
    resStarlen = sizeof(resStar);
    a->kdf_resstar(ck, ik, sn_name, rand, res, res_len,
                   resStar, resStarlen);

    PRT(kausf, 32);
    PRT(resStar, resStarlen);
}

static void test_auth(AuthAlgBase *a,
                      const AuthAlgBase::RAND_t  rand,
                      const AuthAlgBase::AUTN_t  autn,
                      AuthAlgBase::AUTS_t        &auts )
{
    AuthAlgBase::RES16_t   res;
    size_t                 res_len;
    AuthAlgBase::KEY_t     ck, ik;
    AuthAlgBase::AK_t      ak;
    AuthAlgBase::AK_t      akstar;
    AuthAlgBase::SQN_t     sqn;
    AuthAlgBase::AMF_t     amf;
    AuthAlgBase::MAC_t     mac_a;
    AuthAlgBase::MAC_t     mac_s;
    AuthAlgBase::KAUSF_t   kausf;
    AuthAlgBase::RESstar_t resStar;
    size_t                 resStarlen;

    PRT(rand, 16);

    res_len = sizeof(res);
    if (a->authenticate(rand, autn, ak, sqn, amf,
                        mac_a, res, &res_len, ck, ik) == false)
    {
        printf("\nERROR: AUTHENTICATION FAILED\n");
    }

    PRT(autn.autn, 16);
    PRT(ak, 6);
    PRT(sqn, 6);
    PRT(amf, 2);
    PRT(mac_a, 8);
    PRT(res, res_len);
    PRT(ck, 16);
    PRT(ik, 16);

    a->kdf_kausf(ck, ik, sn_name, autn, kausf);
    PRT(kausf, 32);

    resStarlen = sizeof(resStar);
    a->kdf_resstar(ck, ik, sn_name, rand, res, res_len,
                   resStar, resStarlen);
    PRT(resStar, resStarlen);

    res_len = sizeof(res);
    if (a->authenticate_s(rand, auts, akstar, sqn,
                          mac_s, res, &res_len, ck, ik) == false)
    {
        printf("\nERROR: RESYNC AUTHENTICATION FAILED\n");
    }

    PRT(auts.auts, 14);
    PRT(akstar, 6);
    PRT(sqn, 6);
    PRT(mac_s, 8);
    PRT(res, res_len);
    PRT(ck, 16);
    PRT(ik, 16);

    a->kdf_kausf(ck, ik, sn_name, autn, kausf);
    resStarlen = sizeof(resStar);
    a->kdf_resstar(ck, ik, sn_name, rand, res, res_len,
                   resStar, resStarlen);

    PRT(kausf, 32);
    PRT(resStar, resStarlen);
}

int main() 
{
    printf("\nParams:\n\n");
    PRT(my_k, 16);
    PRT(my_op, 16);

// test generation
// {k,op,rand,sqn}->{ak,mac-a,mac-s,res,ck,ik}
    printf("\nGenerating Milenage:\n\n");
    {
        Milenage35206  m(my_k,  my_op);
        Milenage35206::OPc_t  op_c;
        m.get_opc(op_c);
        PRT(op_c, 16);
        test_gen(&m, my_rand, my_sqn);
    }

    printf("\nGenerating XOR:\n\n");
    {
        Xor34108  x(my_k);
        test_gen(&x, my_rand, my_sqn);
    }

// test authentication
// {k,op,rand,autn,auts}->{ak,sqn,mac-a,mac-s,res,ck,ik}
    printf("\nAuthenticating Milenage:\n\n");
    {
        Milenage35206  m(my_k,  my_op);
        Milenage35206::OPc_t  op_c;
        m.get_opc(op_c);
        PRT(op_c, 16);
        test_auth(&m, my_rand, autn_mil, auts_mil);
    }

    printf("\nAuthenticating XOR:\n\n");
    {
        Xor34108  x(my_k);
        test_auth(&x, my_rand, autn_xor, auts_xor);
    }

    printf("\n");
    return 0;
}
