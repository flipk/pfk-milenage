
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

AuthAlgBase::RAND_t my_rand = {
    0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34,
    0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34
};

AuthAlgBase::AUTN_t  autn_mil = {
    0x5f, 0x8f, 0x3f, 0xbc, 0x88, 0x4a, 0x80, 0x00,
    0xa0, 0x2a, 0x7a, 0x55, 0x1c, 0x23, 0x1b, 0x71
};

AuthAlgBase::AUTS_t  auts_mil = {
    0xc2, 0x68, 0xb9, 0x66, 0x97, 0x86, 0x26, 0x5c,
    0xda, 0x75, 0x20, 0x6b, 0x3f, 0x2b
};

AuthAlgBase::AUTN_t  autn_xor = {
    0x37, 0x30, 0x31, 0x32, 0x33, 0x3d, 0x80, 0x00,
    0x34, 0x35, 0x36, 0x37, 0x30, 0x30, 0xb2, 0x33
};

AuthAlgBase::AUTS_t  auts_xor = {
    0x37, 0x30, 0x31, 0x32, 0x33, 0x3d, 0x34, 0x35,
    0x36, 0x37, 0x30, 0x30, 0x32, 0x33
};

/* expected output:

Params:

        my_k[16] = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
       my_op[16] = 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff

Testing Milenage:

        op_c[16] = 69 d5 c2 eb 2e 2e 62 47 50 54 1d 3b bc 69 2b a5
        rand[16] = 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34
        autn[16] = 5f 8f 3f bc 88 4a 80 00 a0 2a 7a 55 1c 23 1b 71
          ak[ 6] = 5f 8f 3f bc 88 4b
         sqn[ 6] = 00 00 00 00 00 01
         amf[ 2] = 80 00
       mac_a[ 8] = a0 2a 7a 55 1c 23 1b 71
         res[ 8] = cf b4 4b d0 a6 9c 5c e8
          ck[16] = 1b cb e8 4c ef 79 2e 57 01 a6 fc e3 d9 fc 43 6d
          ik[16] = 69 40 30 c6 37 93 4d 88 33 b4 18 92 8d 9e ea 73
        auts[14] = c2 68 b9 66 97 86 26 5c da 75 20 6b 3f 2b
      akstar[ 6] = c2 68 b9 66 97 87
         sqn[ 6] = 00 00 00 00 00 01
       mac_s[ 8] = 26 5c da 75 20 6b 3f 2b
         res[ 8] = cf b4 4b d0 a6 9c 5c e8
          ck[16] = 1b cb e8 4c ef 79 2e 57 01 a6 fc e3 d9 fc 43 6d
          ik[16] = 69 40 30 c6 37 93 4d 88 33 b4 18 92 8d 9e ea 73

Testing XOR:

        rand[16] = 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34
        autn[16] = 37 30 31 32 33 3d 80 00 34 35 36 37 30 30 b2 33
          ak[ 6] = 37 30 31 32 33 3c
         sqn[ 6] = 00 00 00 00 00 01
         amf[ 2] = 80 00
       mac_a[ 8] = 34 35 36 37 30 30 b2 33
         res[16] = 34 35 36 37 30 31 32 33 3c 3d 3e 3f 38 39 3a 3b
          ck[16] = 35 36 37 30 31 32 33 3c 3d 3e 3f 38 39 3a 3b 34
          ik[16] = 36 37 30 31 32 33 3c 3d 3e 3f 38 39 3a 3b 34 35
        auts[14] = 37 30 31 32 33 3d 34 35 36 37 30 30 32 33
      akstar[ 6] = 37 30 31 32 33 3c
         sqn[ 6] = 00 00 00 00 00 01
       mac_s[ 8] = 34 35 36 37 30 30 32 33
         res[16] = 34 35 36 37 30 31 32 33 3c 3d 3e 3f 38 39 3a 3b
          ck[16] = 35 36 37 30 31 32 33 3c 3d 3e 3f 38 39 3a 3b 34
          ik[16] = 36 37 30 31 32 33 3c 3d 3e 3f 38 39 3a 3b 34 35

*/

static void printhex(const char *name, const uint8_t *bytes, int len)
{
    printf("%12s[%2d] =", name, len);
    for (int ind = 0; ind < len; ind++)
        printf(" %02x", bytes[ind]);
    printf("\n");
}
#define PRT(v,l)  printhex(#v, v, l)

static void test_alg(AuthAlgBase *a,
                     const AuthAlgBase::RAND_t  rand,
                     const AuthAlgBase::AUTN_t  autn,
                     AuthAlgBase::AUTS_t        auts )
{
    AuthAlgBase::RES16_t  res;
    size_t                res_len;
    AuthAlgBase::KEY_t    ck, ik;
    AuthAlgBase::AK_t     ak;
    AuthAlgBase::AK_t     akstar;
    AuthAlgBase::SQN_t    sqn;
    AuthAlgBase::AMF_t    amf;
    AuthAlgBase::MAC_t    mac_a;
    AuthAlgBase::MAC_t    mac_s;

    PRT(rand, 16);

    res_len = sizeof(res);
    if (a->authenticate(rand, autn, ak, sqn, amf,
                        mac_a, res, &res_len, ck, ik) == false)
    {
        printf("\nERROR: AUTHENTICATION FAILED\n");
    }

    PRT(autn, 16);
    PRT(ak, 6);
    PRT(sqn, 6);
    PRT(amf, 2);
    PRT(mac_a, 8);
    PRT(res, res_len);
    PRT(ck, 16);
    PRT(ik, 16);

    res_len = sizeof(res);
    if (a->authenticate_s(rand, auts, akstar, sqn,
                          mac_s, res, &res_len, ck, ik) == false)
    {
        printf("\nERROR: RESYNC AUTHENTICATION FAILED\n");
    }

    PRT(auts, 14);
    PRT(akstar, 6);
    PRT(sqn, 6);
    PRT(mac_s, 8);
    PRT(res, res_len);
    PRT(ck, 16);
    PRT(ik, 16);
}

int main() 
{
    printf("\nParams:\n\n");
    PRT(my_k, 16);
    PRT(my_op, 16);

    printf("\nTesting Milenage:\n\n");
    {
        Milenage35206  m(my_k,  my_op);
        Milenage35206::OPc_t  op_c;
        m.get_opc(op_c);
        PRT(op_c, 16);
        test_alg(&m, my_rand, autn_mil, auts_mil);
    }

    printf("\nTesting XOR:\n\n");
    {
        Xor34108  x(my_k);
        test_alg(&x, my_rand, autn_xor, auts_xor);
    }

    printf("\n");
    return 0;
}
