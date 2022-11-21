
#include "Milenage35206.h"
#include "xor34108.h"
#include <stdio.h>

// NOTE that 3GPP TS 34.108 15.2.0 8.2 defines a default K.
uint8_t my_k[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

Milenage35206::OP_t my_op = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

uint8_t my_rand[16] = {
    0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34,
    0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34
};

uint8_t my_sqn[6] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

uint8_t my_amf[2] = {
    0x80, 0x00
};

/* expected output:

Params:

        my_k[16] = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 
       my_op[16] = 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff 
     my_rand[16] = 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 
      my_sqn[ 6] = 00 00 00 00 00 01 
      my_amf[ 2] = 80 00 

Testing Milenage:

        op_c[16] = 69 d5 c2 eb 2e 2e 62 47 50 54 1d 3b bc 69 2b a5 
       mac_a[ 8] = a0 2a 7a 55 1c 23 1b 71 
         res[ 8] = cf b4 4b d0 a6 9c 5c e8 
          ck[16] = 1b cb e8 4c ef 79 2e 57 01 a6 fc e3 d9 fc 43 6d 
          ik[16] = 69 40 30 c6 37 93 4d 88 33 b4 18 92 8d 9e ea 73 
          ak[ 6] = 5f 8f 3f bc 88 4b 
        autn[16] = 5f 8f 3f bc 88 4a 80 00 a0 2a 7a 55 1c 23 1b 71 
       mac_s[ 8] = 8c a6 99 91 02 3b 0c 73 
      akstar[ 6] = c2 68 b9 66 97 87 
      autn_s[16] = c2 68 b9 66 97 86 80 00 8c a6 99 91 02 3b 0c 73 

Testing XOR:

       mac_a[ 8] = 34 35 36 37 30 30 b2 33 
         res[ 8] = 34 35 36 37 30 31 32 33 
          ck[16] = 35 36 37 30 31 32 33 3c 3d 3e 3f 38 39 3a 3b 34 
          ik[16] = 36 37 30 31 32 33 3c 3d 3e 3f 38 39 3a 3b 34 35 
          ak[ 6] = 37 30 31 32 33 3c 
        autn[16] = 37 30 31 32 33 3d 80 00 34 35 36 37 30 30 b2 33 
       mac_s[ 8] = 34 35 36 37 30 30 b2 33 
      akstar[ 6] = 37 30 31 32 33 3c 
      autn_s[16] = 37 30 31 32 33 3d 80 00 34 35 36 37 30 30 b2 33 

*/

void printhex(const char *name, uint8_t *bytes, int len)
{
    printf("%12s[%2d] = ", name, len);
    for (int ind = 0; ind < len; ind++)
        printf("%02x ", bytes[ind]);
    printf("\n");
}
#define PRT(v)  printhex(#v, v, sizeof(v))

void test_milenage(void)
{
    printf("\nTesting Milenage:\n\n");

    Milenage35206   m(my_k,  my_op);

    uint8_t op_c[16];
    m.get_opc(op_c);
    PRT(op_c);

    uint8_t mac_a[8];
    m.f1( my_rand, my_sqn, my_amf, mac_a );
    PRT(mac_a);

    uint8_t res[8], ck[16], ik[16], ak[6];
    m.f2345( my_rand, res, ck, ik, ak );
    PRT(res);
    PRT(ck);
    PRT(ik);
    PRT(ak);

    uint8_t autn[16];
    Milenage35206::make_autn( ak, my_sqn, my_amf, mac_a, autn );
    PRT(autn);

    uint8_t mac_s[8];
    m.f1star( my_rand, my_sqn, my_amf, mac_s );
    PRT(mac_s);

    uint8_t akstar[6];
    m.f5star( my_rand, akstar );
    PRT(akstar);

    uint8_t autn_s[16];
    m.make_autn( akstar, my_sqn, my_amf, mac_s, autn_s );
    PRT(autn_s);
}

void test_xor(void)
{
    printf("\nTesting XOR:\n\n");

    Xor34108  x(my_k);

    uint8_t mac_a[8];
    x.f1( my_rand, my_sqn, my_amf, mac_a );
    PRT(mac_a);

    uint8_t res[8], ck[16], ik[16], ak[6];
    x.f2345( my_rand, res, ck, ik, ak );
    PRT(res);
    PRT(ck);
    PRT(ik);
    PRT(ak);

    uint8_t autn[16];
    Milenage35206::make_autn( ak, my_sqn, my_amf, mac_a, autn );
    PRT(autn);

    uint8_t mac_s[8];
    x.f1star( my_rand, my_sqn, my_amf, mac_s );
    PRT(mac_s);

    uint8_t akstar[6];
    x.f5star( my_rand, akstar );
    PRT(akstar);

    uint8_t autn_s[16];
    Milenage35206::make_autn( akstar, my_sqn, my_amf, mac_s, autn_s );
    PRT(autn_s);
}


int
main()
{
    printf("\nParams:\n\n");
    PRT(my_k);
    PRT(my_op);
    PRT(my_rand);
    PRT(my_sqn);
    PRT(my_amf);

    test_milenage();
    test_xor();

    printf("\n");
    return 0;
}
