
#include <inttypes.h>
#include <string.h>

// 3GPP TS 34.108 15.2.0 s07-s08

class Xor34108
{
    uint8_t k[16];

    static void do_xor(uint8_t *dest,
                       const uint8_t *src1,
                       const uint8_t *src2,
                       int len)
    {
        int i;
        for (i = 0; i < len; i++)
            dest[i] = src1[i] ^ src2[i];
    }

public:

    Xor34108( uint8_t _k[16] )
    {
        memcpy(k, _k, 16);
    }

    void f1    ( const uint8_t rand[16],
                 const uint8_t sqn[6],
                 const uint8_t amf[2], 
                 uint8_t mac_a[8] );

    void f2345 ( const uint8_t rand[16],
                 uint8_t res[8],
                 uint8_t ck[16],
                 uint8_t ik[16],
                 uint8_t ak[6] );

    void f1star( const uint8_t rand[16],
                 const uint8_t sqn[6],
                 const uint8_t amf[2], 
                 uint8_t mac_s[8] );

    void f5star( const uint8_t rand[16],
                 uint8_t ak[6] );

};
