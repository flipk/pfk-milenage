
#ifndef __XOR_34_108_H__
#define __XOR_34_108_H__

#include "auth-alg-base.h"

// 3GPP TS 34.108 15.2.0 s07-s08

class Xor34108 : public AuthAlgBase
{
public:
    static const size_t RES_LEN = 16;

private:
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
    Xor34108( RAND_t _k ) : AuthAlgBase( _k ) { }
    void f1    ( const RAND_t rand,
                 const SQN_t sqn,
                 const AMF_t amf,
                 MAC_t mac_a );
    bool f2345 ( const RAND_t rand,
                 RES16_t res,
                 size_t *res_len,
                 KEY_t   ck,
                 KEY_t   ik,
                 AK_t    ak);
    void f1star( const RAND_t rand,
                 const SQN_t  sqn,
                 const AMF_t  amf,
                 MAC_t   mac_s );
    void f5star( const RAND_t rand,
                 AK_t   ak );

};

#endif /* __XOR_34_108_H__ */
