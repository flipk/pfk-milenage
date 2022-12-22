
#ifndef __MILENAGE_35_206_H__
#define __MILENAGE_35_206_H__

/*-------------------------------------------------------------------
 *          Example algorithms f1, f1*, f2, f3, f4, f5, f5*
 *-------------------------------------------------------------------
 *
 *  A sample implementation of the example 3GPP authentication and
 *  key agreement functions f1, f1*, f2, f3, f4, f5 and f5*.  This is
 *  a byte-oriented implementation of the functions, and of the block
 *  cipher kernel function Rijndael.
 *
 *  This has been coded for clarity, not necessarily for efficiency.
 *
 *  The functions f2, f3, f4 and f5 share the same inputs and have 
 *  been coded together as a single function.  f1, f1* and f5* are
 *  all coded separately.
 *
 *-----------------------------------------------------------------*/


#include "auth-alg-base.h"
#include <mbedtls/aes.h>

class Milenage35206 : public AuthAlgBase
{

public:
    typedef  uint8_t OP_t[16];
    typedef  uint8_t OPc_t[16];
    static const size_t RES_LEN = 8;

private:
    // NOTE : the Rijndael algorithm described in 35.206 is,
    //        literally, AES-128. so use mbedtls.
    mbedtls_aes_context  ctx;
    OPc_t   op_c;

public:
    Milenage35206( K_t _k, OP_t   _op );
    Milenage35206( K_t _k, OPc_t  _op_c[16] );
    virtual ~Milenage35206(void);

    inline void get_opc( uint8_t  _op_c[16] )
    {
        memcpy(_op_c, op_c, 16 );
    }

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

#endif /* __MILENAGE_35_206_H__ */
