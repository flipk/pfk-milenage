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


#include <inttypes.h>
#include <string.h>

#include "Rijndael.h"

class Milenage35206 {

public:

    typedef  uint8_t OP_t[16];
    typedef  uint8_t OPc_t[16];

    Rijndael rij;
    OPc_t   op_c;

public:

    Milenage35206( uint8_t k[16], OP_t   _op )
        : rij(k)
    {
        uint8_t i;
        rij.Encrypt( _op, op_c );
        for (i=0; i<16; i++)
            op_c[i] ^= _op[i];
    }
    Milenage35206( uint8_t k[16], OPc_t  _op_c[16] )
        : rij(k)
    {
        memcpy(op_c, _op_c, sizeof(op_c));
    }

/*-------------------------------------------------------------------
 *                            Algorithm f1
 *-------------------------------------------------------------------
 *
 *  Computes network authentication code MAC-A from key K, random
 *  challenge RAND, sequence number SQN and authentication management
 *  field AMF.
 *
 *-----------------------------------------------------------------*/

    void f1    ( const uint8_t rand[16],
                 const uint8_t sqn[6],
                 const uint8_t amf[2], 
                 uint8_t mac_a[8] );

/*-------------------------------------------------------------------
 *                            Algorithms f2-f5
 *-------------------------------------------------------------------
 *
 *  Takes key K and random challenge RAND, and returns response RES,
 *  confidentiality key CK, integrity key IK and anonymity key AK.
 *
 * f2 calculates the challenge response "RES".
 * f3 calculates the cipher key "CK".
 * f4 calculates the integrity key "IK".
 * f5 calculates the anonymity key "AK".
 *
 *-----------------------------------------------------------------*/

    void f2345 ( const uint8_t rand[16],
                 uint8_t res[8],
                 uint8_t ck[16],
                 uint8_t ik[16],
                 uint8_t ak[6] );

    void get_opc( uint8_t  _op_c[16] )
    {
        memcpy(_op_c, op_c, 16 );
    }

/* make AUTN out of AK, SQN, AMF, and MAC-A */

    static inline void make_autn( const uint8_t ak[6],
                                  const uint8_t sqn[6],
                                  const uint8_t amf[2],
                                  const uint8_t mac_a[8],
                                  uint8_t autn[16] )
    {
        uint8_t i;
        for (i=0; i < 6; i++)
            autn[0 + i] = ak[i] ^ sqn[i];

        memcpy(autn + 6, amf, 2);
        memcpy(autn + 8, mac_a, 8);
    }

/*-------------------------------------------------------------------
 *                            Algorithm f1*
 *-------------------------------------------------------------------
 *
 *  Computes resynch authentication code MAC-S from key K, random
 *  challenge RAND, sequence number SQN and authentication management
 *  field AMF.
 *
 *-----------------------------------------------------------------*/

    void f1star( const uint8_t rand[16],
                 const uint8_t sqn[6],
                 const uint8_t amf[2], 
                 uint8_t mac_s[8] );

/*-------------------------------------------------------------------
 *                            Algorithm f5*
 *-------------------------------------------------------------------
 *
 *  Takes key K and random challenge RAND, and returns resynch
 *  anonymity key AK.
 *
 *-----------------------------------------------------------------*/

    void f5star( const uint8_t rand[16],
                 uint8_t ak[6] );

};
