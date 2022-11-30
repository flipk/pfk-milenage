
#ifndef __AUTH_ALG_BASE_H__
#define __AUTH_ALG_BASE_H__

#include <inttypes.h>
#include <string.h>

class AuthAlgBase {

public:
    typedef uint8_t K_t[16];
    typedef uint8_t RAND_t[16];
    typedef uint8_t AUTN_t[16];
    typedef uint8_t AUTS_t[14];
    typedef uint8_t SQN_t[6];
    typedef SQN_t AK_t;
    typedef uint8_t AMF_t[2];
    typedef uint8_t MAC_t[8];
    typedef uint8_t RES16_t[16];
    typedef uint8_t KEY_t[16];

protected:
    K_t  k;

public:
    AuthAlgBase( K_t _k )
    {
        memcpy(k, _k, sizeof(k));
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

    virtual void f1    ( const RAND_t rand,
                         const SQN_t sqn,
                         const AMF_t amf,
                         MAC_t mac_a )      = 0;

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
 * res_len should come in as the size of the buffer.
 * it will be returned as the size consumed.
 * returns false if 'res' isn't big enough.
 *
 *-----------------------------------------------------------------*/

    virtual bool f2345 ( const RAND_t rand,
                         RES16_t res,
                         size_t *res_len,
                         KEY_t   ck,
                         KEY_t   ik,
                         AK_t    ak)        = 0;

/*-------------------------------------------------------------------
 *                            Algorithm f1*
 *-------------------------------------------------------------------
 *
 *  Computes resynch authentication code MAC-S from key K, random
 *  challenge RAND, sequence number SQN and authentication management
 *  field AMF.
 *
 *-----------------------------------------------------------------*/

    virtual void f1star( const RAND_t rand,
                         const SQN_t  sqn,
                         const AMF_t  amf,
                         MAC_t   mac_s )    = 0;

/*-------------------------------------------------------------------
 *                            Algorithm f5*
 *-------------------------------------------------------------------
 *
 *  Takes key K and random challenge RAND, and returns resynch
 *  anonymity key AK.
 *
 *-----------------------------------------------------------------*/

    virtual void f5star( const RAND_t rand,
                         AK_t   ak )        = 0;


/* make AUTN out of AK, SQN, AMF, and MAC-A */
    static inline void make_autn( const AK_t ak,
                                  const SQN_t sqn,
                                  const AMF_t amf,
                                  const MAC_t mac_a,
                                  AUTN_t autn )
    {
        uint8_t i;
        for (i=0; i < 6; i++)
            autn[0 + i] = ak[i] ^ sqn[i];
        memcpy(autn + 6, amf, 2);
        memcpy(autn + 8, mac_a, 8);
    }

/* make AUTS out of AK, SQN, and MAC-S */
    static inline void make_auts( const AK_t ak,
                                  const SQN_t sqn,
                                  const MAC_t mac_s,
                                  AUTS_t autn )
    {
        uint8_t i;
        for (i=0; i < 6; i++)
            autn[0 + i] = ak[i] ^ sqn[i];
        memcpy(autn + 6, mac_s, 8);
    }

};

#endif /* __AUTH_ALG_BASE_H__ */
