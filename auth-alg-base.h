
#ifndef __AUTH_ALG_BASE_H__
#define __AUTH_ALG_BASE_H__

#include <inttypes.h>
#include <string.h>
#include <string>
#include <mbedtls/md.h>

class AuthAlgBase {

public:
    typedef uint8_t K_t[16];
    typedef uint8_t RAND_t[16];
    typedef uint8_t SQN_t[6];
    typedef SQN_t AK_t;
    typedef uint8_t AMF_t[2];
    typedef uint8_t MAC_t[8];
    // requires a size_t with it to determine if RES
    // is supposed to be 8 or 16 bytes.
    typedef uint8_t RES16_t[16];
    // technically to support GSM, there should be a length with this
    // too, since Kc is 8 bytes; but at the moment this does not
    // support GSM, only UMTS, LTE, and 5G; so CK and IK are always 16
    // bytes.
    typedef uint8_t KEY_t[16];
    // 5G-specific
    typedef uint8_t  KAUSF_t[32];
    typedef uint8_t  RESstar_t[16];

    struct AUTN_t {
        // AUTN : SQN^AK  ||  AMF  ||  MAC_A
        static const int SIZE = 16;
        static const int SQNAK_OFFSET = 0;
        static const int AMF_OFFSET = sizeof(SQN_t);
        static const int MAC_OFFSET = AMF_OFFSET + sizeof(AMF_t);

        uint8_t  autn[SIZE];

        void get_sqnak(SQN_t sqnak) const {
            for (int ind = 0; ind < sizeof(SQN_t); ind++)
                sqnak[ind] = autn[SQNAK_OFFSET+ind];
        }
        void get_sqn(const AK_t ak, SQN_t sqn) const {
            for (int ind = 0; ind < sizeof(SQN_t); ind++)
                sqn[ind] = autn[SQNAK_OFFSET+ind] ^ ak[ind];
        }
        void set_sqn(const AK_t ak, const SQN_t sqn) {
            for (int ind = 0; ind < sizeof(SQN_t); ind++)
                autn[SQNAK_OFFSET + ind] = sqn[ind] ^ ak[ind];
        }
        void get_amf(AMF_t  amf) const {
            for (int ind = 0; ind < sizeof(AMF_t); ind++)
                amf[ind] = autn[AMF_OFFSET + ind];
        }
        void set_amf(const AMF_t amf) {
            for (int ind = 0; ind < sizeof(AMF_t); ind++)
                autn[AMF_OFFSET + ind] = amf[ind];
        }
        void set_mac(const MAC_t mac_a) {
            for (int ind = 0; ind < sizeof(MAC_t); ind++)
                autn[MAC_OFFSET + ind] = mac_a[ind];
        }
        bool validate_mac(const MAC_t mac_a) const {
            return memcmp(autn + MAC_OFFSET, mac_a, sizeof(MAC_t)) == 0;
        }
    };

    struct AUTS_t {
        // AUTS : SQN^AKSTAR ||  MAC_A
        static const int SIZE = 14;
        static const int SQNAK_OFFSET = 0;
        static const int MAC_OFFSET = sizeof(SQN_t);

        uint8_t  auts[SIZE];

        void get_sqnak(SQN_t sqnak) const {
            for (int ind = 0; ind < sizeof(SQN_t); ind++)
                sqnak[ind] = auts[SQNAK_OFFSET+ind];
        }
        void get_sqn(const AK_t akstar, SQN_t sqn) const {
            for (int ind = 0; ind < sizeof(SQN_t); ind++)
                sqn[ind] = auts[SQNAK_OFFSET+ind] ^ akstar[ind];
        }
        void set_sqn(const AK_t ak, const SQN_t sqn) {
            for (int ind = 0; ind < sizeof(SQN_t); ind++)
                auts[SQNAK_OFFSET + ind] = sqn[ind] ^ ak[ind];
        }
        void set_mac(const MAC_t mac_s) {
            for (int ind = 0; ind < sizeof(MAC_t); ind++)
                auts[MAC_OFFSET + ind] = mac_s[ind];
        }
        bool validate_mac(const MAC_t mac_s) const {
            return memcmp(auts + MAC_OFFSET, mac_s, sizeof(MAC_t)) == 0;
        }
    };

protected:
    K_t  k;

public:
    AuthAlgBase( K_t _k );
    virtual ~AuthAlgBase(void);

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

/* the network performs this operation prior to starting an auth cycle.
   take a RAND and SQN and generate AUTN and other params. */
    bool generate( const RAND_t rand,
                   const SQN_t sqn,
                   AK_t ak,
                   AMF_t amf,
                   MAC_t mac_a,
                   RES16_t res,
                   size_t *res_len,
                   KEY_t ck,
                   KEY_t ik,
                   AUTN_t &autn );

/* the mobile performs this operation if it receives a RAND&AUTN
   and the MAC-A matches but the SQN is wrong.  take a RAND and
   correct SQN and generate AUTS and other params. */
    bool generate_s( const RAND_t rand,
                     const SQN_t sqn,
                     AK_t akstar,
                     AMF_t amfstar,
                     MAC_t mac_s,
                     RES16_t res,
                     size_t *res_len,
                     KEY_t ck,
                     KEY_t ik,
                     AUTS_t &auts );

/* the mobile performs this operation upon receipt of RAND&AUTN.
   authenticate RAND & AUTN, and calculate parameters.
   returns true if AUTN passes, or false if not. */
    bool authenticate( const RAND_t rand,
                       const AUTN_t &autn,
                       AK_t ak,
                       SQN_t sqn,
                       AMF_t amf,
                       MAC_t mac_a,
                       RES16_t res,
                       size_t  *res_len,
                       KEY_t  ck,
                       KEY_t  ik);

/* the network performs this operation upon receipt of AUTS from mobile.
   authenticate RAND & AUTS, and calculate parameters.
   returns true if AUTS passes, or false if not.
   note AMF is 0x00 0x00 in this case. */
    bool authenticate_s( const RAND_t rand,
                         const AUTS_t &auts,
                         AK_t ak,
                         SQN_t sqn,
                         MAC_t mac_s,
                         RES16_t res,
                         size_t  *res_len,
                         KEY_t  ck,
                         KEY_t  ik);

private:
    mbedtls_md_context_t   ctx;

    typedef uint8_t FC_t;
    struct param {
        const uint8_t *buf;
        uint16_t len;
        param(void) { buf = NULL; len = 0; }
    };
    struct params_t {
        static const int MAX_PARAMS = 16;
        param params[16];
        int count;
        params_t(void) {
            count = 0;
        }
        void add(const uint8_t *b, uint16_t l) {
            if (count < MAX_PARAMS) {
                params[count].buf = b;
                params[count].len = l;
                count++;
            }
        }
    };

    typedef uint8_t KDF_t[32]; // SHA256 HMAC output
    /* TS 33.220 section B.2.0 */
    void kdf_common(const AuthAlgBase::KEY_t ck,
                    const AuthAlgBase::KEY_t ik,
                    const params_t  &params,
                    FC_t  fc,  KDF_t output);

    // first byte hashed is the cost factor (FC).
    static const FC_t  fc_res_star_derivation = 0x6B;
    static const FC_t  fc_kausf_derivation = 0x6A;

public:
    /* TS 33.501 section A.2 */
    void kdf_kausf(const AuthAlgBase::KEY_t ck,
                   const AuthAlgBase::KEY_t ik,
                   const std::string &sn_name,
                   const AuthAlgBase::AUTN_t &autn,
                   KAUSF_t  kausf);

    /* TS 33.501 section A.4 */
    void kdf_resstar(const AuthAlgBase::KEY_t ck,
                     const AuthAlgBase::KEY_t ik,
                     const std::string &sn_name,
                     const AuthAlgBase::RAND_t  rand,
                     const AuthAlgBase::RES16_t res,
                     size_t reslen,
                     RESstar_t  resStar,
                     size_t &resStarlen);

};

#endif /* __AUTH_ALG_BASE_H__ */
