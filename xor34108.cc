
#include "xor34108.h"

// 3GPP TS 34.108 15.2.0 s07-s08
//
// 8.1.2 Definition of the test algorithm for authentication
//
// 8.1.2.1 Authentication and key derivation in the test USIM and SS
//
// The following steps describe sequence of operations for the functions
// f1, f2, f3, f4 and f5 to perform in the test USIM and SS, in order to
// obtain the XMAC/MAC, RES/XRES, CK, IK, Kc and AK respectively, to be
// used in the authentication and key agreement procedure.

void Xor34108 :: f1    ( const RAND_t rand,
                         const SQN_t sqn,
                         const AMF_t amf,
                         MAC_t mac_a )
{
// XDOUT[0..127] = K[0..127] XOR RAND[0..127]
// CDOUT[0..63] = SQN[0..47] || AMF[0..15]
// MAC[0..63] = f1(XDOUT, CDOUT) = XDOUT[0..63] XOR CDOUT[0..63]

// but only half the k/rand/xdout needed for mac_a,
// so skip the second half.

    uint8_t xdout[16 / 2];
    do_xor(xdout, k, rand, 16 / 2);
    do_xor(mac_a, xdout, sqn, 6);
    do_xor(mac_a + 6, xdout + 6, amf, 2);
}

bool Xor34108 :: f2345 ( const RAND_t rand,
                         RES16_t res,
                         size_t *res_len,
                         KEY_t   ck,
                         KEY_t   ik,
                         AK_t    ak )
{
    uint8_t xdout[16], cdout[8];

    if (*res_len < RES_LEN)
        return false;
    *res_len = RES_LEN;

// XDOUT[0..127] = K[0..127] XOR RAND[0..127]
    do_xor(xdout, k, rand, 16);

// RES[0..127] = f2(XDOUT,n) = XDOUT[0..63]
    memcpy(res, xdout, RES_LEN);

// CK[0..127] = f3(XDOUT) = XDOUT[8..127,0..7]
    memcpy(ck, xdout+1, 15);
    ck[15] = xdout[0];

// IK[0..127] = f4(XDOUT) = XDOUT[16..127,0..15]
    memcpy(ik, xdout+2, 14);
    memcpy(ik + 14, xdout, 2);

// AK[0..47]  = f5(XDOUT) = XDOUT[24..71]
    memcpy(ak, xdout + 3, 6);

// NOTE : for GSM,
// Kc[0..63] = c3(CK,IK), see 3GPP TS 33.102 [24], clause 6.8.1.2.
// but not implemented here.

    return true;
}

// 8.1.2.2 Generation of re-synchronization parameters in the USIM
//
// When the test USIM receives an authentication token (AUTN) having
// the value of AMF field equal to the AMF RESYNCH value then the test
// USIM shall initiate the re-synchronization procedure.
//
// When the test USIM starts the re-synchronization procedure, the MAC-S
// and AK have to be calculated using the functions f1* and f5*, which in
// the test algorithm are identical to f1 and f5, respectively.

void Xor34108 :: f1star( const RAND_t rand,
                         const SQN_t  sqn,
                         const AMF_t  amf,
                         MAC_t   mac_s )
{
    uint8_t xdout[16];

// XDOUT[0..127] = K[0..127] XOR RAND[0..127]
// CDOUT[0..63] = SQN[0..47] || AMF*[0..15]
//      Where AMF* assumes a dummy value of all zeros
    do_xor(xdout, k, rand, 16);

// MAC-S[0..63] = f1*(XDOUT, CDOUT) = XDOUT[0..63] XOR CDOUT[0..63]
    do_xor(mac_s, xdout, sqn, 6);
    do_xor(mac_s + 6, xdout + 6, amf, 2);
}

void Xor34108 :: f5star( const RAND_t rand,
                         AK_t   ak )
{
    uint8_t xdout[16], cdout[8];

// XDOUT[0..127] = K[0..127] XOR RAND[0..127]
    do_xor(xdout + 3, k + 3, rand + 3, 6);

// AK[0..47] = f5*(XDOUT) = XDOUT[24..71]
    memcpy(ak, xdout + 3, 6);
}
