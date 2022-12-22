
#include "Milenage35206.h"

#define rijEncrypt(in, out) \
    mbedtls_aes_crypt_ecb( &ctx, MBEDTLS_AES_ENCRYPT, in, out )

Milenage35206 :: Milenage35206( K_t _k, OP_t   _op )
    : AuthAlgBase(_k)
{
    uint8_t i;
    mbedtls_aes_init( &ctx );
    mbedtls_aes_setkey_enc( &ctx, k, sizeof(k) * 8 );
    rijEncrypt(_op, op_c);
    for (i=0; i<16; i++)
        op_c[i] ^= _op[i];
}

Milenage35206 :: Milenage35206( K_t _k, OPc_t  _op_c[16] )
    : AuthAlgBase(_k)
{
    mbedtls_aes_init( &ctx );
    mbedtls_aes_setkey_enc( &ctx, k, sizeof(k) * 8 );
    memcpy(op_c, _op_c, sizeof(op_c));
}

//virtual
Milenage35206 :: ~Milenage35206(void)
{
    mbedtls_aes_free( &ctx );
}

void Milenage35206 :: f1    ( const RAND_t rand,
                              const SQN_t sqn,
                              const AMF_t amf,
                              MAC_t mac_a )
{
  uint8_t temp[16];
  uint8_t in1[16];
  uint8_t out1[16];
  uint8_t rijndaelInput[16];
  uint8_t i;

  for (i=0; i<16; i++)
    rijndaelInput[i] = rand[i] ^ op_c[i];
  rijEncrypt( rijndaelInput, temp );

  for (i=0; i<6; i++)
  {
    in1[i]    = sqn[i];
    in1[i+8]  = sqn[i];
  }
  for (i=0; i<2; i++)
  {
    in1[i+6]  = amf[i];
    in1[i+14] = amf[i];
  }

  /* XOR op_c and in1, rotate by r1=64, and XOR *
   * on the constant c1 (which is all zeroes)   */

  for (i=0; i<16; i++)
    rijndaelInput[(i+8) % 16] = in1[i] ^ op_c[i];

  /* XOR on the value temp computed before */

  for (i=0; i<16; i++)
    rijndaelInput[i] ^= temp[i];
  
  rijEncrypt( rijndaelInput, out1 );
  for (i=0; i<16; i++)
    out1[i] ^= op_c[i];
  for (i=0; i<8; i++)
    mac_a[i] = out1[i];
}

bool Milenage35206 :: f2345 ( const RAND_t rand,
                              RES16_t res,
                              size_t *res_len,
                              KEY_t   ck,
                              KEY_t   ik,
                              AK_t    ak )
{
  uint8_t temp[16];
  uint8_t out[16];
  uint8_t rijndaelInput[16];
  uint8_t i;

  if (*res_len < RES_LEN)
    return false;
  *res_len = RES_LEN;

  for (i=0; i<16; i++)
    rijndaelInput[i] = rand[i] ^ op_c[i];
  rijEncrypt( rijndaelInput, temp );

  /* To obtain output block OUT2: XOR OPc and TEMP,    *
   * rotate by r2=0, and XOR on the constant c2 (which *
   * is all zeroes except that the last bit is 1).     */

  for (i=0; i<16; i++)
    rijndaelInput[i] = temp[i] ^ op_c[i];
  rijndaelInput[15] ^= 1;

  rijEncrypt( rijndaelInput, out );
  for (i=0; i<16; i++)
    out[i] ^= op_c[i];

  for (i=0; i<8; i++)
    res[i] = out[i+8];
  for (i=0; i<6; i++)
    ak[i]  = out[i];

  /* To obtain output block OUT3: XOR OPc and TEMP,        *
   * rotate by r3=32, and XOR on the constant c3 (which    *
   * is all zeroes except that the next to last bit is 1). */

  for (i=0; i<16; i++)
    rijndaelInput[(i+12) % 16] = temp[i] ^ op_c[i];
  rijndaelInput[15] ^= 2;

  rijEncrypt( rijndaelInput, out );
  for (i=0; i<16; i++)
    out[i] ^= op_c[i];

  for (i=0; i<16; i++)
    ck[i] = out[i];

  /* To obtain output block OUT4: XOR OPc and TEMP,         *
   * rotate by r4=64, and XOR on the constant c4 (which     *
   * is all zeroes except that the 2nd from last bit is 1). */

  for (i=0; i<16; i++)
    rijndaelInput[(i+8) % 16] = temp[i] ^ op_c[i];
  rijndaelInput[15] ^= 4;

  rijEncrypt( rijndaelInput, out );
  for (i=0; i<16; i++)
    out[i] ^= op_c[i];

  for (i=0; i<16; i++)
    ik[i] = out[i];

  return true;
}

void Milenage35206 :: f1star( const RAND_t rand,
                              const SQN_t  sqn,
                              const AMF_t  amf,
                              MAC_t   mac_s )
{
  uint8_t temp[16];
  uint8_t in1[16];
  uint8_t out1[16];
  uint8_t rijndaelInput[16];
  uint8_t i;

  for (i=0; i<16; i++)
    rijndaelInput[i] = rand[i] ^ op_c[i];
  rijEncrypt( rijndaelInput, temp );

  for (i=0; i<6; i++)
  {
    in1[i]    = sqn[i];
    in1[i+8]  = sqn[i];
  }
  for (i=0; i<2; i++)
  {
    in1[i+6]  = amf[i];
    in1[i+14] = amf[i];
  }

  /* XOR op_c and in1, rotate by r1=64, and XOR *
   * on the constant c1 (which is all zeroes)   */

  for (i=0; i<16; i++)
    rijndaelInput[(i+8) % 16] = in1[i] ^ op_c[i];

  /* XOR on the value temp computed before */

  for (i=0; i<16; i++)
    rijndaelInput[i] ^= temp[i];
  
  rijEncrypt( rijndaelInput, out1 );
  for (i=0; i<16; i++)
    out1[i] ^= op_c[i];

  for (i=0; i<8; i++)
    mac_s[i] = out1[i+8];
}

void Milenage35206 :: f5star( const RAND_t rand,
                              AK_t   ak )
{
  uint8_t temp[16];
  uint8_t out[16];
  uint8_t rijndaelInput[16];
  uint8_t i;

  for (i=0; i<16; i++)
    rijndaelInput[i] = rand[i] ^ op_c[i];
  rijEncrypt( rijndaelInput, temp );

  /* To obtain output block OUT5: XOR OPc and TEMP,         *
   * rotate by r5=96, and XOR on the constant c5 (which     *
   * is all zeroes except that the 3rd from last bit is 1). */

  for (i=0; i<16; i++)
    rijndaelInput[(i+4) % 16] = temp[i] ^ op_c[i];
  rijndaelInput[15] ^= 8;

  rijEncrypt( rijndaelInput, out );
  for (i=0; i<16; i++)
    out[i] ^= op_c[i];

  for (i=0; i<6; i++)
    ak[i] = out[i];
}
