#include <inttypes.h>

class Rijndael {

    /* Rijndael round subkeys */
    uint8_t roundKeys[11][4][4];

    /* Rijndael S box table */
    static const uint8_t S[256];

    /* This array does the multiplication by x in GF(2^8) */
    static const uint8_t Xtime[256];

    uint8_t state[4][4];

    void KeySchedule( uint8_t key[16] );
    void KeyAdd(int round);

    /* Byte substitution transformation */
    int ByteSub(void);

    /* Row shift transformation */
    void ShiftRow(void);

    /* MixColumn transformation*/
    void MixColumn(void);

public:

    /*-------------------------------------------------------------------
     *  Rijndael key schedule function.  Takes 16-byte key and creates 
     *  all Rijndael's internal subkeys ready for encryption.
     *-----------------------------------------------------------------*/
    Rijndael( uint8_t key[16] );

    /*-------------------------------------------------------------------
     *  Rijndael encryption function.  Takes 16-byte input and creates 
     *  16-byte output (using round keys already derived from 16-byte 
     *  key).
     *-----------------------------------------------------------------*/
    void Encrypt( uint8_t input[16], uint8_t output[16] );
};
