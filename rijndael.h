/*
 *
 * Rijndael is a 128/192/256-bit block cipher that accepts key sizes of
 * 128, 192, or 256 bits, designed by Joan Daemen and Vincent Rijmen.  See
 * http://www.esat.kuleuven.ac.be/~rijmen/rijndael/ for details.
 */

#if !defined(RIJNDAEL_H)
#define RIJNDAEL_H

#include <stdlib.h>

typedef unsigned long UINT32;
typedef unsigned char UINT8;

/* Other block sizes and key lengths are possible, but in the context of
 * the ssh protocols, 256 bits is the default. */
#define RIJNDAEL_BLOCKSIZE 16
#define RIJNDAEL_KEYSIZE 32

#define     MODE_ECB        1    /*  Are we ciphering in ECB mode?   */
#define     MODE_CBC        2    /*  Are we ciphering in CBC mode?   */
#define     MODE_CFB1       3    /*  Are we ciphering in 1-bit CFB mode? */


/* Allow keys of size 128 <= bits <= 256 */

#define RIJNDAEL_MIN_KEYSIZE 16
#define RIJNDAEL_MAX_KEYSIZE 32

typedef struct {
  UINT32 keys[60];		/* maximum size of key schedule */
  UINT32 ikeys[60];		/* inverse key schedule */
  int nrounds;			/* number of rounds to use for our key size */
  int mode;			/* encryption mode */
} RIJNDAEL_context;

/* This basically performs Rijndael's key scheduling algorithm, as it's the
 * only initialization required anyhow.   The key size is specified in bytes,
 * but the only valid values are 16 (128 bits), 24 (192 bits), and 32 (256
 * bits).  If a value other than these three is specified, the key will be
 * truncated to the closest value less than the key size specified, e.g.
 * specifying 7 will use only the first 6 bytes of the key given.  DO NOT
 * PASS A VALUE LESS THAN 16 TO KEYSIZE! */
void
rijndael_setup(RIJNDAEL_context *ctx, size_t keysize, const UINT8 *key);

/*
 * rijndael_encrypt()
 *
 * Encrypt 16 bytes of data with the Rijndael algorithm.  Before this
 * function can be used, rijndael_setup must be used in order to initialize
 * Rijndael's key schedule.
 *
 * This function always encrypts 16 bytes of plaintext to 16 bytes of
 * ciphertext.  The memory areas of the plaintext and the ciphertext can
 * overlap.
 */

void
rijndael_encrypt(RIJNDAEL_context *context,
		 const UINT8 *plaintext,
		 UINT8 *ciphertext);

/*
 * rijndael_decrypt()
 *
 * Decrypt 16 bytes of data with the Rijndael algorithm.
 *
 * Before this function can be used, rijndael_setup() must be used in order
 * to set up the key schedule required for the decryption algorithm.
 * 
 * This function always decrypts 16 bytes of ciphertext to 16 bytes of
 * plaintext.  The memory areas of the plaintext and the ciphertext can
 * overlap.
 */

void
rijndael_decrypt(RIJNDAEL_context *context,
		 const UINT8 *ciphertext,
		 UINT8 *plaintext);

#endif /* RIJNDAEL_H */
