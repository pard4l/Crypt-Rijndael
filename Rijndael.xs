#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* try to be compatible with older perls */
/* SvPV_nolen() macro first defined in 5.005_55 */
/* this is slow, not threadsafe, but works */
#include "patchlevel.h"
#if (PATCHLEVEL == 4) || ((PATCHLEVEL == 5) && (SUBVERSION < 55))
static STRLEN nolen_na;
# define SvPV_nolen(sv) SvPV ((sv), nolen_na)
#endif

#include "rijndael.h"
#include "_rijndael.c"

typedef struct cryptstate {
  RIJNDAEL_context ctx;
  int mode;
} *Crypt__Rijndael;

MODULE = Crypt::Rijndael		PACKAGE = Crypt::Rijndael

PROTOTYPES: ENABLE

  # newCONSTSUB is here as of 5.004_70

BOOT:
{
#if (PATCHLEVEL > 4) || ((PATCHLEVEL == 4) && (SUBVERSION >= 70))
  HV *stash = gv_stashpv("Crypt::Rijndael", 0);

  newCONSTSUB (stash, "keysize",   newSViv (32));
  newCONSTSUB (stash, "blocksize", newSViv (16));
  newCONSTSUB (stash, "MODE_ECB",  newSViv (MODE_ECB));
  newCONSTSUB (stash, "MODE_CBC",  newSViv (MODE_CBC));
#endif
}

#if (PATCHLEVEL < 4) || ((PATCHLEVEL == 4) && (SUBVERSION < 70))

int
keysize(...)
  CODE:
     RETVAL=32;
  OUTPUT:
     RETVAL

int
blocksize(...)
  CODE:
     RETVAL=16;
  OUTPUT:
     RETVAL

int
MODE_ECB(...)
  CODE:
     RETVAL=MODE_ECB;
  OUTPUT:
     RETVAL

int
MODE_CBC(...)
  CODE:
     RETVAL=MODE_CBC;
  OUTPUT:
     RETVAL

#endif


Crypt::Rijndael
new(class, key, mode=MODE_ECB)
        SV *	class
        SV *	key
        int	mode
        CODE:
        {
          STRLEN keysize;
          
          if (!SvPOK (key))
            croak("key must be a string scalar");

          keysize = SvCUR(key);

          if (keysize != 16 && keysize != 24 && keysize != 32)
            croak ("wrong key length: key must be 128, 192 or 256 bits long");
          if (mode != MODE_ECB && mode != MODE_CBC)
            croak ("illegal mode: mode must be MODE_ECB or MODE_CBC");

          Newz(0, RETVAL, 1, struct cryptstate);
	  RETVAL->ctx.mode = RETVAL->mode = mode;
          rijndael_setup(&RETVAL->ctx, keysize, SvPV_nolen(key));

	}
	OUTPUT:
        RETVAL

SV *
encrypt(self, data)
 	Crypt::Rijndael self
        SV *	data
        ALIAS:
        	decrypt = 1
        CODE:
        {
          SV *res;
          STRLEN size;
          void *rawbytes = SvPV(data,size);

          if (size) {
	    if (size % RIJNDAEL_BLOCKSIZE)
	      croak ("encrypt: datasize not multiple of blocksize (%d bytes)", RIJNDAEL_BLOCKSIZE);

	    RETVAL = NEWSV (0, size);
	    SvPOK_only (RETVAL);
	    SvCUR_set (RETVAL, size);
	    (ix ? block_decrypt : block_encrypt)
	      (&self->ctx, rawbytes, size, SvPV_nolen(RETVAL));
          } else
            RETVAL = newSVpv ("", 0);
        }
	OUTPUT:
        RETVAL

void
DESTROY(self)
        Crypt::Rijndael self
        CODE:
        Safefree(self);
