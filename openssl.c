#include <stdio.h>
#include <openssl/rsa.h>
#include "output.h"

int main(int argc,char **argv)
{
	int e=0x10001;
	int bits=1024;

	if (argc>=2) {
		int r=atoi(argv[1]);
		if (r>=128) {
			bits=r;
		}
	}

#if 0
	RSA *rsa=RSA_new();
	if (!rsa) {
		fprintf(stderr,"RSA new failed\n");
		return 1;
	}
	BIGNUM *exp=BN_new();
	if (!BN_set_word(exp,e)) {
		fprintf(stderr,"BN set failed\n");
		RSA_free(rsa);
		return 2;
	}

	// TODO: initialize prng:   RAND_add
	RSA_generate_key_ex(rsa,bits,exp,NULL); // ? retval
	BN_free(exp);

#else
fprintf(stderr,"Generating %d bits ...\n",bits);
	RSA *rsa=RSA_generate_key(bits,e,NULL,NULL);
	if (!rsa) {
		fprintf(stderr,"RSA key gen failed\n");
		// ERR_get_error ? / ERR_error_string
		return 1;
	}
fprintf(stderr,"Done...\n");
#endif

//BN_print_fp(stdout,num);
// TODO?  swap p,q ?  -> must recalculate qInv...

#define OUT(name,num) \
  out.name ## Len = BN_num_bytes(num); \
  out.name=alloca(out.name ## Len); \
  BN_bn2bin(num,out.name);

	RSAPRIV out;
	OUT(n,rsa->n);
	OUT(e,rsa->e);
	OUT(d,rsa->d);
	OUT(p,rsa->p);
	OUT(q,rsa->q);
	OUT(dp,rsa->dmp1);
	OUT(dq,rsa->dmq1);
	OUT(qinv,rsa->iqmp);
#undef OUT

	if ( (argc>=3)&&(argv[2][0]=='-')&&(argv[2][1])&&(!argv[2][2]) ) {
		switch (argv[2][1]) {
		case 'j':
			printJson(stdout,&out);
			break;
		case 'd':
			printDer(stdout,&out);
			break;
		case 'p':
		default:
			printPem(stdout,&out);
			break;
		}
	} else {
//		printJson(stdout,&out);
//		printJson(stderr,&out);
//		printDer(stdout,&out);
		printPem(stdout,&out);
	}

	RSA_free(rsa);

	return 0;
}

