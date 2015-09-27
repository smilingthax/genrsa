#ifndef OUTPUT_H_
#define OUTPUT_H_

#include <stdio.h>

typedef struct {
	unsigned char *n,*e,*d,*p,*q,*dp,*dq,*qinv;
	int nLen,eLen,dLen,pLen,qLen,dpLen,dqLen,qinvLen;
} RSAPRIV;

void printJson(FILE *f, const RSAPRIV *rsa);

unsigned char *writeDer(const RSAPRIV *rsa,int *len);
void printDer(FILE *f, const RSAPRIV *rsa);
void printPem(FILE *f, const RSAPRIV *rsa);

// void printPubPem(FILE *F, const RSAPRIV *rsa);
// rsa(pkcs1) pubkey:  SEQUENCE { INTEGER(n) INTEGER(e) }
// pkcs8/spki pubkey:  SEQUENCE { SEQUENCE { rsaEncryption(1.2.840.113549.1.1.1 = 06 09 2A 86 48 86 F7 0D 01 01 01) [optional parameters/NULL] } BIT STRING(raw pkcs1 data) }

/*
	// window.crypto.subtle.generateKey({name: 'RSA-OAEP', modulusLength: 1024, publicExponent: new Uint8Array([1,0,1]), hash: {name: 'SHA-256'}},true,['encrypt','decrypt']);
	// ... exportKey  ... 'jwk', 'spki'(public)  or 'pkcs8'(private)
	// jwk[public]:  e, n  base64
	// jwk[private]: d, dp, dq, e, n, p, q, qi
*/

#endif
