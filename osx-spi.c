#include <stdio.h>
#include <stdlib.h>
#include "output.h"

#include <CommonCrypto/CommonCryptor.h>

// These routines do not seem to be that fast ...
// e.g. 4096 bits: openssl 0.4 sec, commoncrypto: 4.3 sec

/* Note: CommonCrypto is an open source wrapper around (private) CoreCrypto

#if defined(__has_include)
#if __has_include(<CommonCrypto/CommonRSACryptor.h>)
#include <CommonCrypto/CommonRSACryptor.h>
#endif
#if __has_include(<CommonCrypto/CommonBigNum.h>)
#include <CommonCrypto/CommonBigNum.h>
#endif
#endif
*/

// needs 10.8 (bignum)
// See also: webkit... Source/WebCore/crypto/CommonCryptoUtilities, mac/...

typedef struct _CCRSACryptor *CCRSACryptorRef;
CCCryptorStatus CCRSACryptorGeneratePair(size_t keysize, uint32_t e, CCRSACryptorRef *publicKey, CCRSACryptorRef *privateKey);
CCCryptorStatus CCRSAGetKeyComponents(CCRSACryptorRef rsaKey, uint8_t *modulus, size_t *modulusLength, uint8_t *exponent, size_t *exponentLength, uint8_t *p, size_t *pLength, uint8_t *q, size_t *qLength);
void CCRSACryptorRelease(CCRSACryptorRef key);

typedef struct _CCBigNumRef *CCBigNumRef;
typedef CCCryptorStatus CCStatus;
CCBigNumRef CCCreateBigNum(CCStatus *status);
CCBigNumRef CCBigNumFromData(CCStatus *status, const void *s, size_t len);
uint32_t CCBigNumByteCount(const CCBigNumRef bn);
size_t CCBigNumToData(CCStatus *status, const CCBigNumRef bn, void *to);
CCStatus CCBigNumSubI(CCBigNumRef result, const CCBigNumRef a, const uint32_t b);
CCStatus CCBigNumMod(CCBigNumRef result, CCBigNumRef dividend, CCBigNumRef modulus);
CCStatus CCBigNumInverseMod(CCBigNumRef result, const CCBigNumRef a, const CCBigNumRef modulus);
void CCBigNumFree(CCBigNumRef bn);

// calculate dp=d mod (p-1), dq=d mod (q-1), qinv=q^-1 mod p -- which CCRSAGetKeyComponents does not return...
static CCStatus calculateOthers(
	uint8_t *dp,size_t *dpLen,
	uint8_t *dq,size_t *dqLen,
	uint8_t *qinv,size_t *qinvLen,
	const uint8_t *d,size_t dLen,
	const uint8_t *p,size_t pLen,
	const uint8_t *q,size_t qLen)
{
	CCStatus stat=kCCSuccess;
	CCBigNumRef ccd=NULL,ccp=NULL,ccp1=NULL,ccdp=NULL,ccq=NULL,ccq1=NULL,ccdq=NULL,ccqinv=NULL;

	ccd=CCBigNumFromData(&stat,d,dLen);
	if (!ccd) goto bnerr;

	ccp=CCBigNumFromData(&stat,p,pLen);
	if (!ccp) goto bnerr;
	ccp1=CCCreateBigNum(&stat);
	if (!ccp1) goto bnerr;
	stat=CCBigNumSubI(ccp1,ccp,1);
	if (stat) goto bnerr;

	ccq=CCBigNumFromData(&stat,q,qLen);
	if (!ccq) goto bnerr;
	ccq1=CCCreateBigNum(&stat);
	if (!ccq1) goto bnerr;
	stat=CCBigNumSubI(ccq1,ccq,1);
	if (stat) goto bnerr;

	ccdp=CCCreateBigNum(&stat);
	if (!ccdp) goto bnerr;
	stat=CCBigNumMod(ccdp,ccd,ccp1);
	if (stat) goto bnerr;

	ccdq=CCCreateBigNum(&stat);
	if (!ccdq) goto bnerr;
	stat=CCBigNumMod(ccdq,ccd,ccq1);
	if (stat) goto bnerr;

	ccqinv=CCCreateBigNum(&stat);
	if (!ccqinv) goto bnerr;
	stat=CCBigNumInverseMod(ccqinv,ccq,ccp);
	if (stat) goto bnerr;

	if ( (*dpLen<CCBigNumByteCount(ccdp))||
	     (*dqLen<CCBigNumByteCount(ccdq))||
	     (*qinvLen<CCBigNumByteCount(ccqinv)) ) {
		stat=kCCBufferTooSmall;
		goto bnerr;
	}

	*dpLen=CCBigNumToData(&stat,ccdp,dp);
	if (stat) goto bnerr;
	*dqLen=CCBigNumToData(&stat,ccdq,dq);
	if (stat) goto bnerr;
	*qinvLen=CCBigNumToData(&stat,ccqinv,qinv);
	if (stat) goto bnerr;

bnerr:
	if (ccd) CCBigNumFree(ccd);
	if (ccp) CCBigNumFree(ccp);
	if (ccp1) CCBigNumFree(ccp1);
	if (ccdp) CCBigNumFree(ccdp);
	if (ccq) CCBigNumFree(ccq);
	if (ccq1) CCBigNumFree(ccq1);
	if (ccdq) CCBigNumFree(ccdq);
	return stat;
}

int main(int argc,char **argv)
{
	int bits=1024; // bits%32==0, >=1024
	int e=0x10001; // e >=65536(?)

	if (argc>=2) {
		int r=atoi(argv[1]);
		if (r>=128) {
			bits=r;
		}
	}

	CCCryptorStatus err;
	CCRSACryptorRef pubKey,privKey;

fprintf(stderr,"Generating %d bits ...\n",bits);
	err=CCRSACryptorGeneratePair(bits,e,&pubKey,&privKey);
	if (err) {
		fprintf(stderr,"Generate Pair failed: %d\n",err);
		// TODO ...
		return 1;
	}
	CCRSACryptorRelease(pubKey);

	uint8_t *mem=malloc(bits*7);
	if (!mem) {
		fprintf(stderr,"Alloc failed\n");
		CCRSACryptorRelease(privKey);
		return 1;
	}

	uint8_t *modulus=mem,*exponent=mem+bits,*p=mem+2*bits,*q=mem+3*bits;
	size_t modLen=bits,expLen=bits,pLen=bits,qLen=bits;
	err=CCRSAGetKeyComponents(privKey,modulus,&modLen,exponent,&expLen,p,&pLen,q,&qLen);
	CCRSACryptorRelease(privKey);
	if (err) {
		fprintf(stderr,"GetKeyComponents failed: %d\n",err);
		free(mem);
		return 1;
	}

	uint8_t *dp=mem+4*bits,*dq=mem+5*bits,*qinv=mem+6*bits;
	size_t dpLen=bits,dqLen=bits,qinvLen=bits;
	CCStatus stat=calculateOthers(dp,&dpLen,dq,&dqLen,qinv,&qinvLen,
	                              exponent,expLen,p,pLen,q,qLen);
	if (stat) {
		fprintf(stderr,"BigNum error: %d\n",stat);
		free(mem);
		return 1;
	}
fprintf(stderr,"Done...\n");

	uint8_t pubExp[4]={e>>24,e>>16,e>>8,e};
	RSAPRIV out={
		.n = modulus, .nLen = modLen,
		.e = pubExp, .eLen = sizeof(pubExp),
		.d = exponent, .dLen = expLen,
		.p = p, .pLen = pLen,
		.q = q, .qLen = qLen,
		.dp = dp, .dpLen = dpLen,
		.dq = dq, .dqLen = dqLen,
		.qinv = qinv, .qinvLen = qinvLen
	};

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
		printPem(stdout,&out);
	}

	free(mem);

	return 0;
}
