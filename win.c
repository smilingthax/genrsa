#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include "output.h"

static void error(const char *str)
{
	fprintf(stderr, "%s (%lx)\n", str, GetLastError());
}

static BOOL exportKey(HCRYPTKEY hKey,
                      HCRYPTKEY hExpKey,
                      DWORD dwBlobType,
                      DWORD dwFlags,
                      LPBYTE *ppbKeyBlob,
                      DWORD *pdwBlobLen)
{
// assert( (ppbKeyBlob)&&(pdwBlobLen) );
	*ppbKeyBlob = NULL;
	*pdwBlobLen = 0;

	DWORD size;
	if (!CryptExportKey(hKey,hExpKey,dwBlobType,dwFlags,NULL,&size)) {
		return FALSE;
	}
	*ppbKeyBlob = malloc(size);
	if (!*ppbKeyBlob) {
		return FALSE;
	}
	if (!CryptExportKey(hKey,hExpKey,dwBlobType,dwFlags,*ppbKeyBlob,&size)) {
		free(*ppbKeyBlob);
		*ppbKeyBlob = NULL;
		return FALSE;
	}
	*pdwBlobLen = size;
	return TRUE;
}

int main(int argc,char **argv)
{
	// prevent \n -> \r\n  for binary data (e.g. DER)
	setmode(fileno(stdout), O_BINARY);

	HCRYPTPROV hProv;
	if (!CryptAcquireContext(
		&hProv,
		NULL,
		MS_STRONG_PROV, // or NULL(?)
		PROV_RSA_FULL,     // or only PROV_RSA_SIG ?
		// MS_ENH_RSA_AES_PROV, // or: MS_STRONG_PROV
		// PROV_RSA_AES,        //     PROV_RSA_FULL
		CRYPT_VERIFYCONTEXT)) { // | CRYPT_SILENT
		error("Failed to aquire crypto context\n");
		return 1;
	}

	WORD keylen=1024;
if (argc==2) {
	int r=atoi(argv[1]);
	if (r>=128) {
		keylen=r;
	}
}
fprintf(stderr, "Generating %d bits ...\n", keylen);

	HCRYPTKEY hKey;
	if (!CryptGenKey(
		hProv,
		CALG_RSA_KEYX, // or: CALG_RSA_SIGN
		(keylen<<16) | CRYPT_EXPORTABLE,
		&hKey)) {
		error("Failed to generate key");
		CryptReleaseContext(hProv, 0);
		return 2;
	}

fprintf(stderr, "Done...\n");

	LPBYTE blob;
	DWORD size;
	if (!exportKey(
		hKey,
		0,
		PRIVATEKEYBLOB, 0,
		&blob,
		&size)) {
		error("Failed to export key");
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProv, 0);
		return 3;
	}
	// privatekey format:  https://msdn.microsoft.com/en-us/library/windows/desktop/aa382021(v=vs.85).aspx  (Enhanced Provider Key BLOBs)

	BLOBHEADER *hdr=(BLOBHEADER *)blob;
	if (hdr->bType==7) { // (pub->magic==0x32415353)
		RSAPUBKEY *pub=(RSAPUBKEY *)((BLOBHEADER *)blob+1);
		int bytes=pub->bitlen/8;
		BYTE *data=(BYTE *)(pub+1);

		// TODO ? rounding?
		RSAPRIV out={
			.n = data, .nLen = bytes,
			.e = (BYTE *)&pub->pubexp, .eLen = sizeof(DWORD), // trick
			.d = data+7*bytes/2, .dLen = bytes,
			.p = data+2*bytes/2, .pLen = bytes/2, // TODO?  swap p,q ?  -> must recalculate qInv...
			.q = data+3*bytes/2, .qLen = bytes/2,
			.dp = data+4*bytes/2, .dpLen = bytes/2,
			.dq = data+5*bytes/2, .dqLen = bytes/2,
			.qinv = data+6*bytes/2, .qinvLen = bytes/2
		};

		// NOTE: output.c has to be compiled with BIGINT_LE!

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
//			printJson(stdout,&out);
//			printJson(stderr,&out); // note: stderr is not O_BINARY
//			fflush(stderr);
//			printDer(stdout,&out);
			printPem(stdout,&out);
		}
	}

	free(blob);

	CryptDestroyKey(hKey);
	CryptReleaseContext(hProv, 0); // retval ignored..

	return 0;
}

