#include "output.h"
#include <string.h>
#include <stdlib.h>

//#define BIGINT_LE

typedef struct {
	const char *name;
	unsigned char *buf;
	int len;
} OUTDATA;

// ret must be OUTDATA [9] (at least)
static void rsapriv2Out(OUTDATA *ret,const RSAPRIV *rsa)
{
// assert(rsa);
	// RFC 3447 (pkcs1 privkey):
	ret[0]=(OUTDATA){"n",rsa->n,rsa->nLen};
	ret[1]=(OUTDATA){"e",rsa->e,rsa->eLen};
	ret[2]=(OUTDATA){"d",rsa->d,rsa->dLen};
	ret[3]=(OUTDATA){"p",rsa->p,rsa->pLen};
	ret[4]=(OUTDATA){"q",rsa->q,rsa->qLen};
	ret[5]=(OUTDATA){"dp",rsa->dp,rsa->dpLen};
	ret[6]=(OUTDATA){"dq",rsa->dq,rsa->dqLen};
	ret[7]=(OUTDATA){"qinv",rsa->qinv,rsa->qinvLen};
	ret[8]=(OUTDATA){NULL};
	
	// shortest representation
	int i;
	for (i=0; ret[i].name; i++) {
#ifndef BIGINT_LE
		while ( (ret[i].len>0)&&(ret[i].buf[0]==0) ) {
			ret[i].buf++;
#else
		while ( (ret[i].len>0)&&(ret[i].buf[ret[i].len-1]==0) ) {
#endif
			ret[i].len--;
		}
	}
}

void printJson(FILE *f,const RSAPRIV *rsa)
{
	OUTDATA out[9];
	rsapriv2Out(out,rsa);

	int i,j;
	for (i=0; out[i].name; i++) {
		if (i==0) {
			fprintf(f,"{");
		} else {
			fprintf(f,",");
		}
#ifndef BIGINT_LE
		fprintf(f,"\"%s\":[%d",out[i].name,out[i].buf[0]);
		for (j=1; j<out[i].len; j++) {
			fprintf(f,",%d",out[i].buf[j]);
		}
		fprintf(f,"]");
#else
		fprintf(f,"\"%s\":[",out[i].name);
		for (j=out[i].len-1; j>0; j--) {
			fprintf(f,"%d,",out[i].buf[j]);
		}
		fprintf(f,"%d]",out[i].buf[0]);
#endif
	}
	fprintf(f,"}\n");
}

// supports only tagTag<31; 0<=tagLength, <8**255
static unsigned char *derTag(unsigned char *ret,unsigned char tagClass,unsigned char tagPC,unsigned char tagTag,unsigned int tagLength)
{
	ret[0]=((tagClass&0x02)<<6)|((tagPC&0x01)<<5)|(tagTag&0x1f);
	if (tagLength<0x80) { // short
		ret[1]=tagLength;
		return ret+2;
	} // else: long
	unsigned int i=0,tmp=tagLength;
	unsigned char buf[sizeof(int)];
	while (tmp>0) {
		buf[sizeof(int)-1-i]=tmp&0xff;
		tmp>>=8;
		i++;
	}
	ret[1]=0x80+i;
	memcpy(ret+2,buf+sizeof(int)-i,i);
	return ret+2+i;
}

static unsigned int derTagLength(unsigned int tagLength)
{
	if (tagLength<0x80) { // short
		return 2+tagLength;
	} // else: long
	unsigned int i=0,tmp=tagLength;
	while (tmp>0) {
		tmp>>=8;
		i++;
	}
	return 2+i+tagLength;
}

static int derUintLength(unsigned char *buf,int len)
{
	if (len==0) { // treat as single 0
		return 1;
	}
#ifndef BIGINT_LE
	if (buf[0]>=0x80) { // prevent signed
#else
	if (buf[len-1]>=0x80) { // prevent signed
#endif
		return len+1;
	}
	return len;
}

static unsigned char *derUint(unsigned char *ret,unsigned char *buf,int len)
{
	ret=derTag(ret,0,0,2,derUintLength(buf,len)); // INTEGER
	if (len==0) {
		*ret++=0;
		return ret;
	}
#ifndef BIGINT_LE
	if (buf[0]>=0x80) { // prevent signed
		*ret++=0;
	}
	memcpy(ret,buf,len);
	return ret+len;
#else
	if (buf[len-1]>=0x80) { // prevent signed
		*ret++=0;
	}
	int i;
	for (i=len; i>0; i--) {
		*ret++=buf[i-1];
	}
	return ret;
#endif
}

unsigned char *writeDer(const RSAPRIV *rsa,int *len)
{
// assert(len);
	OUTDATA out[9];
	rsapriv2Out(out,rsa);

	// SEQUENCE { INTEGER(0) INTEGER(n) INTEGER(e) ... d p q dP dQ dInv }
	// or: pkcs8 privkey [RFC5209]: SEQUENCE { INTEGER{v1(0)} rsaEncryption OCTET STRING(raw pkcs1 data) [SET OF attributes] }

	// calculate sequence size
	int i,slen=0;
	slen+=derTagLength(1); // INT(0) length
	for (i=0; out[i].name; i++) {
		slen+=derTagLength(derUintLength(out[i].buf,out[i].len));
	}

	*len=derTagLength(slen);
	unsigned char *ret=malloc(*len),*pos=ret;
	if (!ret) {
		return NULL;
	}

	// write
	pos=derTag(pos,0,1,16,slen); // SEQUENCE
	pos=derTag(pos,0,0,2,1); // INTEGER(0)
	*pos++=0;
	for (i=0; out[i].name; i++) {
		pos=derUint(pos,out[i].buf,out[i].len);
	}
	return ret;
}

void printDer(FILE *f,const RSAPRIV *rsa)
{
	int len;
	unsigned char *data=writeDer(rsa,&len);
	if (!data) {
		return;
	}
	fwrite(data,len,1,f);
	free(data);
}

static inline void ENC4(int a,char *buf)
{
  static char *b64t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  buf[0]=b64t[(a>>18)&0x3f];
  buf[1]=b64t[(a>>12)&0x3f];
  buf[2]=b64t[(a>>6)&0x3f];
  buf[3]=b64t[a&0x3f];
}

void printPem(FILE *f,const RSAPRIV *rsa)
{
	int len;
	unsigned char *data=writeDer(rsa,&len),*pos=data;
	if (!data) {
		return;
	}

#define LINELEN 16  // *4   [or: 19]
	fprintf(f,"-----BEGIN RSA PRIVATE KEY-----\n");
	int i=(len-1)/(3*LINELEN),j;
	char buf[4];
	for (; i>0; i--) {
		for (j=0; j<LINELEN; j++,pos+=3) {
			ENC4((pos[0]<<16)+(pos[1]<<8)+pos[2],buf);
			fwrite(buf,4,1,f);
		}
		fprintf(f,"\n");
	}
	for (j=(data+len-pos)/3; j>0; j--,pos+=3) {
		ENC4((pos[0]<<16)+(pos[1]<<8)+pos[2],buf);
		fwrite(buf,4,1,f);
	}
	if (pos+2==data+len) {
		ENC4((pos[0]<<16)+(pos[1]<<8),buf);
		buf[3]='=';
		fwrite(buf,4,1,f);
	} else if (pos+1==data+len) {
		ENC4((pos[0]<<16),buf);
		buf[2]='=';
		buf[3]='=';
		fwrite(buf,4,1,f);
	}
	fprintf(f,"\n");
	fprintf(f,"-----END RSA PRIVATE KEY-----\n");
	free(data);
}

