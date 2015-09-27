
var fs=require('fs');

function loadKey(filename) {
	var data=fs.readFileSync(filename,'ascii').split('\n');
	for (var i=0, len=data.length; i<len; i++) {
		if (data[i].match(/-BEGIN RSA PRIVATE KEY-/)) {
			for (var j=0; j<len; j++) {
				if (data[j].match(/-END RSA PRIVATE KEY-/)) {
					// found
					return new Buffer(data.slice(i+1,j).join(''),'base64');
				}
			}
		}
	}
	return false; // not found
}

var cproc=require('child_process');
function generateKey(bits,cb) {
	cproc.execFile('./genrsa',[bits,'-d'],{
		// cwd: '...'
//		encoding: 'buffer' // needs >=0.12
		encoding: 'binary'
	},function(err,stdout,stderr) {
//		console.log(new Buffer(stdout).toString('base64'));
//		process.stdout.write(stdout);
	//	process.stdout.write(new Buffer(stdout,'binary')); // also works with 'buffer'
		cb(new Buffer(stdout,'binary'));
	});
}


function readDerLength(data,pos,end) {
	if (pos>=end) {
		throw new Error('Premature end');
	}
	var length=data[pos];
	if (length==0) { // indefinite
		throw new Error('Unsupported: indefinite length');
	} else if (length&0x80) { // long
		if (length==0xff) {
			throw new Error('Unsupported length');
		}
		length&=0x7f;
		pos++;
		if (pos+length>end) {
			throw new Error('Premature end');
		} else if (length>4) {
			throw new Error('Excessive length value');
		}
		var ret=0;
		for (var i=0; i<length; i++,pos++) {
			ret<<=8;
			ret|=data[pos];
		}
		if (ret<0) {
			throw new Error('Length overflow');
		}
		return [pos,ret];
	} else { // short
		return [pos+1,length];
	}
}

function readDerInteger(data,pos,end) {
	if (data[pos]!=0x02) { // 00 0 00010  Integer
		throw new Error('Expected Integer');
	}
	var l=readDerLength(data,pos+1,end);
	if (l[0]+l[1]>end) {
		throw new Error('Integer too long');
	}
	return [l[0]+l[1],data.slice(l[0],l[0]+l[1])];
}

function readDerRsaKey(data) {
	if (data[0]!=0x30) { // 00 1 10000  Sequence
		throw new Error('Expected Sequence');
	}
	var l0=readDerLength(data,1,data.length);
	var pos=l0[0],end=l0[0]+l0[1];
	if (end>data.length) {
		throw new Error('Sequence too long');
	} else if (end<data.length) {
		throw new Error('Trailing garbage?');
	}

	// expect INT(0)
	if (pos+3>end) {
		throw new Error('Too short');
	} else if ( (data[pos]!=0x02)||(data[pos+1]!=0x01)||(data[pos+2]!=0x00) ) {
		throw new Error('Expected Int(0)');
	}
	pos+=3;

	// read integers
	var ret={};
	var keys=['n','e','d','p','q','dp','dq','qinv'];
	for (var i=0,len=keys.length; i<len; i++) {
		var l1=readDerInteger(data,pos,end);
		ret[keys[i]]=l1[1];
		pos=l1[0];
	}

	if (pos!=end) {
		throw new Error('Unfinished sequence');
	}
	return ret;
}

/*
generateKey(128,function(data) {
	var key=readDerRsaKey(data);
console.log(data.toString('hex'));
	console.log(key);
});
*/

var data=loadKey('out1');
//console.log(readDerRsaKey(data));



  // TODO? not needed because we can first serialize childs...
function derTagLength(tagLength) {
	if (tagLength<0x80) { // short
		return 2+tagLength;
	} // else: long
	var i=0, tmp=tagLength;
	while (tmp>0) {
		tmp>>=8;
		i++;
	}
	return 2+i+tagLength;
}

function derUintLength(buf) {
	if (!buf.length) { // treat as single 0
		return 1;
	}
	if (buf[0]>=0x80) { // prevent signed
		return buf.length+1;
	}
	return buf.length;
}

function writeDerTag(tagClass,tagPC,tagTag,tagLength) {
	var b0=((tagClass&0x02)<<6)|((tagPC&0x01)<<5)|(tagTag&0x1f);
	if (tagLength<0x80) { // short
		return new Buffer([b0,tagLength]);
	} // else: long
	var i=0, tmp=tagLength, ret=[];
	while (tmp>0) {
		ret.push(tmp&0xff);
		tmp>>=8;
		i++;
	}
	ret.push(0x80+i);
	ret.push(b0);
	return new Buffer(ret.reverse());
}

function writeDerUint(buf) {
	if (!buf.length) { // treat as single 0
		return new Buffer([2,1,0]); // writeDerTag(0,0,2,1), 0
	}
	var ret=[
		writeDerTag(0,0,2,derUintLength(buf)) // INTEGER
	];
	if (buf[0]>=0x80) { // prevent signed
		ret.push(new Buffer([0]));
	}
	ret.push(buf);
	return Buffer.concat(ret);
}

// TODO? relative
function writeDerOid(oid) {
	if ( (oid.length<2)||(oid[0]<0)||(oid[0]>2)||(oid[1]<0)||(oid[1]>=40) ) {
		throw new Error('Bad OID');
	}
	var ret=[0x06,0,oid[0]*40+oid[1]]; // Object Identifier
	for (var i=2, len=oid.length; i<len; i++) {
		var val=oid[i];
		if (val<0) {
			throw new Error('Bad OID');
		}
		var tmp=[val&0x7f];
		val>>=7;
		while (val>0) {
			tmp.push(val&0x7f|0x80);
			val>>=7;
		}
		ret.push.apply(ret,tmp.reverse());
	}
if (ret.length-2>=0x80) { throw new Error('Very long OID not supported yet'); }
	ret[1]=ret.length-2;
	return new Buffer(ret);
}


function pemb64(buf,size/*=16*/) {
	var ret=[];
	size=size || 16;  // *4
	for (var i=0, len=buf.length; i<len; i+=3*size) {
		ret.push(buf.slice(i,i+3*size).toString('base64'));
	}
	return ret.join('\n');
}

function writeDerRsaPubKey(key,spki/*=false*/) {
/* TODO?
	var n=writeDerUint(key.n),
	    e=writeDerUint(key.e);
	var ret=[writeDerTag(0,1,16,n.length,e.length),n,e];
*/
	var slen=derTagLength(derUintLength(key.n))+
	         derTagLength(derUintLength(key.e));

	// rsa(pkcs1) pubkey:  SEQUENCE { INTEGER(n) INTEGER(e) }
	// pkcs8/spki pubkey:  SEQUENCE { SEQUENCE { rsaEncryption(1.2.840.113549.1.1.1 = 06 09 2A 86 48 86 F7 0D 01 01 01) [optional parameters/NULL] } BIT STRING(raw pkcs1 data) }
	var ret=[];
	ret.push(writeDerTag(0,1,16,slen)); // Sequence
	ret.push(writeDerUint(key.n));
	ret.push(writeDerUint(key.e));

	if (spki) {
		ret.unshift(new Buffer([0])); // Bit String first octet: unused bits at end: 0
		slen++;
		ret.unshift(writeDerTag(0,0,3,derTagLength(slen))); // Bit String
		// ret.unshift(writeDerTag(0,0,5,0)); // Null (optional...)
		var oid=writeDerOid([1,2,840,113549,1,1,1]); // rsaEncryption
		ret.unshift(oid);
		ret.unshift(writeDerTag(0,1,16,oid.length)); // .length+2
		ret.unshift(writeDerTag(0,1,16,derTagLength(derTagLength(slen))+derTagLength(oid.length))); // .length+2
	}
	return Buffer.concat(ret);
}

function writePemRsaPubKey(key,spki/*=false*/) {
	var buf=writeDerRsaPubKey(key,spki);
	if (spki) {
		return '-----BEGIN PUBLIC KEY-----\n'+
		       pemb64(buf)+
		       '\n-----END PUBLIC KEY-----\n';
	} else {
		// HINT: openssl rsa -RSAPublicKey_in ...
		return '-----BEGIN RSA PUBLIC KEY-----\n'+
		       pemb64(buf)+
		       '\n-----END RSA PUBLIC KEY-----\n';
	}
}

//process.stdout.write(writeDerRsaPubKey(readDerRsaKey(data),true));
console.log(writePemRsaPubKey(readDerRsaKey(data),true));

/*  TODO ?
// TODO? json -> buffer...

function writeDerRsaKey(key) {  // -> inverse of readDerRsaKey()
	// SEQUENCE { INTEGER(0) INTEGER(n) INTEGER(e) ... d p q dP dQ dInv }
	// or: pkcs8 privkey [RFC5209]: SEQUENCE { INTEGER{v1(0)} rsaEncryption OCTET STRING(raw pkcs1 data) [SET OF attributes] }
}

function writePemRsaKey(key) {
	var buf=writeDerRsaKey(key);
	return '-----BEGIN RSA PRIVATE KEY-----\n'+
	       pemb64(buf)+
	       '\n-----END RSA PRIVATE KEY-----\n';
}
*/


// SSH

function signify(num) {
	if (num[0]>0x80) {
		return Buffer.concat(new Buffer([0]),num);
	}
	return num;
}

function chunk(str,len) {
	var ret=[];
	while (str.length>len) {
		ret.push(str.substr(0,len));
		str=str.substr(len);
	}
	ret.push(str);
	return ret;
}

function writeSshPubKey(key,fmt/*='oneLine'*/) { // or fmt=='raw' or fmt=='ssh2'
	var e=signify(key.e),n=signify(key.n);

	var type='ssh-rsa';
	var buf1=new Buffer(type.length+2*4);
	var pos=0;
	buf1.writeUInt32BE(type.length,pos);
	pos+=4;
	buf1.write(type,pos);
	pos+=type.length;

	buf1.writeUInt32BE(e.length,pos);
	// assert(pos+4==buf1.length);

	var buf2=new Buffer(4);
	buf2.writeUInt32BE(n.length,0);

	var buf=Buffer.concat([buf1,e,buf2,n]);

	fmt=fmt || 'oneLine';
	if (fmt==='oneLine') {
		return type+' '+buf.toString('base64')+'\n';  // TODO?  +' key@name\n';
	} else if (fmt==='raw') {
		return buf;
	} // else: ssh2 block
	var bits=n.length*8;
	if (n[0]==0) { // TODO? more precise?
		bits-=8;
	}
	return '---- BEGIN SSH2 PUBLIC KEY ----\n'+
	       'Comment: "'+bits+'-bit RSA"\n'+
//	       pemb64(buf,17)+  // openssh: 17.5 ...
	       chunk(buf.toString('base64'),70).join('\n')+
	       '\n---- END SSH2 PUBLIC KEY ----\n';
}

// TODO... function readSshPubKey(data) ...   2-3 formats (cf. writeSshPubKey) ...

var crypto=require('crypto');
// e.g. for "1024 17:9f:89:2b:6d:13:55:cc:b0:56:12:38:97:37:7e:59 ppkk (RSA)"  or "1024 SHA256:...base64" or "1024 MD5:0f:12:..."
function sshPubKeyFingerprint(key,algo/*='md5'*/) {
	var hash=crypto.createHash(algo || 'md5');
	// TODO? fingerprint from pubkey only  --- ... e.g. via readSshPubKey... TODO
	hash.update(writeSshPubKey(key,'raw'));
	return hash.digest('hex');
}
// NOTE: Amazon EC2 uses different hash (of private key!): http://blog.jbrowne.com/?p=23#comment-817

//console.log(writeSshPubKey(readDerRsaKey(data),!false));
console.log(chunk(sshPubKeyFingerprint(readDerRsaKey(data)),2).join(':'));

