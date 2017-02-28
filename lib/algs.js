// Copyright 2015 Joyent, Inc.

var algInfo = {
	'dsa': {
		parts: ['p', 'q', 'g', 'y'],
		sizePart: 'p'
	},
	'rsa': {
		parts: ['e', 'n'],
		sizePart: 'n'
	},
	'ecdsa': {
		parts: ['curve', 'Q'],
		sizePart: 'Q'
	},
	'ed25519': {
		parts: ['R'],
		normalize: false,
		sizePart: 'R'
	}
};
algInfo['curve25519'] = algInfo['ed25519'];

var algPrivInfo = {
	'dsa': {
		parts: ['p', 'q', 'g', 'y', 'x']
	},
	'rsa': {
		parts: ['n', 'e', 'd', 'iqmp', 'p', 'q']
	},
	'ecdsa': {
		parts: ['curve', 'Q', 'd']
	},
	'ed25519': {
		parts: ['R', 'r'],
		normalize: false
	}
};
algPrivInfo['curve25519'] = algPrivInfo['ed25519'];

var hashAlgs = {
	'md5': true,
	'sha1': true,
	'sha256': true,
	'sha384': true,
	'sha512': true
};

/*
 * taken from
 * http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdfi
 * and
 * http://www.secg.org/sec2-v2.pdf
 */
var curves = {
	'secp256k1': {
		size: 256,
		pkcs8oid: '1.3.132.0.10',
		p: new Buffer(('00' +
			'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
			'FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F').
			replace(/ /g, ''), 'hex'),
		a: new Buffer(('00' +
			'00000000 00000000 00000000 00000000' +
			'00000000 00000000 00000000 00000000').
			replace(/ /g, ''), 'hex'),
		b: new Buffer(('00' +
			'00000000 00000000 00000000 00000000' +
			'00000000 00000000 00000000 00000007').
			replace(/ /g, ''), 'hex'),
		n: new Buffer(('00' +
			'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE' +
			'BAAEDCE6 AF48A03B BFD25E8C D0364141').
			replace(/ /g, ''), 'hex'),
		G: new Buffer(('04' + 
			'79BE667E F9DCBBAC 55A06295 CE870B07' +
			'029BFCDB 2DCE28D9 59F2815B 16F81798' +
			'483ADA77 26A3C465 5DA4FBFC 0E1108A8' +
			'FD17B448 A6855419 9C47D08F FB10D4B8').
			replace(/ /g, ''),'hex')
	},
	'nistp256': {
		size: 256,
		pkcs8oid: '1.2.840.10045.3.1.7',
		p: new Buffer(('00' +
		    'FFFFFFFF 00000001 00000000 00000000' +
		    '00000000 FFFFFFFF FFFFFFFF FFFFFFFF').
		    replace(/ /g, ''), 'hex'),
		a: new Buffer(('00' +
		    'FFFFFFFF 00000001 00000000 00000000' +
		    '00000000 FFFFFFFF FFFFFFFF FFFFFFFC').
		    replace(/ /g, ''), 'hex'),
		b: new Buffer((
		    '5AC635D8 AA3A93E7 B3EBBD55 769886BC' +
		    '651D06B0 CC53B0F6 3BCE3C3E 27D2604B').
		    replace(/ /g, ''), 'hex'),
		s: new Buffer(('00' +
		    'C49D3608 86E70493 6A6678E1 139D26B7' +
		    '819F7E90').
		    replace(/ /g, ''), 'hex'),
		n: new Buffer(('00' +
		    'FFFFFFFF 00000000 FFFFFFFF FFFFFFFF' +
		    'BCE6FAAD A7179E84 F3B9CAC2 FC632551').
		    replace(/ /g, ''), 'hex'),
		G: new Buffer(('04' +
		    '6B17D1F2 E12C4247 F8BCE6E5 63A440F2' +
		    '77037D81 2DEB33A0 F4A13945 D898C296' +
		    '4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16' +
		    '2BCE3357 6B315ECE CBB64068 37BF51F5').
		    replace(/ /g, ''), 'hex')
	},
	'nistp384': {
		size: 384,
		pkcs8oid: '1.3.132.0.34',
		p: new Buffer(('00' +
		    'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
		    'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE' +
		    'FFFFFFFF 00000000 00000000 FFFFFFFF').
		    replace(/ /g, ''), 'hex'),
		a: new Buffer(('00' +
		    'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
		    'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE' +
		    'FFFFFFFF 00000000 00000000 FFFFFFFC').
		    replace(/ /g, ''), 'hex'),
		b: new Buffer((
		    'B3312FA7 E23EE7E4 988E056B E3F82D19' +
		    '181D9C6E FE814112 0314088F 5013875A' +
		    'C656398D 8A2ED19D 2A85C8ED D3EC2AEF').
		    replace(/ /g, ''), 'hex'),
		s: new Buffer(('00' +
		    'A335926A A319A27A 1D00896A 6773A482' +
		    '7ACDAC73').
		    replace(/ /g, ''), 'hex'),
		n: new Buffer(('00' +
		    'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
		    'FFFFFFFF FFFFFFFF C7634D81 F4372DDF' +
		    '581A0DB2 48B0A77A ECEC196A CCC52973').
		    replace(/ /g, ''), 'hex'),
		G: new Buffer(('04' +
		    'AA87CA22 BE8B0537 8EB1C71E F320AD74' +
		    '6E1D3B62 8BA79B98 59F741E0 82542A38' +
		    '5502F25D BF55296C 3A545E38 72760AB7' +
		    '3617DE4A 96262C6F 5D9E98BF 9292DC29' +
		    'F8F41DBD 289A147C E9DA3113 B5F0B8C0' +
		    '0A60B1CE 1D7E819D 7A431D7C 90EA0E5F').
		    replace(/ /g, ''), 'hex')
	},
	'nistp521': {
		size: 521,
		pkcs8oid: '1.3.132.0.35',
		p: new Buffer((
		    '01FFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
		    'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
		    'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
		    'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
		    'FFFF').replace(/ /g, ''), 'hex'),
		a: new Buffer(('01ff' +
		    'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
		    'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
		    'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
		    'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFC').
		    replace(/ /g, ''), 'hex'),
		b: new Buffer(('51' +
		    '953EB961 8E1C9A1F 929A21A0 B68540EE' +
		    'A2DA725B 99B315F3 B8B48991 8EF109E1' +
		    '56193951 EC7E937B 1652C0BD 3BB1BF07' +
		    '3573DF88 3D2C34F1 EF451FD4 6B503F00').
		    replace(/ /g, ''), 'hex'),
		s: new Buffer(('00' +
		    'D09E8800 291CB853 96CC6717 393284AA' +
		    'A0DA64BA').replace(/ /g, ''), 'hex'),
		n: new Buffer(('01ff' +
		    'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF' +
		    'FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFA' +
		    '51868783 BF2F966B 7FCC0148 F709A5D0' +
		    '3BB5C9B8 899C47AE BB6FB71E 91386409').
		    replace(/ /g, ''), 'hex'),
		G: new Buffer(('04' +
		    '00C6 858E06B7 0404E9CD 9E3ECB66 2395B442' +
		         '9C648139 053FB521 F828AF60 6B4D3DBA' +
		         'A14B5E77 EFE75928 FE1DC127 A2FFA8DE' +
		         '3348B3C1 856A429B F97E7E31 C2E5BD66' +
		    '0118 39296A78 9A3BC004 5C8A5FB4 2C7D1BD9' +
		         '98F54449 579B4468 17AFBD17 273E662C' +
		         '97EE7299 5EF42640 C550B901 3FAD0761' +
		         '353C7086 A272C240 88BE9476 9FD16650').
		    replace(/ /g, ''), 'hex')
	}
};

module.exports = {
	info: algInfo,
	privInfo: algPrivInfo,
	hashAlgs: hashAlgs,
	curves: curves
};
