// Copyright 2017 Joyent, Inc.

module.exports = {
	read: read,
	verify: verify,
	sign: sign,
	signAsync: signAsync,
	write: write,

	/* Internal private API */
	// fromBuffer: fromBuffer,
	toBuffer: toBuffer,
};

var assert = require('assert-plus');
var SSHBuffer = require('../ssh-buffer');
var crypto = require('crypto');
var Buffer = require('safer-buffer').Buffer;
var algs = require('../algs');
var Key = require('../key');
var ecdsa = require('./pkcs1')
var PrivateKey = require('../private-key');
var Identity = require('../identity');
var rfc4253 = require('./rfc4253');
var Signature = require('../signature');
var utils = require('../utils');
var Certificate = require('../certificate');
var asn1 = require('asn1')
const { KMSClient, ListKeysCommand, GetPublicKeyCommand, SignCommand } = require("@aws-sdk/client-kms");
const pkcs1 = require('./pkcs1');

function verify(cert, key) {
	/*
	 * We always give an issuerKey, so if our verify() is being called then
	 * there was no signature. Return false.
	 */
	return (false);
}

var TYPES = {
	'user': 1,
	'host': 2
};
Object.keys(TYPES).forEach(function (k) { TYPES[TYPES[k]] = k; });

var ECDSA_ALGO = /^ecdsa-sha2-([^@-]+)-cert-v01@openssh.com$/;

async function kms_init() {
	const client = new KMSClient({ region: "us-west-2" });
	const command = new ListKeysCommand();

	try {
		const data = await client.send(command);
		console.log(data);
	} catch (error) {
		console.log(error); // an error occurred
	}

}



async function read(buf, options) {
	// Read the public key and add the parts here.
	const client = new KMSClient({ region: "us-west-2" });
	const command = new ListKeysCommand();

	try {
		const data = await client.send(new GetPublicKeyCommand({ KeyId: buf }));
		var publicKey = Buffer.from(data.PublicKey);
		// console.log(publicKey); // successful response
		var input = publicKey
		var der = new asn1.BerReader(publicKey)
		der.originalInput = input;

		der.readSequence();
		ec_publickey = pkcs1.readPkcs1('ECDSA', 'public', der)
		ec_publickey.parts.push({ name: 'arn', data: buf })
		// console.log(publicKey)
		priv_key = new PrivateKey(ec_publickey);
		return priv_key

	} catch (err) {
		console.log(err); // an error occurred
	}

}


function sign(cert, key) {
	const client = new KMSClient({ region: "us-west-2" });
	console.log(key.parts.find(element => element.name === 'arn').data.toString())
	const command = new SignCommand({
		KeyId: key.parts.find(element => element.name === 'arn').data.toString(),
		Message: Buffer.from(cert),
		MessageType: "RAW",
		SigningAlgorithm: "ECDSA_SHA_256"
	});

	return client.send(command)
		.then(data => {
			const signature = Buffer.from(data.Signature);
			console.log(signature); // successful response
			sig = Signature.parse(signature, key.type, 'asn1');
			sig.hashAlgorithm = 'sha256';
			sig.curve = key.curve;
			return sig;
		})
		.catch(err => {
			console.log(err); // an error occurred
			throw err;
		});
}

function signAsync(cert, signer, done) {
	if (cert.signatures.openssh === undefined)
		cert.signatures.openssh = {};
	try {
		var blob = toBuffer(cert, true);
	} catch (e) {
		delete (cert.signatures.openssh);
		done(e);
		return;
	}
	var sig = cert.signatures.openssh;

	signer(blob, function (err, signature) {
		if (err) {
			done(err);
			return;
		}
		try {
			/*
			 * This will throw if the signature isn't of a
			 * type/algo that can be used for SSH.
			 */
			signature.toBuffer('ssh');
		} catch (e) {
			done(e);
			return;
		}
		sig.signature = signature;
		done();
	});
}

function write(cert, options) {
	if (options === undefined)
		options = {};

	var blob = toBuffer(cert);
	var out = getCertType(cert.subjectKey) + ' ' + blob.toString('base64');
	if (options.comment)
		out = out + ' ' + options.comment;
	return (out);
}


function toBuffer(cert, noSig) {
	assert.object(cert.signatures.openssh, 'signature for openssh format');
	var sig = cert.signatures.openssh;

	if (sig.nonce === undefined)
		sig.nonce = crypto.randomBytes(16);
	var buf = new SSHBuffer({});
	buf.writeString(getCertType(cert.subjectKey));
	buf.writeBuffer(sig.nonce);

	var key = cert.subjectKey;
	var algInfo = algs.info[key.type];
	algInfo.parts.forEach(function (part) {
		buf.writePart(key.part[part]);
	});

	buf.writeInt64(cert.serial);

	var type = cert.subjects[0].type;
	assert.notStrictEqual(type, 'unknown');
	cert.subjects.forEach(function (id) {
		assert.strictEqual(id.type, type);
	});
	type = TYPES[type];
	buf.writeInt(type);

	if (sig.keyId === undefined) {
		sig.keyId = cert.subjects[0].type + '_' +
			(cert.subjects[0].uid || cert.subjects[0].hostname);
	}
	buf.writeString(sig.keyId);

	var sub = new SSHBuffer({});
	cert.subjects.forEach(function (id) {
		if (type === TYPES.host)
			sub.writeString(id.hostname);
		else if (type === TYPES.user)
			sub.writeString(id.uid);
	});
	buf.writeBuffer(sub.toBuffer());

	buf.writeInt64(dateToInt64(cert.validFrom));
	buf.writeInt64(dateToInt64(cert.validUntil));

	var exts = sig.exts;
	if (exts === undefined)
		exts = [];

	var extbuf = new SSHBuffer({});
	exts.forEach(function (ext) {
		if (ext.critical !== true)
			return;
		extbuf.writeString(ext.name);
		extbuf.writeBuffer(ext.data);
	});
	buf.writeBuffer(extbuf.toBuffer());

	extbuf = new SSHBuffer({});
	exts.forEach(function (ext) {
		if (ext.critical === true)
			return;
		extbuf.writeString(ext.name);
		if ('data' in ext) {
			extbuf.writeBuffer(ext.data);
		} else {
			extbuf.writeString('');
		}
	});
	buf.writeBuffer(extbuf.toBuffer());

	/* reserved */
	buf.writeBuffer(Buffer.alloc(0));

	sub = rfc4253.write(cert.issuerKey);
	buf.writeBuffer(sub);

	if (!noSig)
		buf.writeBuffer(sig.signature.toBuffer('ssh'));

	return (buf.toBuffer());
}

function getAlg(certType) {
	if (certType === 'ssh-rsa-cert-v01@openssh.com')
		return ('rsa');
	if (certType === 'ssh-dss-cert-v01@openssh.com')
		return ('dsa');
	if (certType.match(ECDSA_ALGO))
		return ('ecdsa');
	if (certType === 'ssh-ed25519-cert-v01@openssh.com')
		return ('ed25519');
	throw (new Error('Unsupported cert type ' + certType));
}

function getCertType(key) {
	if (key.type === 'rsa')
		return ('ssh-rsa-cert-v01@openssh.com');
	if (key.type === 'dsa')
		return ('ssh-dss-cert-v01@openssh.com');
	if (key.type === 'ecdsa')
		return ('ecdsa-sha2-' + key.curve + '-cert-v01@openssh.com');
	if (key.type === 'ed25519')
		return ('ssh-ed25519-cert-v01@openssh.com');
	throw (new Error('Unsupported key type ' + key.type));
}
