// Copyright 2018 Joyent, Inc.  All rights reserved.

var test = require('tape').test;

var sshpk = require('../lib/index');
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
var sinon = require('sinon');
var asn1 = require('asn1');
var SSHBuffer = require('../lib/ssh-buffer');
var kms = require('../lib/formats/kms');
const { KMS } = require('aws-sdk');
// const fs = require('fs');

var testDir = path.join(__dirname, 'assets');

var GEORGE_KEY, GEORGE_SSH, GEORGE_X509;
var BARRY_KEY;
var JIM_KEY, JIM_SSH, JIM_X509, JIM_X509_TXT;
var EC_KEY, EC_KEY2;
var SUE_KEY;


test('setup', async function (t) {
	var d = fs.readFileSync(path.join(testDir, 'id_dsa'));
	GEORGE_KEY = sshpk.parseKey(d);
	GEORGE_SSH = fs.readFileSync(path.join(testDir, 'george-openssh.pub'));
	GEORGE_X509 = fs.readFileSync(path.join(testDir, 'george-x509.pem'));

	d = fs.readFileSync(path.join(testDir, 'id_dsa2'));
	BARRY_KEY = sshpk.parsePrivateKey(d);

	d = fs.readFileSync(path.join(testDir, 'id_rsa'));
	JIM_KEY = sshpk.parsePrivateKey(d);

	JIM_SSH = fs.readFileSync(path.join(testDir, 'jim-openssh.pub'));
	JIM_X509 = fs.readFileSync(path.join(testDir, 'jim-x509.pem'));
	JIM_X509_TXT = fs.readFileSync(path.join(testDir, 'jim-x509-text.pem'));

	d = fs.readFileSync(path.join(testDir, 'id_ecdsa'));
	EC_KEY = await sshpk.parsePrivateKey(d);
	d = fs.readFileSync(path.join(testDir, 'id_ecdsa2'));
	EC2_KEY = sshpk.parsePrivateKey(d);

	d = fs.readFileSync(path.join(testDir, 'id_ed25519'));
	SUE_KEY = sshpk.parsePrivateKey(d);

	t.end();
});

// test('create rsa self-signed, loopback', function (t) {
// 	var id = sshpk.identityForHost('foobar.com');
// 	var cert = sshpk.createSelfSignedCertificate(id, JIM_KEY);

// 	var x509 = cert.toBuffer('pem');
// 	var cert2 = sshpk.parseCertificate(x509, 'pem');
// 	t.ok(JIM_KEY.fingerprint().matches(cert2.subjectKey));
// 	t.ok(cert2.subjects[0].equals(cert.subjects[0]));

// 	var ossh = cert.toBuffer('openssh');
// 	var cert3 = sshpk.parseCertificate(ossh, 'openssh');
// 	t.ok(JIM_KEY.fingerprint().matches(cert3.subjectKey));
// 	t.ok(cert3.subjects[0].equals(cert.subjects[0]));
// 	t.strictEqual(cert3.subjects[0].hostname, 'foobar.com');

// 	t.end();
// });


test('create ecdsa kms ', async function (t) {
	KMS_KEY = await sshpk.parsePrivateKey('arn:aws:kms:us-west-2:226209437353:key/dedb7685-196b-416d-b36b-4e88f3b30452');
	public_key =KMS_KEY.toPublic().toString('ssh');
	// console.log(KMS_KEY)
	console.log("public_key: ")
	console.log(public_key)
	var id = sshpk.identityForUser('CA');
	cert = await sshpk.createSelfSignedCertificate(id, KMS_KEY);

	var parallels = sshpk.identityForUser('parallels');
	// var ca = sshpk.identityForHost('foobar.com');
	// var cacert = sshpk.createSelfSignedCertificate(ca, EC2_KEY);
	var leaf_cert = await sshpk.createCertificate(parallels, EC_KEY, id, KMS_KEY, {
		lifetime: 90000,
		purposes: [],
		extensions: [
			// These options are the reasons for using a custom fork
			'permit-X11-forwarding',
			'permit-agent-forwarding',
			'permit-port-forwarding',
			// The certificate is usable without these but the shell looks pretty unusable
			'permit-pty',
			'permit-user-rc',
		],
	},);

	var ca_ssh = cert.toBuffer('openssh');
	var leaf_ssh = leaf_cert.toBuffer('openssh');
	// console.log(ca_ssh.toString())
	// console.log(leaf_ssh.toString())
	fs.writeFile('ca_ssh.txt', public_key, (err) => {
		if (err) throw err;
		console.log('ca_ssh.txt has been saved!');
	});

	fs.writeFile('leaf_ssh.txt', leaf_ssh.toString(), (err) => {
		if (err) throw err;
		console.log('leaf_ssh.txt has been saved!');
	});
	t.end();
});



// test('create ecdsa signed, loopback', function (t) {
// 	var id = sshpk.identityForUser('jim');
// 	var ca = sshpk.identityForHost('foobar.com');
// 	var cacert = sshpk.createSelfSignedCertificate(ca, EC2_KEY);
// 	var cert = sshpk.createCertificate(id, EC_KEY, ca, EC2_KEY);

// 	var x509 = cert.toBuffer('pem');
// 	var cert2 = sshpk.parseCertificate(x509, 'pem');
// 	t.ok(EC_KEY.fingerprint().matches(cert2.subjectKey));
// 	t.ok(cert2.subjects[0].equals(cert.subjects[0]));
// 	t.ok(cert2.isSignedBy(cacert));

// 	var ossh = cert.toBuffer('openssh');
// 	var cert3 = sshpk.parseCertificate(ossh, 'openssh');
// 	t.ok(EC_KEY.fingerprint().matches(cert3.subjectKey));
// 	t.ok(cert3.subjects[0].equals(cert.subjects[0]));
// 	t.strictEqual(cert3.subjects[0].uid, 'jim');
// 	t.ok(cert3.isSignedBy(cacert));

// 	t.end();
// });

