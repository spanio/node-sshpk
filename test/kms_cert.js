let test = require('tape').test;
let sshpk = require('../lib/index');
let fs = require('fs');
let path = require('path');
let kms = require('../lib/formats/kms');
const {PrivateKey} = require("../lib");
let testDir = path.join(__dirname, 'assets');

let EC_KEY;
const KMS_KEY_ARN = 'arn:aws:kms:us-west-2:226209437353:key/dedb7685-196b-416d-b36b-4e88f3b30452';


test('setup', async function (t) {
	const d = fs.readFileSync(path.join(testDir, 'local_developer_key.pub'));
	EC_KEY = await sshpk.parseKey(d);
	t.end();
});

test('read a public key from kms', async function (t) {
	const publicKey = await kms.read(KMS_KEY_ARN, {});
	console.log('publicKey: ', publicKey)

	const publicKeySsh = publicKey.toString('ssh');
	console.log('ssh format: ', publicKeySsh)

	t.end();
});

test('create a certificate from kms', async function (t) {
	const id = sshpk.identityForUser("CA");
	const serialNumber = "gen3-panel-serial-12345678"
	const parallels = [
		sshpk.identityForUser("span-" + serialNumber),
	];
	const publicKey = await kms.read(KMS_KEY_ARN, {});

	const leafCert = await sshpk.createCertificate(parallels, EC_KEY, id, publicKey, {
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
	});

	const leafCertSsh = leafCert.toString('openssh')
	fs.writeFile('leaf_ssh.txt', leafCertSsh, (err) => {
		if (err) throw err;
		console.log('leaf_ssh.txt has been saved!');
	});

	const publicKeySsh = publicKey.toString('ssh');
	fs.writeFile('public_key_ssh.txt', publicKeySsh, (err) => {
		if (err) throw err;
		console.log('public_key_ssh.txt has been saved!');
	});

	t.end();
});

test('create ecdsa kms ', async function (t) {
	const id = sshpk.identityForUser('CA');
	const publicKey = await kms.read(KMS_KEY_ARN, {});
	const wrapperPrivateKey = new PrivateKey(publicKey)
	const cert = await sshpk.createSelfSignedCertificate(id, wrapperPrivateKey);
	console.log("cert: ", cert)
	t.end();
});

