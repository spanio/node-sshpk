// Copyright 2017 Joyent, Inc.

module.exports = {
    read: read,
    verify: verify,
    sign: sign,
    write: write,
    toBuffer: toBuffer,
};

let assert = require('assert-plus');
let SSHBuffer = require('../ssh-buffer');
let crypto = require('crypto');
let Buffer = require('safer-buffer').Buffer;
let algs = require('../algs');
let rfc4253 = require('./rfc4253');
let Signature = require('../signature');
let asn1 = require('asn1')
const {KMSClient, GetPublicKeyCommand, SignCommand} = require("@aws-sdk/client-kms");
const pkcs1 = require('./pkcs1');

const types = { 1: 'user', 2: 'host', user: 1, host: 2 }


/**
 * Get the public key from a KMS key ARN
 * @param keyArn
 * @returns {Promise<Key>}
 */
async function read(keyArn, _) {
    const client = new KMSClient();
    const command = new GetPublicKeyCommand({KeyId: keyArn});

    return await client
        .send(command)
        .then(({PublicKey: publicKey}) => {
            const publicKeyDer = new asn1.BerReader(Buffer.from(publicKey));
            publicKeyDer.readSequence();

            const ecPublicKey
                = pkcs1.readPkcs1('ECDSA', 'public', publicKeyDer);
            ecPublicKey.parts.push({name: 'arn', data: keyArn});
            console.debug("EC Public Key: ", ecPublicKey);

            return ecPublicKey;
        })
        .catch(err => {
            console.warn(err); // an error occurred
            throw err;
        });
}

/*
 * We always give an issuerKey, so if our verify() is being called then
 * there was no signature. Return false.
 */
function verify() {
    return false;
}

async function sign(cert, key) {
    const client = new KMSClient();
    const keyArn = key.parts.find(element => element.name === 'arn').data.toString()

    console.debug("Signing with key", keyArn);
    const command = new SignCommand({
        KeyId: keyArn,
        Message: Buffer.from(cert),
        MessageType: "RAW",
        SigningAlgorithm: "ECDSA_SHA_256"
    });

    return client.send(command)
        .then(data => {
            const signature = Buffer.from(data.Signature);
            console.trace(signature); // successful response

            const sig = Signature.parse(signature, key.type, 'asn1');
            sig.hashAlgorithm = 'sha256';
            sig.curve = key.curve;
            return sig;
        })
        .catch(err => {
            console.error(err); // an error occurred
            throw err;
        });
}

function write(cert, options) {
    if (options === undefined) options = {};

    const blob = toBuffer(cert);
    let out = getCertType(cert.subjectKey) + ' ' + blob.toString('base64');
    if (options.comment) {
        out = out + ' ' + options.comment;
    }
    return (out);
}

function toBuffer(cert, noSig) {
    assert.object(cert.signatures.openssh, 'signature for openssh format');
    const sig = cert.signatures.openssh;

    if (sig.nonce === undefined)
        sig.nonce = crypto.randomBytes(16);
    let buf = new SSHBuffer({});
    buf.writeString(getCertType(cert.subjectKey));
    buf.writeBuffer(sig.nonce);

    const key = cert.subjectKey;
    const algInfo = algs.info[key.type];
    algInfo.parts.forEach(function (part) {
        buf.writePart(key.part[part]);
    });

    buf.writeInt64(cert.serial);

    let type = cert.subjects[0].type;
    assert.notStrictEqual(type, 'unknown');

    cert.subjects.forEach(function (id) {
        assert.strictEqual(id.type, type);
    });

    type = types[type];
    buf.writeInt(type);

    if (sig.keyId === undefined) {
        sig.keyId = cert.subjects[0].type + '_' +
            (cert.subjects[0].uid || cert.subjects[0].hostname);
    }
    buf.writeString(sig.keyId);

    let sub = new SSHBuffer({});
    cert.subjects.forEach(function (id) {
        if (type === types.host)
            sub.writeString(id.hostname);
        else if (type === types.user)
            sub.writeString(id.uid);
    });
    buf.writeBuffer(sub.toBuffer());

    buf.writeInt64(dateToInt64(cert.validFrom));
    buf.writeInt64(dateToInt64(cert.validUntil));

    let exts = sig.exts;
    if (exts === undefined)
        exts = [];

    let extbuf = new SSHBuffer({});
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
