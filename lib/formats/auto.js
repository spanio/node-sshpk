// Copyright 2018 Joyent, Inc.

module.exports = {
    read: read,
    write: write
};

let assert = require('assert-plus');
let Buffer = require('safer-buffer').Buffer;
let pem = require('./pem');
let ssh = require('./ssh');
let rfc4253 = require('./rfc4253');
let dnssec = require('./dnssec');
let putty = require('./putty');
let kms = require('./kms');

let DNSSEC_PRIVKEY_HEADER_PREFIX = 'Private-key-format: v1';

async function read(buf, options) {
    if (typeof (buf) === 'string') {
        if (buf.startsWith('arn:aws:kms:'))
            return (kms.read(buf, options));
        if (buf.trim().match(/^[-]+[ ]*BEGIN/))
            return (pem.read(buf, options));
        if (buf.match(/^\s*ssh-[a-z]/))
            return (ssh.read(buf, options));
        if (buf.match(/^\s*ecdsa-/))
            return (ssh.read(buf, options));
        if (buf.match(/^putty-user-key-file-2:/i))
            return (putty.read(buf, options));
        if (findDNSSECHeader(buf))
            return (dnssec.read(buf, options));
        buf = Buffer.from(buf, 'binary');
    } else {
        assert.buffer(buf);
        if (findPEMHeader(buf))
            return (pem.read(buf, options));
        if (findSSHHeader(buf))
            return (ssh.read(buf, options));
        if (findPuTTYHeader(buf))
            return (putty.read(buf, options));
        if (findDNSSECHeader(buf))
            return (dnssec.read(buf, options));
    }
    if (buf.readUInt32BE(0) < buf.length)
        return (rfc4253.read(buf, options));
    throw (new Error('Failed to auto-detect format of key'));
}

function findPuTTYHeader(buf) {
    let offset = 0;
    while (offset < buf.length &&
    (buf[offset] === 32 || buf[offset] === 10 || buf[offset] === 9))
        ++offset;
    if (offset + 22 <= buf.length &&
        buf.slice(offset, offset + 22).toString('ascii').toLowerCase() ===
        'putty-user-key-file-2:')
        return (true);
    return (false);
}

function findSSHHeader(buf) {
    let offset = 0;
    while (offset < buf.length &&
    (buf[offset] === 32 || buf[offset] === 10 || buf[offset] === 9))
        ++offset;
    if (offset + 4 <= buf.length &&
        buf.slice(offset, offset + 4).toString('ascii') === 'ssh-')
        return (true);
    if (offset + 6 <= buf.length &&
        buf.slice(offset, offset + 6).toString('ascii') === 'ecdsa-')
        return (true);
    return (false);
}

function findPEMHeader(buf) {
    let offset = 0;
    while (offset < buf.length &&
    (buf[offset] === 32 || buf[offset] === 10))
        ++offset;
    if (buf[offset] !== 45)
        return (false);
    while (offset < buf.length &&
    (buf[offset] === 45))
        ++offset;
    while (offset < buf.length &&
    (buf[offset] === 32))
        ++offset;
    if (offset + 5 > buf.length ||
        buf.slice(offset, offset + 5).toString('ascii') !== 'BEGIN')
        return (false);
    return (true);
}

function findDNSSECHeader(buf) {
    // private case first
    if (buf.length <= DNSSEC_PRIVKEY_HEADER_PREFIX.length)
        return (false);
    let headerCheck = buf.slice(0, DNSSEC_PRIVKEY_HEADER_PREFIX.length);
    if (headerCheck.toString('ascii') === DNSSEC_PRIVKEY_HEADER_PREFIX)
        return (true);

    // public-key RFC3110 ?
    // 'domain.com. IN KEY ...' or 'domain.com. IN DNSKEY ...'
    // skip any comment-lines
    if (typeof (buf) !== 'string') {
        buf = buf.toString('ascii');
    }
    let lines = buf.split('\n');
    let line = 0;
    /* JSSTYLED */
    while (lines[line].match(/^\;/))
        line++;
    if (lines[line].toString('ascii').match(/\. IN KEY /))
        return (true);
    if (lines[line].toString('ascii').match(/\. IN DNSKEY /))
        return (true);
    return (false);
}

function write(key, options) {
    throw (new Error('"auto" format cannot be used for writing'));
}
