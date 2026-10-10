(function (root) {
    'use strict';

    const QUIC_V1_VERSION = [0x00, 0x00, 0x00, 0x01];
    const QUIC_V1_SALT = hexToBytes('38762cf7f55934b34d179ae6a4c80cadccbb7f0a');
    const DCID_LEN = 8;
    const PN_LEN = 2;
    const TAG_LEN = 16;
    const KEEP_PREFIX = (4 - PN_LEN) + 16;
    const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])$/;

    function hexToBytes(hex) {
        const out = new Uint8Array(hex.length / 2);
        for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
        return out;
    }

    function bytesToHex(bytes) {
        let s = '';
        for (const b of bytes) s += b.toString(16).padStart(2, '0');
        return s;
    }

    function getCrypto() {
        const c = root.crypto || (typeof require === 'function' ? require('crypto').webcrypto : null);
        if (!c || !c.subtle) {
            throw new Error('Web Crypto недоступен. Откройте страницу по https:// или через localhost.');
        }
        return c;
    }

    function randomBytes(n) {
        const a = new Uint8Array(n);
        getCrypto().getRandomValues(a);
        return a;
    }

    const u16 = (n) => [(n >> 8) & 0xff, n & 0xff];
    const u24 = (n) => [(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
    const varint2 = (n) => u16(0x4000 | n);

    function normalizeDomain(raw) {
        let s = String(raw || '').trim().toLowerCase();
        if (!s) return { ok: false, error: 'Введите домен.' };

        s = s
            .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
            .replace(/[\/?#].*$/, '')        
            .replace(/^.*@/, '')               
            .replace(/:\d+$/, '')               
            .replace(/\.$/, '');            

        try {
            s = new URL('http://' + s).hostname;  
        } catch (e) {
            return { ok: false, error: 'Некорректный домен.' };
        }

        if (!HOST_RE.test(s)) {
            return { ok: false, error: 'Некорректный домен. Пример: www.apple.com, microsoft.com, ya.ru' };
        }
        return { ok: true, host: s };
    }

    function Builder() {
        this.b = [];
        this.r = [];
    }
    Builder.prototype.add = function (bytes, isRandom) {
        if (isRandom) this.r.push([this.b.length, this.b.length + bytes.length]);
        for (const x of bytes) this.b.push(x);
        return this;
    };
    Builder.prototype.addBuilder = function (o) {
        const base = this.b.length;
        for (const [s, e] of o.r) this.r.push([s + base, e + base]);
        for (const x of o.b) this.b.push(x);
        return this;
    };

    function buildCryptoFrame(host) {
        const name = new TextEncoder().encode(host);

        const exts = new Builder();
        exts.add([0x00, 0x00, ...u16(name.length + 5), ...u16(name.length + 3), 0x00, ...u16(name.length), ...name]);
        exts.add([0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d]);
        exts.add([0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04]);
        exts.add([0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33]);
        exts.add([0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        exts.add([0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
        exts.add(randomBytes(32), true);

        const body = new Builder();
        body.add([0x03, 0x03]);        
        body.add(randomBytes(32), true); 
        body.add([0x00]);                  
        body.add([0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03]); 
        body.add([0x01, 0x00]);            
        body.add(u16(exts.b.length));
        body.addBuilder(exts);

        const hs = new Builder();
        hs.add([0x01, ...u24(body.b.length)]); 
        hs.addBuilder(body);

        const frame = new Builder();
        frame.add([0x06, 0x00, ...varint2(hs.b.length)]); 
        frame.addBuilder(hs);
        return frame; 
    }

    async function hmac(keyBytes, data) {
        const subtle = getCrypto().subtle;
        const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        return new Uint8Array(await subtle.sign('HMAC', key, data));
    }

    async function expandLabel(secret, label, length) {
        const full = new TextEncoder().encode('tls13 ' + label);
        const info = new Uint8Array([...u16(length), full.length, ...full, 0x00]);
        const t1 = await hmac(secret, new Uint8Array([...info, 0x01]));
        return t1.slice(0, length);
    }

    async function deriveInitialKeys(dcid) {
        const initialSecret = await hmac(QUIC_V1_SALT, dcid);
        const clientSecret = await expandLabel(initialSecret, 'client in', 32);
        return {
            key: await expandLabel(clientSecret, 'quic key', 16),
            iv: await expandLabel(clientSecret, 'quic iv', 12),
            hp: await expandLabel(clientSecret, 'quic hp', 16)
        };
    }

    async function buildInitialPacket(host) {
        const subtle = getCrypto().subtle;

        const frame = buildCryptoFrame(host);
        const plaintext = new Uint8Array(frame.b);

        const dcid = randomBytes(DCID_LEN);
        const pn = randomBytes(PN_LEN);
        const keys = await deriveInitialKeys(dcid);

        const header = new Uint8Array([
            0xc0 | (PN_LEN - 1),
            ...QUIC_V1_VERSION,
            DCID_LEN, ...dcid,
            0x00,                              
            0x00,                            
            ...varint2(PN_LEN + plaintext.length + TAG_LEN),
            ...pn
        ]);

        const nonce = new Uint8Array(keys.iv);
        for (let i = 0; i < PN_LEN; i++) nonce[nonce.length - PN_LEN + i] ^= pn[i];

        const aesKey = await subtle.importKey('raw', keys.key, 'AES-GCM', false, ['encrypt']);
        const ct = new Uint8Array(await subtle.encrypt(
            { name: 'AES-GCM', iv: nonce, additionalData: header, tagLength: 128 },
            aesKey, plaintext
        ));

        const sampleOffset = 4 - PN_LEN;
        const sample = ct.slice(sampleOffset, sampleOffset + 16);
        const hpKey = await subtle.importKey('raw', keys.hp, 'AES-CBC', false, ['encrypt']);
        const mask = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv: new Uint8Array(16) }, hpKey, sample));

        const protectedHeader = new Uint8Array(header);
        protectedHeader[0] ^= mask[0] & 0x0f;
        for (let i = 0; i < PN_LEN; i++) protectedHeader[protectedHeader.length - PN_LEN + i] ^= mask[1 + i];

        const packet = new Uint8Array(protectedHeader.length + ct.length);
        packet.set(protectedHeader, 0);
        packet.set(ct, protectedHeader.length);

        const isRandom = new Array(packet.length).fill(false);
        const payloadStart = protectedHeader.length;
        for (const [s, e] of frame.r) {
            for (let i = Math.max(s, KEEP_PREFIX); i < e; i++) isRandom[payloadStart + i] = true;
        }
        for (let i = packet.length - TAG_LEN; i < packet.length; i++) isRandom[i] = true;

        let i1 = '';
        let i = 0;
        while (i < packet.length) {
            let j = i;
            while (j < packet.length && isRandom[j] === isRandom[i]) j++;
            i1 += isRandom[i]
                ? `<r ${j - i}>`
                : `<b 0x${bytesToHex(packet.slice(i, j))}>`;
            i = j;
        }

        return { i1, packetHex: bytesToHex(packet), length: packet.length, host };
    }

    async function generateI1(rawDomain) {
        const n = normalizeDomain(rawDomain);
        if (!n.ok) throw new Error(n.error);
        return (await buildInitialPacket(n.host)).i1;
    }

    const api = { normalizeDomain, buildInitialPacket, generateI1, deriveInitialKeys, hexToBytes, bytesToHex };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.QuicGen = api;
})(typeof window !== 'undefined' ? window : globalThis);
