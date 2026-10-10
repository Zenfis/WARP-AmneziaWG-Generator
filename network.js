(function (root) {
    'use strict';

    const DNS_PROVIDERS = {
        cloudflare: { name: 'Cloudflare', v4: ['1.1.1.1', '1.0.0.1'],             v6: ['2606:4700:4700::1111', '2606:4700:4700::1001'] },
        google:     { name: 'Google',     v4: ['8.8.8.8', '8.8.4.4'],             v6: ['2001:4860:4860::8888', '2001:4860:4860::8844'] },
        quad9:      { name: 'Quad9',      v4: ['9.9.9.9', '149.112.112.112'],     v6: ['2620:fe::fe', '2620:fe::9'] },
        adguard:    { name: 'AdGuard',    v4: ['94.140.14.14', '94.140.15.15'],   v6: ['2a10:50c0::ad1:ff', '2a10:50c0::ad2:ff'] },
        opendns:    { name: 'OpenDNS',    v4: ['208.67.222.222', '208.67.220.220'], v6: ['2620:119:35::35', '2620:119:53::53'] }
    };

    function buildDns(mainId, fallbackId, onlyMain) {
        const main = DNS_PROVIDERS[mainId];
        if (!main) throw new Error('Неизвестный DNS-провайдер');

        if (onlyMain || fallbackId === mainId) {
            return [main.v4[0], main.v4[1], main.v6[0], main.v6[1]].join(', ');
        }
        const fb = DNS_PROVIDERS[fallbackId];
        if (!fb) throw new Error('Неизвестный резервный DNS-провайдер');
        return [main.v4[0], main.v6[0], fb.v4[0], fb.v6[0]].join(', ');
    }

    const LAN_V4 = [
        '10.0.0.0/8',      
        '172.16.0.0/12',   
        '192.168.0.0/16',   
        '169.254.0.0/16',  
        '224.0.0.0/4'     
    ];
    const LAN_V6 = [
        'fc00::/7',         
        'fe80::/10',        
        'ff00::/8'       
    ];

    function parseV4(s) {
        return s.split('.').reduce((a, p) => (a << 8n) + BigInt(p), 0n);
    }

    function parseV6(s) {
        const [head, tail] = s.split('::');
        const h = head ? head.split(':') : [];
        const t = tail === undefined ? [] : (tail ? tail.split(':') : []);
        const groups = tail === undefined ? h : [...h, ...Array(8 - h.length - t.length).fill('0'), ...t];
        return groups.reduce((a, g) => (a << 16n) + BigInt('0x' + g), 0n);
    }

    function fmtV4(n) {
        return [24n, 16n, 8n, 0n].map(sh => ((n >> sh) & 255n).toString()).join('.');
    }

    function fmtV6(n) {
        const g = [];
        for (let i = 7n; i >= 0n; i--) g.push(((n >> (i * 16n)) & 0xffffn).toString(16));
        let bestStart = -1, bestLen = 0;
        for (let i = 0; i < 8;) {
            if (g[i] !== '0') { i++; continue; }
            let j = i;
            while (j < 8 && g[j] === '0') j++;
            if (j - i > bestLen) { bestStart = i; bestLen = j - i; }
            i = j;
        }
        if (bestLen < 2) return g.join(':');
        const left = g.slice(0, bestStart).join(':');
        const right = g.slice(bestStart + bestLen).join(':');
        return `${left}::${right}`;
    }

    function parseCidr(cidr, v6) {
        const [addr, prefix] = cidr.split('/');
        return [v6 ? parseV6(addr) : parseV4(addr), parseInt(prefix, 10)];
    }

    function rangeToCidrs(start, end, bits) {
        const out = [];
        while (start <= end) {
            let size = start === 0n ? (1n << BigInt(bits)) : (start & -start);
            while (size > end - start + 1n) size >>= 1n;
            const prefix = bits - (size.toString(2).length - 1);
            out.push([start, prefix]);
            start += size;
        }
        return out;
    }

    function complement(excluded, v6) {
        const bits = v6 ? 128 : 32;
        const max = (1n << BigInt(bits)) - 1n;

        const ranges = excluded
            .map(c => parseCidr(c, v6))
            .map(([base, prefix]) => [base, base + (1n << BigInt(bits - prefix)) - 1n])
            .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));

        const result = [];
        let cursor = 0n;
        for (const [s, e] of ranges) {
            if (s > cursor) result.push(...rangeToCidrs(cursor, s - 1n, bits));
            if (e + 1n > cursor) cursor = e + 1n;
        }
        if (cursor <= max) result.push(...rangeToCidrs(cursor, max, bits));

        return result.map(([base, prefix]) => `${v6 ? fmtV6(base) : fmtV4(base)}/${prefix}`);
    }

    function buildAllowedIps(excludeLan) {
        if (!excludeLan) return '0.0.0.0/0, ::/0';
        return [...complement(LAN_V4, false), ...complement(LAN_V6, true)].join(', ');
    }

    const api = { DNS_PROVIDERS, buildDns, buildAllowedIps, complement, LAN_V4, LAN_V6 };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.NetTools = api;
})(typeof window !== 'undefined' ? window : globalThis);
