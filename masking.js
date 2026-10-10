(function (root) {
    'use strict';

    const enc = new TextEncoder();
    const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

    const MASK_TYPES = {
        quic: {
            name: 'QUIC (HTTP/3)',
            needsDomain: true,
            tip: 'Имитация QUIC-рукопожатия к выбранному домену.'
        },
        dns: {
            name: 'DNS-запрос',
            needsDomain: true,
            tip: 'Обычный DNS-запрос к выбранному домену.'
        },
        stun: {
            name: 'STUN (звонки WebRTC)',
            needsDomain: false,
            tip: 'STUN Binding Request, как в видеозвонках и мессенджерах.'
        },
        sip: {
            name: 'SIP (IP-телефония)',
            needsDomain: true,
            tip: 'Текстовый SIP-запрос OPTIONS с выбранным доменом.'
        },
        none: {
            name: 'Без маскировки (без I1)',
            needsDomain: false,
            tip: 'Параметр I1 не добавляется. Выберите, если сеть не фильтрует WireGuard или клиент не поддерживает AmneziaWG 1.5.'
        }
    };

    function compose(parts) {
        let out = '';
        let literal = '';
        const flush = () => {
            if (literal) {
                out += `<b 0x${hex(enc.encode(literal))}>`;
                literal = '';
            }
        };
        for (const part of parts) {
            if (typeof part === 'string') {
                literal += part;
            } else {
                flush();
                out += part.rc ? `<rc ${part.rc}>` : `<r ${part.r}>`;
            }
        }
        flush();
        return out;
    }

    function dnsQuery(host) {
        const qname = host.split('.').flatMap((label) => [label.length, ...enc.encode(label)]);
        const header = [0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        const question = [...qname, 0x00, 0x00, 0x01, 0x00, 0x01];
        return `<r 2><b 0x${hex([...header, ...question])}>`;
    }

    function stunBindingRequest() {
        return '<b 0x000100002112a442><r 12>';
    }

    function sipOptions(host) {
        const ip = '192.168.1.2';
        return compose([
            'OPTIONS sip:', host, ' SIP/2.0\r\n',
            `Via: SIP/2.0/UDP ${ip}:5060;branch=z9hG4bK`, { rc: 10 }, '\r\n',
            'Max-Forwards: 70\r\n',
            'From: <sip:1001@', host, '>;tag=', { rc: 8 }, '\r\n',
            'To: <sip:', host, '>\r\n',
            'Call-ID: ', { rc: 16 }, `@${ip}\r\n`,
            'CSeq: 1 OPTIONS\r\n',
            `Contact: <sip:1001@${ip}:5060>\r\n`,
            'Accept: application/sdp\r\n',
            'Content-Length: 0\r\n\r\n'
        ]);
    }

    async function generate(type, rawDomain) {
        const meta = MASK_TYPES[type];
        if (!meta) throw new Error('Неизвестный тип маскировки.');

        if (type === 'none') return '';
        if (type === 'stun') return stunBindingRequest();

        const n = root.QuicGen.normalizeDomain(rawDomain);
        if (!n.ok) throw new Error(n.error);

        if (type === 'quic') return (await root.QuicGen.buildInitialPacket(n.host)).i1;
        if (type === 'dns') return dnsQuery(n.host);
        return sipOptions(n.host);
    }

    const api = { MASK_TYPES, generate, dnsQuery, stunBindingRequest, sipOptions };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    root.I1Gen = api;
})(typeof window !== 'undefined' ? window : globalThis);
