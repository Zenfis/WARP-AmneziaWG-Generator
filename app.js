// Проверка, что все скрипты загрузились (иначе страница молча ломается: пустые списки, мёртвые кнопки)
(function checkDependencies() {
    const missing = [];
    if (typeof QuicGen === 'undefined') missing.push('quic.js');
    if (typeof I1Gen === 'undefined') missing.push('masking.js');
    if (typeof NetTools === 'undefined') missing.push('network.js');
    if (!missing.length) return;

    const msg = `Не загружены файлы: ${missing.join(', ')}. Положите их в одну папку с index.html и обновите страницу (Ctrl+F5).`;
    const banner = document.createElement('div');
    banner.className = 'mb-6 p-4 bg-red-50 border border-red-300 text-red-700 text-sm rounded-lg';
    banner.textContent = msg;
    document.querySelector('.max-w-2xl').prepend(banner);
    throw new Error(msg);
})();

const API_URL = 'https://api.cloudflareclient.com/v0a884/reg';

// Элементы UI
const generateBtn = document.getElementById('generateBtn');
const copyBtn = document.getElementById('copyBtn');
const downloadBtn = document.getElementById('downloadBtn');
const configOutput = document.getElementById('configOutput');
const statusText = document.getElementById('status');
const maskType = document.getElementById('maskType');
const maskTip = document.getElementById('maskTip');
const maskDomain = document.getElementById('maskDomain');
const maskDomainWrap = document.getElementById('maskDomainWrap');
const maskError = document.getElementById('maskError');

// Последний зарегистрированный аккаунт (чтобы менять I1 без повторной регистрации)
let lastAccount = null;

function generateRandomString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

async function registerWarpAccount(publicKeyBase64) {
    const installId = generateRandomString(22);

    const payload = {
        key: publicKeyBase64,
        install_id: installId,
        fcm_token: `${installId}:APA91b${generateRandomString(134)}`,
        tos: new Date().toISOString(),
        model: "PC",
        locale: "en_US"
    };

    // Используем CORS-прокси для обхода блокировок браузера при обращении к API Cloudflare
    const response = await corsfix.fetch(API_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'okhttp/3.12.1'
        },
        body: JSON.stringify(payload)
    });

    if (!response.ok) {
        let body = '';
        try {
            body = (await response.text()).replace(/\s+/g, ' ').trim();
        } catch (e) { /* тело недоступно */ }
        console.error('Ответ API (полностью):', response.status, body);
        const details = body.length > 1500 ? body.slice(0, 1500) + '…' : body;
        throw new Error(`Ошибка API: ${response.status} ${response.statusText}${details ? ' — ' + details : ''}`);
    }

    return await response.json();
}

const WARP_DEFAULT_PORT = 2408;
const WARP_FALLBACK_ENDPOINT = `162.159.192.1:${WARP_DEFAULT_PORT}`;

function parsePort(value) {
    const m = /:(\d+)$/.exec(String(value || ''));
    const port = m ? parseInt(m[1], 10) : 0;
    return port > 0 && port < 65536 ? port : 0;
}

function normalizeEndpoint(endpoint, port) {
    const raw = endpoint && (endpoint.v4 || endpoint.host);
    const addr = raw ? String(raw).replace(/:\d+$/, '') : '162.159.192.1';
    const chosen = port || parsePort(raw) || parsePort(endpoint && endpoint.host) || WARP_DEFAULT_PORT;
    return `${addr}:${chosen}`;
}

function buildAmneziaConfig(privateKey, apiResponse, i1, params, net) {
    const config = apiResponse.config;

    if (!config) {
        console.error("Полный ответ API:", apiResponse);
        throw new Error("Не удалось найти конфигурацию в ответе API.");
    }

    const v4Address = config.interface.addresses.v4;
    const v6Address = config.interface.addresses.v6;
    const peerPublicKey = config.peers[0].public_key;

    const endpoint = normalizeEndpoint(config.peers[0].endpoint, net.port);

    const cleanV4 = v4Address.includes('/') ? v4Address : `${v4Address}/32`;
    const cleanV6 = v6Address.includes('/') ? v6Address : `${v6Address}/128`;

    const i1Line = i1 ? `\nI1 = ${i1}` : '';

    return `[Interface]
PrivateKey = ${privateKey}
Address = ${cleanV4}, ${cleanV6}
DNS = ${net.dns}
MTU = ${params.mtu}
Jc = ${params.jc}
Jmin = ${params.jmin}
Jmax = ${params.jmax}
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4${i1Line}

[Peer]
PublicKey = ${peerPublicKey}
Endpoint = ${endpoint}
AllowedIPs = ${net.allowedIps}`;
}

const CUSTOM_PRESET = 'custom';
const PRESETS = {
    light: {
        name: 'Light — минимальный след',
        jc: 4, jmin: 8, jmax: 80, mtu: 1280,
        tip: 'Минимум мусорных пакетов, быстрое подключение. Подходит для большинства домашних сетей без жёсткой фильтрации.'
    },
    mobile: {
        name: 'Mobile / LTE',
        jc: 3, jmin: 8, jmax: 80, mtu: 1280,
        tip: 'Меньше мусорных пакетов: в мобильных сетях крупные всплески заметнее. Если не подключается — попробуйте Balanced (у некоторых операторов помогает Jc от 6).'
    },
    balanced: {
        name: 'Balanced — Wi-Fi',
        jc: 6, jmin: 50, jmax: 500, mtu: 1280,
        tip: 'Компромисс между маскировкой и скоростью для Wi-Fi и проводного интернета с умеренной фильтрацией.'
    },
    aggressive: {
        name: 'Aggressive — усиленный анти-DPI',
        jc: 10, jmin: 50, jmax: 1000, mtu: 1280,
        tip: 'Много крупного мусора: сильнее маскирует, но подключение медленнее. Не для мобильных сетей — возможны срабатывания защиты от флуда.'
    }
};
const CUSTOM_TIP = 'Свои значения: правьте поля ниже, проверка работает как обычно.';
const PARAM_DEFAULTS = PRESETS.light;
const PARAM_IDS = ['jc', 'mtu', 'jmin', 'jmax'];
const paramInputs = Object.fromEntries(PARAM_IDS.map(id => [id, document.getElementById(id)]));

function setFieldState(id, error, warning) {
    const input = paramInputs[id];
    const errEl = document.getElementById(id + 'Error');
    const warnEl = document.getElementById(id + 'Warn');
    errEl.textContent = error || '';
    errEl.classList.toggle('hidden', !error);
    warnEl.textContent = !error && warning ? warning : '';
    warnEl.classList.toggle('hidden', !!error || !warning);
    input.classList.toggle('border-red-500', !!error);
    input.classList.toggle('border-slate-300', !error);
}

function readParams() {
    const v = {};
    const err = {};
    const warn = {};

    for (const id of PARAM_IDS) {
        const raw = paramInputs[id].value.trim();
        if (!/^\d+$/.test(raw)) {
            err[id] = 'Введите целое число.';
        } else {
            v[id] = parseInt(raw, 10);
        }
    }

    if (!err.jc) {
        if (v.jc < 1 || v.jc > 128) err.jc = 'Jc должен быть от 1 до 128.';
        else if (v.jc > 12) warn.jc = 'Много мусорных пакетов — подключение может стать медленнее. Обычно хватает 4–12.';
    }

    if (!err.mtu) {
        if (v.mtu < 1280 || v.mtu > 1420) err.mtu = 'MTU должен быть от 1280 до 1420 (в конфиге есть IPv6, меньше 1280 нельзя).';
        else if (v.mtu > 1280) warn.mtu = 'Значение выше 1280 может не работать в некоторых сетях. При проблемах верните 1280.';
    }

    if (!err.jmax) {
        if (v.jmax > 1280) err.jmax = 'Jmax не может быть больше 1280.';
        else if (v.jmax < 1) err.jmax = 'Jmax должен быть больше 0.';
    }

    if (!err.jmin) {
        if (v.jmin < 1) err.jmin = 'Jmin должен быть больше 0.';
        else if (!err.jmax && v.jmin >= v.jmax) err.jmin = 'Jmin должен быть меньше Jmax.';
    }

    for (const id of PARAM_IDS) setFieldState(id, err[id], warn[id]);
    return Object.keys(err).length ? null : v;
}

const presetSelect = document.getElementById('presetSelect');
const presetTip = document.getElementById('presetTip');

for (const [id, preset] of Object.entries(PRESETS)) presetSelect.add(new Option(preset.name, id));
presetSelect.add(new Option('Свои значения (custom)', CUSTOM_PRESET));

function applyPreset(id) {
    const preset = PRESETS[id];
    if (!preset) return;
    for (const field of PARAM_IDS) paramInputs[field].value = preset[field];
}

function detectPreset() {
    for (const [id, preset] of Object.entries(PRESETS)) {
        if (PARAM_IDS.every(f => paramInputs[f].value.trim() === String(preset[f]))) return id;
    }
    return CUSTOM_PRESET;
}

function syncPresetSelect() {
    presetSelect.value = detectPreset();
    presetTip.textContent = presetSelect.value === CUSTOM_PRESET ? CUSTOM_TIP : PRESETS[presetSelect.value].tip;
}

presetSelect.value = 'light';
applyPreset('light');
syncPresetSelect();

function showMaskError(message) {
    if (message) {
        maskError.textContent = message;
        maskError.classList.remove('hidden');
    } else {
        maskError.classList.add('hidden');
    }
}

async function getI1() {
    return I1Gen.generate(maskType.value, maskDomain.value);
}

const qrBlock = document.getElementById('qrBlock');
const qrCanvas = document.getElementById('qrCanvas');
const qrMessage = document.getElementById('qrMessage');

function clearQr() {
    qrBlock.classList.add('hidden');
}

function showQrMessage(text) {
    qrBlock.classList.remove('hidden');
    qrCanvas.classList.add('hidden');
    qrMessage.textContent = text;
    qrMessage.classList.remove('hidden');
}

function updateQr(text) {
    if (!text) { clearQr(); return; }
    if (typeof qrcode === 'undefined') {
        showQrMessage('Библиотека QR-кода не загрузилась (проверьте доступ к cdn.jsdelivr.net).');
        return;
    }

    let qr = null;
    for (const level of ['M', 'L']) {
        try {
            const candidate = qrcode(0, level);
            candidate.addData(text);
            candidate.make();
            qr = candidate;
            break;
        } catch (e) { }
    }
    if (!qr) {
        showQrMessage('Конфиг слишком большой для QR-кода. Отключите «Исключить локальную сеть» или выберите более короткий тип маскировки (DNS, STUN), либо используйте файл .conf.');
        return;
    }

    const quiet = 4;
    const count = qr.getModuleCount();
    const cell = Math.max(3, Math.floor(600 / (count + quiet * 2)));
    const size = (count + quiet * 2) * cell;
    qrCanvas.width = size;
    qrCanvas.height = size;
    const ctx = qrCanvas.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = '#000000';
    for (let r = 0; r < count; r++) {
        for (let c = 0; c < count; c++) {
            if (qr.isDark(r, c)) ctx.fillRect((c + quiet) * cell, (r + quiet) * cell, cell, cell);
        }
    }

    qrMessage.classList.add('hidden');
    qrCanvas.classList.remove('hidden');
    qrBlock.classList.remove('hidden');
}

async function renderConfig() {
    if (!lastAccount) return;
    const params = readParams();
    if (!params || !readPort()) {
        copyBtn.disabled = true;
        downloadBtn.disabled = true;
        clearQr();
        return;
    }
    try {
        const i1 = await getI1();
        showMaskError('');
        configOutput.value = buildAmneziaConfig(lastAccount.privateKey, lastAccount.data, i1, params, getNetworkSettings());
        updateQr(configOutput.value);
        copyBtn.disabled = false;
        downloadBtn.disabled = false;
    } catch (error) {
        showMaskError(error.message);
        copyBtn.disabled = true;
        downloadBtn.disabled = true;
        clearQr();
    }
}

let renderTimer;
function scheduleRender() {
    clearTimeout(renderTimer);
    renderTimer = setTimeout(renderConfig, 250);
}

maskDomain.addEventListener('input', scheduleRender);
for (const id of PARAM_IDS) {
    paramInputs[id].addEventListener('input', () => {
        readParams();
        syncPresetSelect();
        scheduleRender();
    });
}
presetSelect.addEventListener('change', () => {
    if (presetSelect.value !== CUSTOM_PRESET) applyPreset(presetSelect.value);
    readParams();
    syncPresetSelect();
    scheduleRender();
});
document.getElementById('resetParamsBtn').addEventListener('click', () => {
    applyPreset('light');
    readParams();
    syncPresetSelect();
    renderConfig();
});

for (const [id, meta] of Object.entries(I1Gen.MASK_TYPES)) maskType.add(new Option(meta.name, id));
maskType.value = 'quic';

function syncMaskControls() {
    const meta = I1Gen.MASK_TYPES[maskType.value];
    maskTip.textContent = meta.tip;
    maskDomainWrap.classList.toggle('hidden', !meta.needsDomain);
    if (!meta.needsDomain) showMaskError('');
}
syncMaskControls();

maskType.addEventListener('change', () => {
    syncMaskControls();
    renderConfig();
});

const dnsMain = document.getElementById('dnsMain');
const dnsFallback = document.getElementById('dnsFallback');
const dnsOnlyMain = document.getElementById('dnsOnlyMain');
const dnsPreview = document.getElementById('dnsPreview');
const excludeLan = document.getElementById('excludeLan');

for (const [id, provider] of Object.entries(NetTools.DNS_PROVIDERS)) {
    for (const select of [dnsMain, dnsFallback]) {
        select.add(new Option(provider.name, id));
    }
}
dnsMain.value = 'cloudflare';
dnsFallback.value = 'google';

function syncDnsControls() {
    for (const opt of dnsFallback.options) opt.disabled = opt.value === dnsMain.value;
    if (dnsFallback.value === dnsMain.value) {
        const free = Array.from(dnsFallback.options).find(o => !o.disabled);
        if (free) dnsFallback.value = free.value;
    }
    dnsFallback.disabled = dnsOnlyMain.checked;
    dnsFallback.classList.toggle('opacity-50', dnsOnlyMain.checked);
    dnsPreview.textContent = NetTools.buildDns(dnsMain.value, dnsFallback.value, dnsOnlyMain.checked);
}

const portSelect = document.getElementById('portSelect');
const WARP_PORTS = [
    [2408, '2408 — стандартный'],
    [500, '500 — запасной'],
    [1701, '1701 — запасной'],
    [4500, '4500 — запасной']
];
for (const [port, label] of WARP_PORTS) portSelect.add(new Option(label, String(port)));
portSelect.value = String(WARP_DEFAULT_PORT);

function readPort() {
    return parseInt(portSelect.value, 10) || WARP_DEFAULT_PORT;
}

function getNetworkSettings() {
    return {
        port: readPort(),
        dns: NetTools.buildDns(dnsMain.value, dnsFallback.value, dnsOnlyMain.checked),
        allowedIps: NetTools.buildAllowedIps(excludeLan.checked)
    };
}

for (const el of [dnsMain, dnsFallback, dnsOnlyMain]) {
    el.addEventListener('change', () => {
        syncDnsControls();
        scheduleRender();
    });
}
excludeLan.addEventListener('change', scheduleRender);
portSelect.addEventListener('change', scheduleRender);
syncDnsControls();

generateBtn.addEventListener('click', async () => {
    const params = readParams();
    if (!params || !readPort()) return;

    let i1;
    try {
        i1 = await getI1();
        showMaskError('');
    } catch (error) {
        showMaskError(error.message);
        return;
    }

    try {
        generateBtn.disabled = true;
        statusText.classList.remove('hidden');
        statusText.textContent = 'Генерация ключей...';
        statusText.className = 'mt-4 text-center text-sm font-medium text-slate-600';
        configOutput.value = '';
        clearQr();

        const keyPair = nacl.box.keyPair();
        const privateKeyBase64 = nacl.util.encodeBase64(keyPair.secretKey);
        const publicKeyBase64 = nacl.util.encodeBase64(keyPair.publicKey);

        statusText.textContent = 'Регистрация аккаунта через API Cloudflare...';
        const accountData = await registerWarpAccount(publicKeyBase64);

        statusText.textContent = 'Формирование конфигурации...';
        lastAccount = { privateKey: privateKeyBase64, data: accountData };
        const finalConfig = buildAmneziaConfig(privateKeyBase64, accountData, i1, params, getNetworkSettings());

        configOutput.value = finalConfig;
        updateQr(finalConfig);
        statusText.textContent = 'Готово!';
        statusText.classList.replace('text-slate-600', 'text-green-600');

        copyBtn.disabled = false;
        downloadBtn.disabled = false;

    } catch (error) {
        console.error(error);
        statusText.classList.remove('hidden');
        statusText.className = 'mt-4 text-center text-sm font-medium text-slate-600';
        statusText.textContent = `Произошла ошибка: ${error.message}`;
        statusText.classList.replace('text-slate-600', 'text-red-600');
    } finally {
        generateBtn.disabled = false;
    }
});

copyBtn.addEventListener('click', () => {
    configOutput.select();
    document.execCommand('copy');
    const originalText = copyBtn.textContent;
    copyBtn.textContent = 'Скопировано!';
    setTimeout(() => copyBtn.textContent = originalText, 2000);
});

function localTimestamp(date = new Date()) {
    const pad = (n) => String(n).padStart(2, '0');
    return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
        `_${pad(date.getHours())}-${pad(date.getMinutes())}-${pad(date.getSeconds())}`;
}

downloadBtn.addEventListener('click', () => {
    const blob = new Blob([configOutput.value], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `warp-${localTimestamp()}.conf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
});