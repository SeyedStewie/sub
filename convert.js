const fs = require('fs');
const url = require('url');
const { execSync } = require('child_process');

if (!fs.existsSync('vpn.txt')) {
    console.error('فایل vpn.txt پیدا نشد!');
    process.exit(1);
}

const txtContent = fs.readFileSync('vpn.txt', 'utf8').trim();
const lines = txtContent.split('\n').filter(line => line.trim() !== '');

if (lines.length === 0) {
    console.error('فایل vpn.txt خالی است!');
    process.exit(1);
}

function countryCodeToFlag(countryCode) {
    if (!countryCode || countryCode.length !== 2) return '🌍';
    const codePoints = countryCode
        .toUpperCase()
        .split('')
        .map(char => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
}

function getRealCountryFlag(address) {
    if (!address || address.includes('workers.dev') || address.includes('pages.dev')) {
        return '☁️';
    }

    try {
        const token = process.env.GEO_API_KEY || '';
        let apiUrl = `https://ipinfo.io/${address}/json`;
        if (token) apiUrl += `?token=${token}`;

        const response = execSync(`curl -s --max-time 4 "${apiUrl}"`, { encoding: 'utf8' });
        const data = JSON.parse(response);
        
        if (data && data.country) {
            return countryCodeToFlag(data.country);
        }
    } catch (e) {
        console.warn(`خطا در استعلام GeoIP برای ${address}:`, e.message);
    }

    return '🌍';
}

// پارس کردن انواع لینک‌ها (vless, trojan, wireguard)
function parseConfig(link) {
    try {
        if (link.startsWith('vless://')) {
            const parsed = new URL(link);
            let rawRemarks = decodeURIComponent(parsed.hash.replace('#', '')).trim();
            if (!rawRemarks) rawRemarks = 'VLESS Config';

            const address = parsed.hostname;
            const flag = getRealCountryFlag(address);
            const remarks = `${rawRemarks}${flag}`; // حفظ پرچم قبلی و اضافه شدن پرچم جدید به انتها

            const params = parsed.searchParams;
            return {
                protocol: 'vless',
                remarks,
                address,
                port: parseInt(parsed.port) || 443,
                uuid: parsed.username,
                path: params.get('path') || '',
                security: params.get('security') || 'none',
                sni: params.get('sni') || address,
                fp: params.get('fp') || 'chrome',
                alpn: params.get('alpn') ? params.get('alpn').split(',') : ['http/1.1'],
                net: params.get('type') || 'tcp'
            };
        } 
        else if (link.startsWith('trojan://')) {
            const parsed = new URL(link);
            let rawRemarks = decodeURIComponent(parsed.hash.replace('#', '')).trim();
            if (!rawRemarks) rawRemarks = 'Trojan Config';

            const address = parsed.hostname;
            const flag = getRealCountryFlag(address);
            const remarks = `${rawRemarks}${flag}`;

            const params = parsed.searchParams;
            return {
                protocol: 'trojan',
                remarks,
                address,
                port: parseInt(parsed.port) || 443,
                password: parsed.username,
                path: params.get('path') || '',
                security: params.get('security') || 'tls',
                sni: params.get('sni') || address,
                fp: params.get('fp') || 'chrome',
                net: params.get('type') || 'tcp'
            };
        }
        else if (link.startsWith('wireguard://')) {
            const parsed = new URL(link);
            let rawRemarks = decodeURIComponent(parsed.hash.replace('#', '')).trim();
            if (!rawRemarks) rawRemarks = 'WireGuard Config';

            const address = parsed.hostname;
            const flag = getRealCountryFlag(address);
            const remarks = `${rawRemarks}${flag}`;

            const params = parsed.searchParams;
            return {
                protocol: 'wireguard',
                remarks,
                address,
                port: parseInt(parsed.port) || 51820,
                privateKey: parsed.username,
                publicKey: params.get('publickey') || '',
                ip: params.get('ip') || ''
            };
        }
    } catch (e) {
        console.error('خطا در پارس کردن لینک:', link);
    }
    return null;
}

const jsonConfigs = [];
const singboxOutbounds = [];
const clashProxies = [];
const validLinks = [];

lines.forEach((line) => {
    const config = parseConfig(line);
    if (!config) return;

    validLinks.push(line);

    // ۱. ساختار سفارشی شما برای vpn.json
    if (config.protocol === 'vless' || config.protocol === 'trojan') {
        jsonConfigs.push({
          "remarks": config.remarks,
          "version": { "min": "26.2.6" },
          "log": { "loglevel": "none" },
          "dns": {
            "hosts": { "geosite:category-ads-all": "#3", "geosite:category-ads-ir": "#3" },
            "servers": [
              { "address": "https://8.8.8.8/dns-query", "tag": "remote-dns" },
              { "address": "8.8.8.8", "domains": ["geosite:category-ir"], "expectIPs": ["geoip:ir"], "skipFallback": true }
            ],
            "queryStrategy": "UseIP",
            "tag": "dns"
          },
          "inbounds": [
            {
              "listen": "127.0.0.1", "port": 10808, "protocol": "mixed",
              "settings": { "auth": "noauth", "udp": true },
              "sniffing": { "destOverride": ["http", "tls"], "enabled": true, "routeOnly": true },
              "tag": "mixed-in"
            }
          ],
          "outbounds": [
            {
              "protocol": config.protocol,
              "settings": config.protocol === 'vless' ? {
                "vnext": [{ "address": config.address, "port": config.port, "users": [{ "id": config.uuid, "encryption": "none" }] }]
              } : {
                "servers": [{ "address": config.address, "port": config.port, "password": config.password }]
              },
              "streamSettings": {
                "network": config.net,
                "security": config.security,
                "tlsSettings": { "serverName": config.sni, "fingerprint": config.fp }
              },
              "tag": "proxy"
            },
            { "protocol": "freedom", "settings": {}, "tag": "direct" }
          ],
          "routing": { "domainStrategy": "AsIs", "rules": [] }
        });
    }

    // ۲. خروجی Sing-box برای vpns.json (نمونه اوباند)
    singboxOutbounds.push({
        "type": config.protocol,
        "tag": config.remarks,
        "server": config.address,
        "server_port": config.port,
        ...(config.protocol === 'vless' && { "uuid": config.uuid, "flow": "" }),
        ...(config.protocol === 'trojan' && { "password": config.password }),
        ...(config.protocol === 'wireguard' && { "local_address": [config.ip], "private_key": config.privateKey, "server_pubkey": config.publicKey })
    });

    // ۳. خروجی Clash برای vpn.yml (نمونه پروکسی)
    if (config.protocol === 'vless' || config.protocol === 'trojan') {
        clashProxies.push({
            name: config.remarks,
            type: config.protocol,
            server: config.address,
            port: config.port,
            ...(config.protocol === 'vless' && { uuid: config.uuid, cipher: 'none', tls: true, 'client-fingerprint': config.fp }),
            ...(config.protocol === 'trojan' && { password: config.password, tls: true })
        });
    }
});

if (validLinks.length === 0) {
    console.error('هیچ کانفیگ معتبری یافت نشد!');
    process.exit(1);
}

// ذخیره فایل‌ها
fs.writeFileSync('vpn.json', JSON.stringify(jsonConfigs, null, 2), 'utf8');
fs.writeFileSync('vpns.json', JSON.stringify({ outbounds: singboxOutbounds }, null, 2), 'utf8');

// ساخت محتوای YAML برای Clash
let clashYaml = "proxies:\n";
clashProxies.forEach(p => {
    clashYaml += `  - name: "${p.name}"\n`;
    clashYaml += `    type: ${p.type}\n`;
    clashYaml += `    server: ${p.server}\n`;
    clashYaml += `    port: ${p.port}\n`;
    if (p.uuid) clashYaml += `    uuid: ${p.uuid}\n`;
    if (p.password) clashYaml += `    password: ${p.password}\n`;
    if (p.tls) clashYaml += `    tls: true\n`;
    if (p.cipher) clashYaml += `    cipher: ${p.cipher}\n`;
    if (p['client-fingerprint']) clashYaml += `    client-fingerprint: ${p['client-fingerprint']}\n`;
});
fs.writeFileSync('vpn.yml', clashYaml, 'utf8');

// ساخت و ذخیره Base64 در vpn64.txt
const base64Content = Buffer.from(validLinks.join('\n')).toString('base64');
fs.writeFileSync('vpn64.txt', base64Content, 'utf8');

console.log('تمامی فایل‌های خروجی با موفقیت تولید شدند!');
