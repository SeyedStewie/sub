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

function parseConfig(link) {
    try {
        if (link.startsWith('vless://')) {
            const parsed = new URL(link);
            let rawRemarks = decodeURIComponent(parsed.hash.replace('#', '')).trim();
            if (!rawRemarks) rawRemarks = 'VLESS Config';

            const address = parsed.hostname;
            const flag = getRealCountryFlag(address);
            const remarks = `${rawRemarks}${flag}`;

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

    // ۱. خروجی vpn.json (Xray)
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
            },
            {
              "listen": "127.0.0.1", "port": 10853, "protocol": "dokodemo-door",
              "settings": { "address": "1.1.1.1", "network": "tcp,udp", "port": 53 },
              "tag": "dns-in"
            }
          ],
          "outbounds": [
            {
              "protocol": config.protocol,
              "settings": config.protocol === 'vless' ? {
                "vnext": [{
                  "address": config.address,
                  "port": config.port,
                  "users": [{ "id": config.uuid, "encryption": "none" }]
                }]
              } : {
                "servers": [{
                  "address": config.address,
                  "port": config.port,
                  "password": config.password
                }]
              },
              "streamSettings": {
                "network": config.net,
                "wsSettings": {
                  "host": config.sni.toLowerCase(),
                  "path": config.path
                },
                "security": config.security,
                "tlsSettings": {
                  "serverName": config.sni,
                  "fingerprint": config.fp,
                  "alpn": config.alpn
                },
                "sockopt": {
                  "domainStrategy": "UseIP"
                }
              },
              "tag": "proxy"
            },
            { "protocol": "dns", "settings": { "rules": [{ "action": "hijack" }] }, "tag": "dns-out" },
            { "protocol": "freedom", "settings": { "domainStrategy": "UseIP" }, "tag": "direct" },
            { "protocol": "blackhole", "settings": { "response": { "type": "http" } }, "tag": "block" }
          ],
          "routing": {
            "domainStrategy": "AsIs",
            "rules": [
              { "inboundTag": ["mixed-in"], "port": 53, "outboundTag": "dns-out", "type": "field" },
              { "inboundTag": ["dns-in"], "outboundTag": "dns-out", "type": "field" },
              { "inboundTag": ["remote-dns"], "outboundTag": "proxy", "type": "field" },
              { "inboundTag": ["dns"], "outboundTag": "direct", "type": "field" },
              { "domain": ["geosite:private"], "outboundTag": "direct", "type": "field" },
              { "ip": ["geoip:private"], "outboundTag": "direct", "type": "field" },
              { "network": "udp", "outboundTag": "block", "type": "field" },
              { "domain": ["geosite:category-ads-all", "geosite:category-ads-ir"], "outboundTag": "block", "type": "field" },
              { "domain": ["geosite:category-ir"], "outboundTag": "direct", "type": "field" },
              { "network": "tcp", "outboundTag": "proxy", "type": "field" }
            ]
          },
          "policy": {
            "levels": { "0": { "connIdle": 300, "handshake": 4, "uplinkOnly": 1, "downlinkOnly": 1 } },
            "system": { "statsOutboundUplink": true, "statsOutboundDownlink": true }
          },
          "stats": {}
        });
    }

    // ۲. خروجی Sing-box برای vpns.json
    singboxOutbounds.push({
        "type": config.protocol,
        "tag": config.remarks,
        "server": config.address,
        "server_port": config.port,
        ...(config.protocol === 'vless' && {
            "uuid": config.uuid,
            "flow": "",
            ...(config.security === 'tls' && {
                "tls": {
                    "enabled": true,
                    "server_name": config.sni,
                    "utls": { "enabled": true, "fingerprint": config.fp }
                }
            }),
            ...(config.net === 'ws' && {
                "transport": { "type": "ws", "path": config.path, "headers": { "Host": config.sni } }
            })
        }),
        ...(config.protocol === 'trojan' && { "password": config.password }),
        ...(config.protocol === 'wireguard' && { "local_address": [config.ip], "private_key": config.privateKey, "server_pubkey": config.publicKey })
    });

    // ۳. خروجی Clash برای vpn.yml
    if (config.protocol === 'vless' || config.protocol === 'trojan') {
        clashProxies.push({
            name: config.remarks,
            type: config.protocol,
            server: config.address,
            port: config.port,
            ...(config.protocol === 'vless' && {
                uuid: config.uuid,
                cipher: 'none',
                tls: config.security === 'tls',
                servername: config.sni,
                'client-fingerprint': config.fp,
                network: config.net,
                ...(config.net === 'ws' && {
                    ws: true,
                    'ws-opts': { path: config.path, headers: { Host: config.sni } }
                })
            }),
            ...(config.protocol === 'trojan' && {
                password: config.password,
                tls: true,
                servername: config.sni
            })
        });
    }
});

if (validLinks.length === 0) {
    console.error('هیچ کانفیگ معتبری یافت نشد!');
    process.exit(1);
}

// ذخیره vpn.json (Xray)
fs.writeFileSync('vpn.json', JSON.stringify(jsonConfigs, null, 2), 'utf8');

// ذخیره ساختار کاملاً جدید و استاندارد Sing-box (سازگار با نسخه 1.12 و بالاتر) بدون خطای DNS و Domain Resolver
const singboxFullConfig = {
    "log": { "level": "warn", "timestamp": true },
    "dns": {
        "servers": [
            { "tag": "google", "address": "tls://8.8.8.8" },
            { "tag": "local", "address": "local" }
        ],
        "rules": [
            { "outbound": "any", "server": "google" }
        ],
        "independent_cache": true
    },
    "inbounds": [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 10808
        }
    ],
    "outbounds": [
        ...singboxOutbounds,
        { "type": "direct", "tag": "direct" },
        { "type": "block", "tag": "block" }
    ],
    "route": {
        "default_domain_resolver": "google",
        "rules": [],
        "auto_detect_interface": true
    }
};
fs.writeFileSync('vpns.json', JSON.stringify(singboxFullConfig, null, 2), 'utf8');

// ذخیره ساختار استاندارد Clash با قابلیت انتخاب دستی و «بهترین پینگ»
let clashYaml = "port: 7890\n";
clashYaml += "socks-port: 7891\n";
clashYaml += "allow-lan: true\n";
clashYaml += "mode: rule\n";
clashYaml += "log-level: info\n";
clashYaml += "external-controller: '127.0.0.1:9090'\n\n";

clashYaml += "proxies:\n";
clashProxies.forEach(p => {
    clashYaml += `  - name: "${p.name}"\n`;
    clashYaml += `    type: ${p.type}\n`;
    clashYaml += `    server: ${p.server}\n`;
    clashYaml += `    port: ${p.port}\n`;
    if (p.uuid) clashYaml += `    uuid: ${p.uuid}\n`;
    if (p.password) clashYaml += `    password: ${p.password}\n`;
    if (p.cipher) clashYaml += `    cipher: ${p.cipher}\n`;
    if (p.tls !== undefined) clashYaml += `    tls: ${p.tls}\n`;
    if (p.servername) clashYaml += `    servername: ${p.servername}\n`;
    if (p['client-fingerprint']) clashYaml += `    client-fingerprint: ${p['client-fingerprint']}\n`;
    if (p.network) clashYaml += `    network: ${p.network}\n`;
    if (p.ws) {
        clashYaml += `    ws-opts:\n`;
        if (p['ws-opts'].path) clashYaml += `      path: "${p['ws-opts'].path}"\n`;
        if (p['ws-opts'].headers && p['ws-opts'].headers.Host) {
            clashYaml += `      headers:\n        Host: ${p['ws-opts'].headers.Host}\n`;
        }
    }
});

clashYaml += "\nproxy-groups:\n";
// گروه انتخاب دستی
clashYaml += "  - name: \"انتخاب دستی\"\n";
clashYaml += "    type: select\n";
clashYaml += "    proxies:\n";
clashProxies.forEach(p => {
    clashYaml += `      - "${p.name}"\n`;
});

// گروه بهترین پینگ (خودکار)
clashYaml += "  - name: \"بهترین پینگ\"\n";
clashYaml += "    type: url-test\n";
clashYaml += "    proxies:\n";
clashProxies.forEach(p => {
    clashYaml += `      - "${p.name}"\n`;
});
clashYaml += "    url: 'http://www.gstatic.com/generate_204'\n";
clashYaml += "    interval: 300\n";
clashYaml += "    tolerance: 50\n";

clashYaml += "\nrules:\n";
clashYaml += "  - MATCH,انتخاب دستی\n";

fs.writeFileSync('vpn.yml', clashYaml, 'utf8');

// ذخیره Base64 در vpn64.txt
const base64Content = Buffer.from(validLinks.join('\n')).toString('base64');
fs.writeFileSync('vpn64.txt', base64Content, 'utf8');

console.log('تنظیمات DNS و Route سینگ‌باکس با موفقیت برای نسخه‌های جدید بروزرسانی شد!');
