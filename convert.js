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
            const remarks = `${rawRemarks} ${flag}`;

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
            const remarks = `${rawRemarks} ${flag}`;

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
    } catch (e) {
        console.error('خطا در پارس کردن لینک:', link);
    }
    return null;
}

const jsonConfigs = [];
const singboxOutbounds = [];
const clashProxies = [];
const validLinks = [];
const outboundTags = [];

lines.forEach((line, index) => {
    const config = parseConfig(line);
    if (!config) return;

    validLinks.push(line);
    const tag = `${index + 1} - ${config.protocol.toUpperCase()} - ${config.remarks}`;
    outboundTags.push(tag);

    if (config.protocol === 'vless' || config.protocol === 'trojan') {
        jsonConfigs.push({
          "remarks": config.remarks,
          "outbounds": [{ "protocol": config.protocol, "tag": "proxy" }]
        });
    }

    singboxOutbounds.push({
        "type": config.protocol,
        "tag": tag,
        "server": config.address,
        "server_port": config.port,
        "tcp_fast_open": false,
        "uuid": config.uuid,
        "packet_encoding": "",
        ...(config.security === 'tls' && {
            "tls": {
                "enabled": true,
                "server_name": config.sni,
                "record_fragment": false,
                "insecure": false,
                "alpn": config.alpn,
                "utls": { "enabled": true, "fingerprint": config.fp }
            }
        }),
        ...(config.net === 'ws' && {
            "transport": {
                "type": "ws",
                "path": config.path,
                "max_early_data": 2560,
                "early_data_header_name": "Sec-WebSocket-Protocol",
                "headers": { "Host": config.sni }
            }
        }),
        "domain_resolver": "dns-direct"
    });

    if (config.protocol === 'vless' || config.protocol === 'trojan') {
        clashProxies.push({
            name: tag,
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

fs.writeFileSync('vpn.json', JSON.stringify(jsonConfigs, null, 2), 'utf8');

const selectorTag = "انتخاب دستی";
const urlTestTag = "بهترین پینگ";

const singboxFullConfig = {
    "log": {
        "disabled": true,
        "timestamp": true
    },
    "dns": {
        "servers": [
            {
                "type": "https",
                "server": "8.8.8.8",
                "detour": selectorTag,
                "tag": "dns-remote"
            },
            {
                "type": "udp",
                "server": "8.8.8.8",
                "tag": "dns-direct"
            }
        ],
        "rules": [
            {
                "clash_mode": "Direct",
                "server": "dns-direct"
            },
            {
                "clash_mode": "Global",
                "server": "dns-remote"
            },
            {
                "rule_set": [
                    "geosite-category-ads-all"
                ],
                "action": "reject"
            },
            {
                "type": "logical",
                "mode": "and",
                "rules": [
                    {
                        "rule_set": [
                            "geosite-ir"
                        ]
                    },
                    {
                        "rule_set": "geoip-ir"
                    }
                ],
                "action": "route",
                "server": "dns-direct"
            }
        ],
        "strategy": "ipv4_only",
        "independent_cache": true
    },
    "inbounds": [
        {
            "type": "tun",
            "tag": "tun-in",
            "address": [
                "172.19.0.1/28"
            ],
            "mtu": 9000,
            "auto_route": true,
            "strict_route": true,
            "stack": "mixed"
        },
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 2080
        }
    ],
    "outbounds": [
        ...singboxOutbounds,
        {
            "type": "selector",
            "tag": selectorTag,
            "outbounds": [
                urlTestTag,
                ...outboundTags
            ],
            "interrupt_exist_connections": false
        },
        {
            "type": "direct",
            "tag": "direct",
            "domain_resolver": "dns-direct"
        },
        {
            "type": "urltest",
            "tag": urlTestTag,
            "outbounds": outboundTags,
            "url": "https://www.gstatic.com/generate_204",
            "interrupt_exist_connections": false,
            "interval": "30s"
        }
    ],
    "route": {
        "rules": [
            {
                "ip_cidr": "172.19.0.2",
                "action": "hijack-dns"
            },
            {
                "clash_mode": "Direct",
                "outbound": "direct"
            },
            {
                "clash_mode": "Global",
                "outbound": selectorTag
            },
            {
                "action": "sniff"
            },
            {
                "protocol": "dns",
                "action": "hijack-dns"
            },
            {
                "ip_is_private": true,
                "outbound": "direct"
            },
            {
                "network": "udp",
                "action": "reject"
            },
            {
                "rule_set": [
                    "geosite-category-ads-all"
                ],
                "action": "reject"
            },
            {
                "rule_set": [
                    "geosite-ir"
                ],
                "action": "route",
                "outbound": "direct"
            },
            {
                "rule_set": [
                    "geoip-ir"
                ],
                "action": "route",
                "outbound": "direct"
            }
        ],
        "rule_set": [
            {
                "type": "remote",
                "tag": "geosite-category-ads-all",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ads-all.srs",
                "download_detour": "direct"
            },
            {
                "type": "remote",
                "tag": "geosite-ir",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs",
                "download_detour": "direct"
            },
            {
                "type": "remote",
                "tag": "geoip-ir",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs",
                "download_detour": "direct"
            }
        ],
        "auto_detect_interface": true,
        "final": selectorTag
    },
    "ntp": {
        "enabled": true,
        "server": "time.cloudflare.com",
        "server_port": 123,
        "domain_resolver": "dns-direct",
        "interval": "30m",
        "write_to_system": false
    },
    "experimental": {
        "cache_file": {
            "enabled": true,
            "store_fakeip": true
        },
        "clash_api": {
            "external_controller": "127.0.0.1:9090",
            "external_ui": "ui",
            "default_mode": "Rule",
            "external_ui_download_url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
            "external_ui_download_detour": "direct"
        }
    }
};

fs.writeFileSync('vpns.json', JSON.stringify(singboxFullConfig, null, 2), 'utf8');

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
clashYaml += `  - name: "${selectorTag}"\n`;
clashYaml += "    type: select\n";
clashYaml += "    proxies:\n";
clashYaml += `      - "${urlTestTag}"\n`;
clashProxies.forEach(p => {
    clashYaml += `      - "${p.name}"\n`;
});

clashYaml += `  - name: "${urlTestTag}"\n`;
clashYaml += "    type: url-test\n";
clashYaml += "    proxies:\n";
clashProxies.forEach(p => {
    clashYaml += `      - "${p.name}"\n`;
});
clashYaml += "    url: 'http://www.gstatic.com/generate_204'\n";
clashYaml += "    interval: 300\n";
clashYaml += "    tolerance: 50\n";

clashYaml += "\nrules:\n";
clashYaml += `  - MATCH,${selectorTag}\n`;

fs.writeFileSync('vpn.yml', clashYaml, 'utf8');

const base64Content = Buffer.from(validLinks.join('\n')).toString('base64');
fs.writeFileSync('vpn64.txt', base64Content, 'utf8');

console.log('اسکریپت با موفقیت اجرا شد و فایل‌ها بدون خطا ساخته شدند!');
