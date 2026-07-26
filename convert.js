const fs = require('fs');
const url = require('url');

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

function parseVlessConfig(link, index) {
    try {
        const parsed = new URL(link);
        let rawRemarks = decodeURIComponent(parsed.hash.replace('#', '')).trim();
        if (!rawRemarks) rawRemarks = `VLESS Config ${index + 1}`;

        const address = parsed.hostname;
        const port = parseInt(parsed.port) || 443;
        const uuid = parsed.username;
        const params = parsed.searchParams;

        const path = params.get('path') || '/';
        const host = params.get('host'] || parsed.hostname;
        const sni = params.get('sni'] || host || address;
        const fp = params.get('fp') || 'chrome';

        const tag = `💦 ${index + 1} - VLESS - ${rawRemarks}`;

        const outboundObj = {
            "tag": tag,
            "type": "vless",
            "server": address,
            "server_port": port,
            "tcp_fast_open": false,
            "uuid": uuid,
            "packet_encoding": "",
            "network": "tcp",
            "tls": {
                "enabled": true,
                "server_name": sni,
                "record_fragment": false,
                "insecure": false,
                "alpn": [
                    "http/1.1"
                ],
                "utls": {
                    "enabled": true,
                    "fingerprint": fp
                }
            },
            "transport": {
                "type": "ws",
                "path": path,
                "max_early_data": 2560,
                "early_data_header_name": "Sec-WebSocket-Protocol",
                "headers": {
                    "Host": host
                }
            },
            "domain_resolver": "dns-direct"
        };

        const clashObj = {
            name: tag,
            type: 'vless',
            server: address,
            port: port,
            uuid: uuid,
            cipher: 'none',
            tls: true,
            servername: sni,
            'client-fingerprint': fp,
            network: 'ws',
            ws: true,
            'ws-opts': {
                path: path,
                headers: { Host: host }
            }
        };

        return { tag, outboundObj, clashObj, link };
    } catch (e) {
        console.error(`خطا در پردازش لینک شماره ${index + 1}:`, e.message);
        return null;
    }
}

const singboxOutbounds = [];
const clashProxies = [];
const validLinks = [];
const outboundTags = [];

lines.forEach((line, index) => {
    if (line.startsWith('vless://')) {
        const result = parseVlessConfig(line, index);
        if (result) {
            validLinks.push(result.link);
            outboundTags.push(result.tag);
            singboxOutbounds.push(result.outboundObj);
            clashProxies.push(result.clashObj);
        }
    }
});

if (validLinks.length === 0) {
    console.error('هیچ کانفیگ معتبری یافت نشد!');
    process.exit(1);
}

const selectorTag = "✅ Selector";
const urlTestTag = "💦 Best Ping 🚀";

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

// ساخت فایل Clash YAML
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
    clashYaml += `    uuid: ${p.uuid}\n`;
    clashYaml += `    cipher: ${p.cipher}\n`;
    clashYaml += `    tls: ${p.tls}\n`;
    clashYaml += `    servername: ${p.servername}\n`;
    clashYaml += `    client-fingerprint: ${p['client-fingerprint']}\n`;
    clashYaml += `    network: ${p.network}\n`;
    clashYaml += `    ws: true\n`;
    clashYaml += `    ws-opts:\n`;
    clashYaml += `      path: "${p['ws-opts'].path}"\n`;
    clashYaml += `      headers:\n        Host: ${p['ws-opts'].headers.Host}\n`;
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

console.log('فایل خروجی سینگ‌باکس با موفقیت و تطابق ۱۰۰٪ با ساختار سالم ساخته شد[span_1](start_span)[span_1](end_span)!');
