const fs = require('fs');

if (!fs.existsSync('vpn.txt')) {
    console.error('فایل vpn.txt پیدا نشد!');
    process.exit(1);
}

const txtContent = fs.readFileSync('vpn.txt', 'utf8').replace(/\r/g, '').trim();
const lines = txtContent.split('\n').filter(line => line.trim() !== '');

if (lines.length === 0) {
    console.error('فایل vpn.txt خالی است!');
    process.exit(1);
}

const isIpAddress = (str) => {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(str) || str.includes(':') || str.includes('[');
};

const randomizeCase = (str) => {
    return str.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join('');
};

async function getIpLocation(ip) {
    const ipinfoToken = process.env.IPINFO_TOKEN || ''; 
    try {
        // const response = await fetch(`https://ipinfo.io/${ip}/json?token=${ipinfoToken}`);
        // const data = await response.json();
        // const country = data.country || 'UN';
        // const flag = country.replace(/./g, char => String.fromCodePoint(127397 + char.charCodeAt(0)));
        // return { country, flag };

        return { country: 'DE', flag: '🇩🇪' };
    } catch (e) {
        return { country: 'UN', flag: '🌐' };
    }
}

async function parseVlessConfig(link, index) {
    try {
        const parsed = new URL(link);
        const address = parsed.hostname.replace(/\[|\]/g, '');
        const port = parseInt(parsed.port) || 443;
        const uuid = parsed.username || parsed.pathname.replace(/^\/\/?/, '');
        const params = parsed.searchParams;

        let path = params.get('path') || '/';
        path = path.split('?')[0];
        if (!path.startsWith('/')) path = '/' + path;

        let workerDomain = params.get('host') || params.get('sni') || 'vpn.seyeddex.workers.dev';
        workerDomain = workerDomain.trim();

        const sni = randomizeCase(workerDomain);
        const host = workerDomain;
        const fp = params.get('fp') || 'chrome';

        let originalRemark = parsed.hash ? parsed.hash.slice(1).trim() : '';
        if (!originalRemark) originalRemark = params.get('remark') || `vpn-${index + 1}`;
        originalRemark = decodeURIComponent(originalRemark);

        const locationInfo = await getIpLocation(address);
        
        // چسباندن پرچم بدون فاصله به انتهای ریمارک
        let tag = `${originalRemark}${locationInfo.flag}`;

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
                "alpn": ["http/1.1"],
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
            }
        };

        if (!isIpAddress(address)) {
            outboundObj.domain_resolver = "dns-direct";
        }

        parsed.hash = encodeURIComponent(tag);
        const updatedLink = parsed.toString();

        return { tag, outboundObj, link: updatedLink, host, sni, fp, address, port, uuid, path };
    } catch (e) {
        console.error(`خطا در پردازش لینک شماره ${index + 1}:`, e.message);
        return null;
    }
}

// ساخت کانفیگ کامل Xray برای هر لینک
function buildXrayConfig(result) {
    const { tag, address, port, uuid, path, host, sni, fp } = result;
    return {
        "remarks": tag,
        "version": { "min": "26.2.6" },
        "log": { "loglevel": "none" },
        "dns": {
            "hosts": {
                "geosite:category-ads-all": "#3",
                "geosite:category-ads-ir": "#3"
            },
            "servers": [
                {
                    "address": "https://8.8.8.8/dns-query",
                    "tag": "remote-dns"
                },
                {
                    "address": "8.8.8.8",
                    "domains": [ "geosite:category-ir" ],
                    "expectIPs": [ "geoip:ir" ],
                    "skipFallback": true
                },
                {
                    "address": "8.8.8.8",
                    "domains": [ `full:${host}` ],
                    "skipFallback": true
                }
            ],
            "queryStrategy": "UseIP",
            "tag": "dns"
        },
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "mixed",
                "settings": {
                    "auth": "noauth",
                    "udp": true
                },
                "sniffing": {
                    "destOverride": [ "http", "tls" ],
                    "enabled": true,
                    "routeOnly": true
                },
                "tag": "mixed-in"
            },
            {
                "listen": "127.0.0.1",
                "port": 10853,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "1.1.1.1",
                    "network": "tcp,udp",
                    "port": 53
                },
                "tag": "dns-in"
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": address,
                            "port": port,
                            "users": [
                                {
                                    "id": uuid,
                                    "encryption": "none"
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": "ws",
                    "wsSettings": {
                        "host": host,
                        "path": path
                    },
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": sni,
                        "fingerprint": fp,
                        "alpn": [ "http/1.1" ]
                    },
                    "sockopt": {
                        "domainStrategy": "UseIP",
                        "happyEyeballs": {
                            "tryDelayMs": 250,
                            "prioritizeIPv6": false,
                            "interleave": 2,
                            "maxConcurrentTry": 4
                        }
                    }
                },
                "tag": "proxy"
            },
            {
                "protocol": "dns",
                "settings": {
                    "rules": [
                        { "action": "hijack" }
                    ]
                },
                "tag": "dns-out"
            },
            {
                "protocol": "freedom",
                "settings": {
                    "domainStrategy": "UseIP"
                },
                "tag": "direct"
            },
            {
                "protocol": "blackhole",
                "settings": {
                    "response": {
                        "type": "http"
                    }
                },
                "tag": "block"
            }
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {
                    "inboundTag": [ "mixed-in" ],
                    "port": 53,
                    "outboundTag": "dns-out",
                    "type": "field"
                },
                {
                    "inboundTag": [ "dns-in" ],
                    "outboundTag": "dns-out",
                    "type": "field"
                },
                {
                    "inboundTag": [ "remote-dns" ],
                    "outboundTag": "proxy",
                    "type": "field"
                },
                {
                    "inboundTag": [ "dns" ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "domain": [ "geosite:private" ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "ip": [ "geoip:private" ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "network": "udp",
                    "outboundTag": "block",
                    "type": "field"
                },
                {
                    "domain": [ "geosite:category-ads-all", "geosite:category-ads-ir" ],
                    "outboundTag": "block",
                    "type": "field"
                },
                {
                    "domain": [ "geosite:category-ir" ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "ip": [ "geoip:ir" ],
                    "outboundTag": "direct",
                    "type": "field"
                },
                {
                    "network": "tcp",
                    "outboundTag": "proxy",
                    "type": "field"
                }
            ]
        },
        "policy": {
            "levels": {
                "0": {
                    "connIdle": 300,
                    "handshake": 4,
                    "uplinkOnly": 1,
                    "downlinkOnly": 1
                }
            },
            "system": {
                "statsOutboundUplink": true,
                "statsOutboundDownlink": true
            }
        },
        "stats": {}
    };
}

async function main() {
    const singboxOutbounds = [];
    const outboundTags = [];
    const validLinks = [];
    const xrayConfigs = [];        // برای vpn.json (کانفیگ کامل Xray)
    const clashProxies = [];       // برای vpn.yml

    for (let index = 0; index < lines.length; index++) {
        let line = lines[index].trim();
        if (line.startsWith('vless://')) {
            const result = await parseVlessConfig(line, index);
            if (result) {
                validLinks.push(result.link);
                outboundTags.push(result.tag);
                singboxOutbounds.push(result.outboundObj);

                // ---- Xray full config (vpn.json) ----
                xrayConfigs.push(buildXrayConfig(result));

                // ---- Clash proxy ----
                const clashProxy = {
                    name: result.tag,
                    type: "vless",
                    server: result.outboundObj.server,
                    port: result.outboundObj.server_port,
                    uuid: result.outboundObj.uuid,
                    network: "ws",
                    tls: true,
                    udp: true,
                    sni: result.outboundObj.tls.server_name,
                    fingerprint: result.outboundObj.tls.utls.fingerprint,
                    "ws-path": result.outboundObj.transport.path,
                    "ws-headers": {
                        Host: result.outboundObj.transport.headers.Host
                    }
                };
                clashProxies.push(clashProxy);
            }
        }
    }

    if (validLinks.length === 0) {
        console.error('هیچ کانفیگ معتبری یافت نشد!');
        process.exit(1);
    }

    // ۱. vpn64.txt
    const joinedLinks = validLinks.join('\n');
    const base64Encoded = Buffer.from(joinedLinks).toString('base64');
    fs.writeFileSync('vpn64.txt', base64Encoded, 'utf8');

    // ۲. vpn.json (آرایه کانفیگ‌های کامل Xray)
    fs.writeFileSync('vpn.json', JSON.stringify(xrayConfigs, null, 4), 'utf8');

    // ۳. vpn.yml (Clash)
    const selectorTag = "انتخاب دستی";
    const urlTestTag = "بهترین پینگ";
    const proxyNames = clashProxies.map(p => p.name);

    let ymlContent = "proxies:\n";
    clashProxies.forEach(p => {
        ymlContent += `  - name: "${p.name}"\n`;
        ymlContent += `    type: ${p.type}\n`;
        ymlContent += `    server: ${p.server}\n`;
        ymlContent += `    port: ${p.port}\n`;
        ymlContent += `    uuid: ${p.uuid}\n`;
        ymlContent += `    network: ${p.network}\n`;
        ymlContent += `    tls: ${p.tls}\n`;
        ymlContent += `    udp: ${p.udp}\n`;
        ymlContent += `    sni: ${p.sni}\n`;
        ymlContent += `    fingerprint: ${p.fingerprint}\n`;
        ymlContent += `    ws-path: ${p["ws-path"]}\n`;
        ymlContent += `    ws-headers:\n`;
        ymlContent += `      Host: ${p["ws-headers"].Host}\n`;
    });

    ymlContent += "\nproxy-groups:\n";
    ymlContent += `  - name: "${selectorTag}"\n`;
    ymlContent += `    type: select\n`;
    ymlContent += `    proxies:\n`;
    ymlContent += `      - "${urlTestTag}"\n`;
    proxyNames.forEach(name => { ymlContent += `      - "${name}"\n`; });
    ymlContent += `      - DIRECT\n`;

    ymlContent += `  - name: "${urlTestTag}"\n`;
    ymlContent += `    type: url-test\n`;
    ymlContent += `    proxies:\n`;
    proxyNames.forEach(name => { ymlContent += `      - "${name}"\n`; });
    ymlContent += `    url: "http://www.gstatic.com/generate_204"\n`;
    ymlContent += `    interval: 300\n`;

    ymlContent += "\nrules:\n";
    ymlContent += `  - MATCH, "${selectorTag}"\n`;

    fs.writeFileSync('vpn.yml', ymlContent, 'utf8');

    // ۴. vpns.json (سینگ‌باکس) – بدون تغییر
    const singboxFullConfig = {
        "log": { "disabled": true, "timestamp": true },
        "dns": {
            "servers": [
                { "type": "https", "server": "8.8.8.8", "detour": selectorTag, "tag": "dns-remote" },
                { "type": "udp", "server": "8.8.8.8", "tag": "dns-direct" }
            ],
            "rules": [
                { "clash_mode": "Direct", "server": "dns-direct" },
                { "clash_mode": "Global", "server": "dns-remote" },
                { "rule_set": ["geosite-category-ads-all"], "action": "reject" },
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [
                        { "rule_set": ["geosite-ir"] },
                        { "rule_set": "geoip-ir" }
                    ],
                    "action": "route",
                    "server": "dns-direct"
                }
            ],
            "strategy": "ipv4_only",
            "independent_cache": true
        },
        "inbounds": [
            { "type": "tun", "tag": "tun-in", "address": ["172.19.0.1/28"], "mtu": 9000, "auto_route": true, "strict_route": true, "stack": "mixed" },
            { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080 }
        ],
        "outbounds": [
            ...singboxOutbounds,
            { "type": "selector", "tag": selectorTag, "outbounds": [urlTestTag, ...outboundTags], "interrupt_exist_connections": false },
            { "type": "direct", "tag": "direct", "domain_resolver": "dns-direct" },
            { "type": "urltest", "tag": urlTestTag, "outbounds": outboundTags, "url": "https://www.gstatic.com/generate_204", "interrupt_exist_connections": false, "interval": "30s" }
        ],
        "route": {
            "rules": [
                { "ip_cidr": "172.19.0.2", "action": "hijack-dns" },
                { "clash_mode": "Direct", "outbound": "direct" },
                { "clash_mode": "Global", "outbound": selectorTag },
                { "action": "sniff" },
                { "protocol": "dns", "action": "hijack-dns" },
                { "ip_is_private": true, "outbound": "direct" },
                { "network": "udp", "action": "reject" },
                { "rule_set": ["geosite-category-ads-all"], "action": "reject" },
                { "rule_set": ["geosite-ir"], "action": "route", "outbound": "direct" },
                { "rule_set": ["geoip-ir"], "action": "route", "outbound": "direct" }
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
            "cache_file": { "enabled": true, "store_fakeip": true },
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "external_ui": "ui",
                "default_mode": "Rule",
                "external_ui_download_url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
                "external_ui_download_detour": "direct"
            }
        }
    };

    fs.writeFileSync('vpns.json', JSON.stringify(singboxFullConfig, null, 4), 'utf8');

    console.log('✅ همه ۴ فایل خروجی (vpn.json, vpn64.txt, vpn.yml, vpns.json) با موفقیت و به طور کامل به‌روزرسانی شدند!');
}

main();