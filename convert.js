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

        return { tag, outboundObj, link: updatedLink };
    } catch (e) {
        console.error(`خطا در پردازش لینک شماره ${index + 1}:`, e.message);
        return null;
    }
}

async function main() {
    const singboxOutbounds = [];
    const outboundTags = [];
    const validLinks = [];
    const xrayOutbounds = [];      // برای vpn.json
    const clashProxies = [];       // برای vpn.yml

    for (let index = 0; index < lines.length; index++) {
        let line = lines[index].trim();
        if (line.startsWith('vless://')) {
            const result = await parseVlessConfig(line, index);
            if (result) {
                validLinks.push(result.link);
                outboundTags.push(result.tag);
                singboxOutbounds.push(result.outboundObj);

                // ---- ساخت خروجی Xray ----
                const xrayObj = {
                    protocol: "vless",
                    settings: {
                        vnext: [{
                            address: result.outboundObj.server,
                            port: result.outboundObj.server_port,
                            users: [{
                                id: result.outboundObj.uuid,
                                encryption: "none",
                                flow: ""  // در صورت نیاز از پارامتر flow استفاده کنید
                            }]
                        }]
                    },
                    streamSettings: {
                        network: "ws",
                        security: "tls",
                        tlsSettings: {
                            serverName: result.outboundObj.tls.server_name,
                            fingerprint: result.outboundObj.tls.utls.fingerprint,
                            allowInsecure: false
                        },
                        wsSettings: {
                            path: result.outboundObj.transport.path,
                            headers: result.outboundObj.transport.headers
                        }
                    }
                };
                xrayOutbounds.push(xrayObj);

                // ---- ساخت خروجی Clash ----
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

    // ۱. تولید فایل vpn64.txt (به‌روزرسانی شده)
    const joinedLinks = validLinks.join('\n');
    const base64Encoded = Buffer.from(joinedLinks).toString('base64');
    fs.writeFileSync('vpn64.txt', base64Encoded, 'utf8');

    // ۲. تولید فایل vpn.json (آرایه خروجی‌های Xray)
    fs.writeFileSync('vpn.json', JSON.stringify(xrayOutbounds, null, 4), 'utf8');

    // ۳. تولید فایل vpn.yml (لیست پروکسی‌های Clash)
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
    fs.writeFileSync('vpn.yml', ymlContent, 'utf8');

    // ۴. تولید فایل vpns.json (سینگ‌باکس) – بدون تغییر
    const selectorTag = "انتخاب دستی";
    const urlTestTag = "بهترین پینگ";

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