const fs = require('fs');

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

// تشخیص آی‌پی برای تنظیمات Resolver
const isIpAddress = (ip) => {
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
};

// تابع ایجاد حروف تصادفی برای SNI جهت بایپس DPI
const randomizeCase = (str) => {
    return str.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join('');
};

function parseVlessConfig(link, index) {
    try {
        const parsed = new URL(link);
        const address = parsed.hostname;
        const port = parseInt(parsed.port) || 443;
        const uuid = parsed.username || parsed.pathname.replace(/^\/\/?/, '');
        const params = parsed.searchParams;

        const path = params.get('path') || '/';
        // در کانفیگ ورکر، هدر Host باید همون دامنه اصلی باشه
        const host = params.get('host') || 'vpn.seyeddex.workers.dev';
        // اعمال حروف تصادفی روی SNI
        const sni = randomizeCase(host);
        const fp = params.get('fp') || 'chrome';

        // تنظیم اسم تگ مشابه فایل سالم
        let tagType = "Clean IP";
        if (address === host) tagType = "Domain";
        else if (isIpAddress(address)) tagType = "IPv4";

        const tag = `💦 ${index + 1} - VLESS - ${tagType} : ${port}`;

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
                "server_name": sni, // نامنظم شده
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
                    "Host": host // فیکس شده روی دامنه
                }
            }
        };

        // اعمال domain_resolver فقط برای دامنه‌ها
        if (!isIpAddress(address)) {
            outboundObj.domain_resolver = "dns-direct";
        }

        return { tag, outboundObj, link };
    } catch (e) {
        console.error(`خطا در پردازش لینک شماره ${index + 1}:`, e.message);
        return null;
    }
}

const singboxOutbounds = [];
const outboundTags = [];
const validLinks = [];

lines.forEach((line, index) => {
    if (line.startsWith('vless://')) {
        const result = parseVlessConfig(line, index);
        if (result) {
            validLinks.push(result.link);
            outboundTags.push(result.tag);
            singboxOutbounds.push(result.outboundObj);
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
        {
            "type": "tun",
            "tag": "tun-in",
            "address": ["172.19.0.1/28"],
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
            "outbounds": [urlTestTag, ...outboundTags],
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
console.log('فایل vpns.json با ساختار دقیق ورکرز ساخته شد!');
