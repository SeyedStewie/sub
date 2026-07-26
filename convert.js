const fs = require('fs');

if (!fs.existsSync('vpn.txt')) {
    console.error('فایل vpn.txt پیدا نشد!');
    process.exit(1);
}

// حذف کامل کاراکترهای نامرئی \r که باعث خرابی هدرها می‌شوند
const txtContent = fs.readFileSync('vpn.txt', 'utf8').replace(/\r/g, '').trim();
const lines = txtContent.split('\n').filter(line => line.trim() !== '');

if (lines.length === 0) {
    console.error('فایل vpn.txt خالی است!');
    process.exit(1);
}

// تشخیص دقیق IPv4 و IPv6 (آی‌پی‌ها نباید domain_resolver داشته باشند)
const isIpAddress = (str) => {
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(str) || str.includes(':') || str.includes('[');
};

// تابع ایجاد حروف تصادفی برای SNI جهت دور زدن DPI
const randomizeCase = (str) => {
    return str.split('').map(c => Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()).join('');
};

function parseVlessConfig(link, index) {
    try {
        const parsed = new URL(link);
        const address = parsed.hostname.replace(/\[|\]/g, '');
        const port = parseInt(parsed.port) || 443;
        const uuid = parsed.username || parsed.pathname.replace(/^\/\/?/, '');
        const params = parsed.searchParams;

        // --- پاک کردن Query String از مسیر WebSocket ---
        let path = params.get('path') || '/';
        path = path.split('?')[0];
        if (!path.startsWith('/')) path = '/' + path;

        // استخراج دامنه ورکر
        let workerDomain = params.get('host') || params.get('sni') || 'vpn.seyeddex.workers.dev';
        workerDomain = workerDomain.trim();

        const sni = randomizeCase(workerDomain);
        const host = workerDomain;
        const fp = params.get('fp') || 'chrome';

        // --- استخراج Remark از بخش # ---
        let remark = parsed.hash ? parsed.hash.slice(1).trim() : '';
        // اگر remark خالی بود، از پارامتر 'remark' در query استفاده کن (بعضی لینک‌ها اینطور هستند)
        if (!remark) remark = params.get('remark') || '';

        let tagType = "Clean IP";
        if (address === host) tagType = "Domain";
        else if (isIpAddress(address)) tagType = "IPv4";

        // تعیین تگ نهایی: اگر remark داشت، از آن استفاده کن، در غیر این صورت یک تگ خودکار بساز
        let tag;
        if (remark) {
            tag = remark;
        } else {
            tag = `vpn`;
        }

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

        // --- افزودن domain_resolver برای سرورهای دامنه‌ای ---
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
    line = line.trim();
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

// --- تغییر نام‌های اصلی به فارسی ---
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
console.log('✅ فایل vpns.json با نام‌های فارسی و Remark ساخته شد!');