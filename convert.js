if (validLinks.length === 0) {
    console.error('هیچ کانفیگ معتبری یافت نشد!');
    process.exit(1);
}

// ۱. ذخیره vpn.json (Xray)
fs.writeFileSync('vpn.json', JSON.stringify(jsonConfigs, null, 2), 'utf8');

// ۲. ذخیره ساختار استاندارد و کامل Sing-box برای vpns.json
const singboxFullConfig = {
    "log": { "level": "warn", "timestamp": true },
    "dns": {
        "servers": [
            { "tag": "proxydns", "address": "tls://8.8.8.8" },
            { "tag": "localdns", "address": "local", "detour": "direct" }
        ],
        "rules": [
            { "outbound": "any", "server": "proxydns" }
        ]
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
        "rules": [
            { "protocol": "dns", "outbound": "dns-out" }
        ],
        "auto_detect_interface": true
    }
};
fs.writeFileSync('vpns.json', JSON.stringify(singboxFullConfig, null, 2), 'utf8');

// ۳. ذخیره ساختار استاندارد و کامل Clash برای vpn.yml (به همراه پروکسی گروه‌ها)
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

// اضافه کردن پروکسی گروپ‌ها و رول‌ها برای رفع خطای "پروفایلی نیست" در کلش
clashYaml += "\nproxy-groups:\n";
clashYaml += "  - name: \"🚀 Load-Balance\"\n";
clashYaml += "    type: load-balance\n";
clashYaml += "    proxies:\n";
clashProxies.forEach(p => {
    clashYaml += `      - "${p.name}"\n`;
});
clashYaml += "    url: 'http://www.gstatic.com/generate_204'\n";
clashYaml += "    interval: 300\n";

clashYaml += "\nrules:\n";
clashYaml += "  - MATCH,🚀 Load-Balance\n";

fs.writeFileSync('vpn.yml', clashYaml, 'utf8');

// ۴. ذخیره Base64 در vpn64.txt
const base64Content = Buffer.from(validLinks.join('\n')).toString('base64');
fs.writeFileSync('vpn64.txt', base64Content, 'utf8');

console.log('تمامی فایل‌های خروجی با ساختار استاندارد و کامل ساخته شدند!');
