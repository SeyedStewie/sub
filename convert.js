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
    if (address.includes('workers.dev') || address.includes('pages.dev')) {
        return '☁️';
    }

    try {
        const response = execSync(`curl -s --max-time 3 "http://ip-api.com/json/${address}?fields=status,countryCode"`, { encoding: 'utf8' });
        const data = JSON.parse(response);
        
        if (data.status === 'success' && data.countryCode) {
            return countryCodeToFlag(data.countryCode);
        }
    } catch (e) {
        console.warn(`خطا در استعلام GeoIP برای ${address}:`, e.message);
    }

    return '🌍';
}

function parseVless(link) {
    try {
        const parsed = new URL(link);
        const uuid = parsed.username;
        const address = parsed.hostname;
        const port = parseInt(parsed.port) || 443;
        
        let rawRemarks = decodeURIComponent(parsed.hash.replace('#', '')).trim();
        if (!rawRemarks) rawRemarks = 'VPN Config';

        console.log(`در حال بررسی لوکیشن واقعی برای: ${address}`);
        const flag = getRealCountryFlag(address);
        
        const cleanRemarks = rawRemarks.replace(/[\uD83C[\uDDE6-\uDDFF]{2}|🌍|☁️/g, '').trim();
        const remarks = `${cleanRemarks}${flag}`;

        const params = parsed.searchParams;
        const path = params.get('path') || '';
        const security = params.get('security') || 'none';
        const sni = params.get('sni') || address;
        const fp = params.get('fp') || 'chrome';
        const alpn = params.get('alpn') ? params.get('alpn').split(',') : ['http/1.1'];
        const net = params.get('type') || 'tcp';

        return { remarks, address, port, uuid, path, security, sni, fp, alpn, net };
    } catch (e) {
        console.error('خطا در پردازش لینک:', link);
        return null;
    }
}

// ساخت یک آبجکت کامل کانفیگ برای هر لینک
const jsonConfigs = [];

lines.forEach((line) => {
    if (line.startsWith('vless://')) {
        const config = parseVless(line);
        if (config) {
            jsonConfigs.push({
              "remarks": config.remarks,
              "version": { "min": "26.2.6" },
              "log": { "loglevel": "none" },
              "dns": {
                "hosts": {
                  "geosite:category-ads-all": "#3",
                  "geosite:category-ads-ir": "#3"
                },
                "servers": [
                  { "address": "https://8.8.8.8/dns-query", "tag": "remote-dns" },
                  { "address": "8.8.8.8", "domains": ["geosite:category-ir"], "expectIPs": ["geoip:ir"], "skipFallback": true }
                ],
                "queryStrategy": "UseIP",
                "tag": "dns"
              },
              "inbounds": [
                {
                  "listen": "127.0.0.1",
                  "port": 10808,
                  "protocol": "mixed",
                  "settings": { "auth": "noauth", "udp": true },
                  "sniffing": { "destOverride": ["http", "tls"], "enabled": true, "routeOnly": true },
                  "tag": "mixed-in"
                },
                {
                  "listen": "127.0.0.1",
                  "port": 10853,
                  "protocol": "dokodemo-door",
                  "settings": { "address": "1.1.1.1", "network": "tcp,udp", "port": 53 },
                  "tag": "dns-in"
                }
              ],
              "outbounds": [
                {
                  "protocol": "vless",
                  "settings": {
                    "vnext": [
                      {
                        "address": config.address,
                        "port": config.port,
                        "users": [
                          {
                            "id": config.uuid,
                            "encryption": "none"
                          }
                        ]
                      }
                    ]
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
                  "settings": { "rules": [{ "action": "hijack" }] },
                  "tag": "dns-out"
                },
                {
                  "protocol": "freedom",
                  "settings": { "domainStrategy": "UseIP" },
                  "tag": "direct"
                },
                {
                  "protocol": "blackhole",
                  "settings": { "response": { "type": "http" } },
                  "tag": "block"
                }
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
                  { "ip": ["geoip:ir"], "outboundTag": "direct", "type": "field" },
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
    }
});

if (jsonConfigs.length === 0) {
    console.error('هیچ کانفیگ معتبری یافت نشد!');
    process.exit(1);
}

// ذخیره به صورت آرایه ای از JSONها در فایل نهایی
fs.writeFileSync('vpn.json', JSON.stringify(jsonConfigs, null, 2), 'utf8');
console.log(`فایل vpn.json شامل ${jsonConfigs.length} کانفیگ با موفقیت ساخته شد!`);
