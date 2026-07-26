const fs = require('fs');
const url = require('url');

// خواندن فایل vpn.txt
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

// برای نمونه، اولین کانفیگ را پردازش می‌کنیم (یا می‌توانید برای آرایه ای از Outbounds توسعه دهید)
const vlessLink = lines[0].trim();

function parseVless(link) {
    const parsed = new URL(link);
    const uuid = parsed.username;
    const address = parsed.hostname;
    const port = parseInt(parsed.port);
    const remarks = decodeURIComponent(parsed.hash.replace('#', ''));
    
    const params = parsed.searchParams;
    const path = params.get('path') || '';
    const security = params.get('security') || 'none';
    const sni = params.get('sni') || '';
    const fp = params.get('fp') || 'chrome';
    const alpn = params.get('alpn') ? params.get('alpn').split(',') : ['http/1.1'];
    const net = parsed.protocol.replace(':', '') === 'vless' ? (params.get('type') || 'tcp') : 'tcp';

    return {
        remarks,
        address,
        port,
        uuid,
        path,
        security,
        sni,
        fp,
        alpn,
        net
    };
}

const configData = parseVless(vlessLink);

// ساختار نهایی JSON مطابق نمونه شما
const jsonTemplate = {
  "remarks": configData.remarks,
  "version": {
    "min": "26.2.6"
  },
  "log": {
    "loglevel": "none"
  },
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
        "domains": [
          "geosite:category-ir"
        ],
        "expectIPs": [
          "geoip:ir"
        ],
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
        "destOverride": [
          "http",
          "tls"
        ],
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
            "address": configData.address,
            "port": configData.port,
            "users": [
              {
                "id": configData.uuid,
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": configData.net,
        "wsSettings": {
          "host": configData.sni.toLowerCase(),
          "path": configData.path
        },
        "security": configData.security,
        "tlsSettings": {
          "serverName": configData.sni,
          "fingerprint": configData.fp,
          "alpn": configData.alpn
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
          {
            "action": "hijack"
          }
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
    "domainStrategy": "AsIs",
    "rules": [
      {
        "inboundTag": ["mixed-in"],
        "port": 53,
        "outboundTag": "dns-out",
        "type": "field"
      },
      {
        "inboundTag": ["dns-in"],
        "outboundTag": "dns-out",
        "type": "field"
      },
      {
        "inboundTag": ["remote-dns"],
        "outboundTag": "proxy",
        "type": "field"
      },
      {
        "inboundTag": ["dns"],
        "outboundTag": "direct",
        "type": "field"
      },
      {
        "domain": ["geosite:private"],
        "outboundTag": "direct",
        "type": "field"
      },
      {
        "ip": ["geoip:private"],
        "outboundTag": "direct",
        "type": "field"
      },
      {
        "network": "udp",
        "outboundTag": "block",
        "type": "field"
      },
      {
        "domain": ["geosite:category-ads-all", "geosite:category-ads-ir"],
        "outboundTag": "block",
        "type": "field"
      },
      {
        "domain": ["geosite:category-ir"],
        "outboundTag": "direct",
        "type": "field"
      },
      {
        "ip": ["geoip:ir"],
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

fs.writeFileSync('vpn.json', JSON.stringify(jsonTemplate, null, 2), 'utf8');
console.log('فایل vpn.json با موفقیت ساخته شد!');
