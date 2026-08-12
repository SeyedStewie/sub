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

// --- Protocol parsers ---

function parseVless(link, index) {
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

        return {
            protocol: 'vless',
            tag: originalRemark,
            server: address,
            port: port,
            uuid: uuid,
            path: path,
            host: host,
            sni: sni,
            fp: fp,
            raw: link,
            encryption: params.get('encryption') || 'none'
        };
    } catch (e) {
        console.error(`خطا در پردازش لینک VLESS شماره ${index + 1}:`, e.message);
        return null;
    }
}

function parseTrojan(link, index) {
    try {
        const parsed = new URL(link);
        const address = parsed.hostname.replace(/\[|\]/g, '');
        const port = parseInt(parsed.port) || 443;
        const password = parsed.username || '';
        const params = parsed.searchParams;

        let workerDomain = params.get('sni') || params.get('host') || address;
        workerDomain = workerDomain.trim();

        const sni = randomizeCase(workerDomain);
        const host = workerDomain;
        const fp = params.get('fp') || 'chrome';

        let originalRemark = parsed.hash ? parsed.hash.slice(1).trim() : '';
        if (!originalRemark) originalRemark = params.get('remark') || `trojan-${index + 1}`;
        originalRemark = decodeURIComponent(originalRemark);

        const path = params.get('path') || '/';

        return {
            protocol: 'trojan',
            tag: originalRemark,
            server: address,
            port: port,
            password: password,
            sni: sni,
            fp: fp,
            host: host,
            path: path,
            raw: link
        };
    } catch (e) {
        console.error(`خطا در پردازش لینک Trojan شماره ${index + 1}:`, e.message);
        return null;
    }
}

function parseWireguard(link, index) {
    try {
        const parsed = new URL(link);
        const address = parsed.hostname.replace(/\[|\]/g, '');
        const port = parseInt(parsed.port) || 51820;
        const publicKey = parsed.username || '';
        const params = parsed.searchParams;

        const privateKey = params.get('private_key') || '';
        const allowedIPs = params.get('allowed_ips') || '0.0.0.0/0';
        const addressIP = params.get('address') || '';
        const dns = params.get('dns') || '';

        let originalRemark = parsed.hash ? parsed.hash.slice(1).trim() : '';
        if (!originalRemark) originalRemark = params.get('remark') || `wg-${index + 1}`;
        originalRemark = decodeURIComponent(originalRemark);

        return {
            protocol: 'wireguard',
            tag: originalRemark,
            server: address,
            port: port,
            public_key: publicKey,
            private_key: privateKey,
            allowed_ips: allowedIPs.split(',').map(s => s.trim()),
            address: addressIP.split(',').map(s => s.trim()),
            dns: dns,
            raw: link
        };
    } catch (e) {
        console.error(`خطا در پردازش لینک WireGuard شماره ${index + 1}:`, e.message);
        return null;
    }
}

// --- Build outbound objects for each protocol ---

function buildSingboxOutbound(parsed) {
    const base = {
        tag: parsed.tag,
        type: parsed.protocol,
        server: parsed.server,
        server_port: parsed.port,
        tcp_fast_open: false,
    };

    if (parsed.protocol === 'vless') {
        return {
            ...base,
            uuid: parsed.uuid,
            packet_encoding: '',
            network: 'tcp',
            tls: {
                enabled: true,
                server_name: parsed.sni,
                record_fragment: false,
                insecure: false,
                alpn: ['http/1.1'],
                utls: { enabled: true, fingerprint: parsed.fp }
            },
            transport: {
                type: 'ws',
                path: parsed.path,
                max_early_data: 2560,
                early_data_header_name: 'Sec-WebSocket-Protocol',
                headers: { Host: parsed.host }
            }
        };
    }

    if (parsed.protocol === 'trojan') {
        return {
            ...base,
            password: parsed.password,
            tls: {
                enabled: true,
                server_name: parsed.sni,
                insecure: false,
                alpn: ['http/1.1'],
                utls: { enabled: true, fingerprint: parsed.fp }
            },
            transport: {
                type: 'ws',
                path: parsed.path,
                headers: { Host: parsed.host }
            }
        };
    }

    if (parsed.protocol === 'wireguard') {
        return {
            ...base,
            private_key: parsed.private_key,
            peer_public_key: parsed.public_key,
            peer_address: parsed.server,
            peer_port: parsed.port,
            local_address: parsed.address,
            allowed_ips: parsed.allowed_ips,
            dns_servers: parsed.dns ? [parsed.dns] : [],
        };
    }

    return null;
}

function buildXrayOutbound(parsed) {
    if (parsed.protocol === 'vless') {
        return {
            protocol: 'vless',
            settings: {
                vnext: [{
                    address: parsed.server,
                    port: parsed.port,
                    users: [{ id: parsed.uuid, encryption: parsed.encryption || 'none' }]
                }]
            },
            streamSettings: {
                network: 'ws',
                wsSettings: { host: parsed.host, path: parsed.path + '?ed=2560' },
                security: 'tls',
                tlsSettings: { serverName: parsed.sni, fingerprint: parsed.fp, alpn: ['http/1.1'] },
                sockopt: { domainStrategy: 'UseIP', happyEyeballs: { tryDelayMs: 250, prioritizeIPv6: false, interleave: 2, maxConcurrentTry: 4 } }
            }
        };
    } else if (parsed.protocol === 'trojan') {
        return {
            protocol: 'trojan',
            settings: {
                servers: [{
                    address: parsed.server,
                    port: parsed.port,
                    password: parsed.password,
                    level: 0
                }]
            },
            streamSettings: {
                network: 'ws',
                wsSettings: { host: parsed.host, path: parsed.path + '?ed=2560' },
                security: 'tls',
                tlsSettings: { serverName: parsed.sni, fingerprint: parsed.fp, alpn: ['http/1.1'] },
                sockopt: { domainStrategy: 'UseIP', happyEyeballs: { tryDelayMs: 250, prioritizeIPv6: false, interleave: 2, maxConcurrentTry: 4 } }
            }
        };
    } else if (parsed.protocol === 'wireguard') {
        return {
            protocol: 'wireguard',
            settings: {
                secretKey: parsed.private_key,
                address: parsed.address,
                dns: parsed.dns ? [parsed.dns] : [],
                peers: [{
                    endpoint: `${parsed.server}:${parsed.port}`,
                    publicKey: parsed.public_key,
                    allowedIPs: parsed.allowed_ips
                }]
            },
            streamSettings: { network: 'raw' },
            sockopt: { domainStrategy: 'UseIP' }
        };
    }
    return null;
}

function buildXrayConfig(parsed) {
    const tag = parsed.tag;
    const outbound = buildXrayOutbound(parsed);

    return {
        remarks: tag,
        version: { min: '26.2.6' },
        log: { loglevel: 'none' },
        dns: {
            hosts: {
                'geosite:category-ads-all': '#3',
                'geosite:category-ads-ir': '#3'
            },
            servers: [
                { address: 'https://8.8.8.8/dns-query', tag: 'remote-dns' },
                { address: '8.8.8.8', domains: ['geosite:category-ir'], expectIPs: ['geoip:ir'], skipFallback: true },
                { address: '8.8.8.8', domains: [`full:${parsed.host || parsed.server}`], skipFallback: true }
            ],
            queryStrategy: 'UseIP',
            tag: 'dns'
        },
        inbounds: [
            {
                listen: '127.0.0.1',
                port: 10808,
                protocol: 'mixed',
                settings: { auth: 'noauth', udp: true },
                sniffing: { destOverride: ['http', 'tls'], enabled: true, routeOnly: true },
                tag: 'mixed-in'
            },
            {
                listen: '127.0.0.1',
                port: 10853,
                protocol: 'dokodemo-door',
                settings: { address: '1.1.1.1', network: 'tcp,udp', port: 53 },
                tag: 'dns-in'
            }
        ],
        outbounds: [
            { ...outbound, tag: 'proxy' },
            { protocol: 'dns', settings: { rules: [{ action: 'hijack' }] }, tag: 'dns-out' },
            { protocol: 'freedom', settings: { domainStrategy: 'UseIP' }, tag: 'direct' },
            { protocol: 'blackhole', settings: { response: { type: 'http' } }, tag: 'block' }
        ],
        routing: {
            domainStrategy: 'AsIs',
            rules: [
                { inboundTag: ['mixed-in'], port: 53, outboundTag: 'dns-out', type: 'field' },
                { inboundTag: ['dns-in'], outboundTag: 'dns-out', type: 'field' },
                { inboundTag: ['remote-dns'], outboundTag: 'proxy', type: 'field' },
                { inboundTag: ['dns'], outboundTag: 'direct', type: 'field' },
                { domain: ['geosite:private'], outboundTag: 'direct', type: 'field' },
                { ip: ['geoip:private'], outboundTag: 'direct', type: 'field' },
                { network: 'udp', outboundTag: 'block', type: 'field' },
                { domain: ['geosite:category-ads-all', 'geosite:category-ads-ir'], outboundTag: 'block', type: 'field' },
                { domain: ['geosite:category-ir'], outboundTag: 'direct', type: 'field' },
                { ip: ['geoip:ir'], outboundTag: 'direct', type: 'field' },
                { network: 'tcp', outboundTag: 'proxy', type: 'field' }
            ]
        },
        policy: {
            levels: { '0': { connIdle: 300, handshake: 4, uplinkOnly: 1, downlinkOnly: 1 } },
            system: { statsOutboundUplink: true, statsOutboundDownlink: true }
        },
        stats: {}
    };
}

function buildBestPingXrayConfig(parsedList) {
    if (parsedList.length === 0) return null;

    const proxyOutbounds = parsedList.map((parsed, idx) => {
        const outbound = buildXrayOutbound(parsed);
        return { ...outbound, tag: `proxy-${idx + 1}` };
    });

    const dnsDomains = parsedList
        .map(p => p.host || p.server)
        .filter(Boolean)
        .map(domain => `full:${domain}`);

    return {
        remarks: 'بهترین پینگ',
        version: { min: '26.2.6' },
        log: { loglevel: 'none' },
        dns: {
            hosts: {
                'geosite:category-ads-all': '#3',
                'geosite:category-ads-ir': '#3'
            },
            servers: [
                { address: 'https://8.8.8.8/dns-query', tag: 'remote-dns' },
                { address: '8.8.8.8', domains: ['geosite:category-ir'], expectIPs: ['geoip:ir'], skipFallback: true },
                { address: '8.8.8.8', domains: dnsDomains, skipFallback: true }
            ],
            queryStrategy: 'UseIP',
            tag: 'dns'
        },
        inbounds: [
            {
                listen: '127.0.0.1',
                port: 10808,
                protocol: 'mixed',
                settings: { auth: 'noauth', udp: true },
                sniffing: { destOverride: ['http', 'tls'], enabled: true, routeOnly: true },
                tag: 'mixed-in'
            },
            {
                listen: '127.0.0.1',
                port: 10853,
                protocol: 'dokodemo-door',
                settings: { address: '1.1.1.1', network: 'tcp,udp', port: 53 },
                tag: 'dns-in'
            }
        ],
        outbounds: [
            ...proxyOutbounds,
            { protocol: 'dns', settings: { rules: [{ action: 'hijack' }] }, tag: 'dns-out' },
            { protocol: 'freedom', settings: { domainStrategy: 'UseIP' }, tag: 'direct' },
            { protocol: 'blackhole', settings: { response: { type: 'http' } }, tag: 'block' }
        ],
        routing: {
            domainStrategy: 'AsIs',
            rules: [
                { inboundTag: ['mixed-in'], port: 53, outboundTag: 'dns-out', type: 'field' },
                { inboundTag: ['dns-in'], outboundTag: 'dns-out', type: 'field' },
                { inboundTag: ['remote-dns'], balancerTag: 'all-proxies', type: 'field' },
                { inboundTag: ['dns'], outboundTag: 'direct', type: 'field' },
                { domain: ['geosite:private'], outboundTag: 'direct', type: 'field' },
                { ip: ['geoip:private'], outboundTag: 'direct', type: 'field' },
                { network: 'udp', outboundTag: 'block', type: 'field' },
                { domain: ['geosite:category-ads-all', 'geosite:category-ads-ir'], outboundTag: 'block', type: 'field' },
                { domain: ['geosite:category-ir'], outboundTag: 'direct', type: 'field' },
                { ip: ['geoip:ir'], outboundTag: 'direct', type: 'field' },
                { network: 'tcp', balancerTag: 'all-proxies', type: 'field' }
            ],
            balancers: [
                {
                    tag: 'all-proxies',
                    selector: ['proxy'],
                    strategy: { type: 'leastPing' },
                    fallbackTag: 'proxy-1'
                }
            ]
        },
        observatory: {
            subjectSelector: ['proxy'],
            probeUrl: 'https://www.gstatic.com/generate_204',
            probeInterval: '30s',
            enableConcurrency: true
        },
        policy: {
            levels: { '0': { connIdle: 300, handshake: 4, uplinkOnly: 1, downlinkOnly: 1 } },
            system: { statsOutboundUplink: true, statsOutboundDownlink: true }
        },
        stats: {}
    };
}

function buildClashProxy(parsed) {
    const proxy = {
        name: parsed.tag,
        type: parsed.protocol,
        server: parsed.server,
        port: parsed.port,
        'ip-version': 'ipv4',
        tfo: false,
        udp: false
    };

    if (parsed.protocol === 'vless') {
        return {
            ...proxy,
            uuid: parsed.uuid,
            'packet-encoding': '',
            tls: true,
            servername: parsed.sni,
            'client-fingerprint': parsed.fp,
            'skip-cert-verify': false,
            alpn: ['http/1.1'],
            network: 'ws',
            'ws-opts': {
                path: parsed.path,
                'max-early-data': 2560,
                'early-data-header-name': 'Sec-WebSocket-Protocol',
                headers: { Host: parsed.host }
            }
        };
    } else if (parsed.protocol === 'trojan') {
        return {
            ...proxy,
            password: parsed.password,
            tls: true,
            servername: parsed.sni,
            'client-fingerprint': parsed.fp,
            'skip-cert-verify': false,
            alpn: ['http/1.1'],
            network: 'ws',
            'ws-opts': {
                path: parsed.path,
                headers: { Host: parsed.host }
            }
        };
    } else if (parsed.protocol === 'wireguard') {
        return {
            ...proxy,
            'private-key': parsed.private_key,
            'public-key': parsed.public_key,
            'allowed-ips': parsed.allowed_ips,
            'ip-address': parsed.address,
            dns: parsed.dns ? [parsed.dns] : []
        };
    }
    return null;
}

async function main() {
    const singboxOutbounds = [];
    const outboundTags = [];
    const validLinks = [];
    const parsedConfigs = [];
    const xrayConfigs = [];
    const clashProxies = [];

    for (let index = 0; index < lines.length; index++) {
        const line = lines[index].trim();
        let parsed = null;

        if (line.startsWith('vless://')) {
            parsed = parseVless(line, index);
        } else if (line.startsWith('trojan://')) {
            parsed = parseTrojan(line, index);
        } else if (line.startsWith('wireguard://')) {
            parsed = parseWireguard(line, index);
        } else {
            console.warn(`خط ${index + 1}: پروتکل ناشناخته - نادیده گرفته شد`);
            continue;
        }

        if (!parsed) continue;

        parsedConfigs.push(parsed);
        validLinks.push(parsed.raw);
        outboundTags.push(parsed.tag);

        // Sing-box outbound
        const sbOut = buildSingboxOutbound(parsed);
        if (sbOut) singboxOutbounds.push(sbOut);

        // Xray config
        const xray = buildXrayConfig(parsed);
        if (xray) xrayConfigs.push(xray);

        // Clash proxy
        const clash = buildClashProxy(parsed);
        if (clash) clashProxies.push(clash);
    }

    if (validLinks.length === 0) {
        console.error('هیچ کانفیگ معتبری یافت نشد!');
        process.exit(1);
    }

    // Append Best Ping entry to Xray configs array (vpn.json)
    const bestPingConfig = buildBestPingXrayConfig(parsedConfigs);
    if (bestPingConfig) {
        xrayConfigs.push(bestPingConfig);
    }

    // 1. vpn64.txt
    const joinedLinks = validLinks.join('\n');
    const base64Encoded = Buffer.from(joinedLinks).toString('base64');
    fs.writeFileSync('vpn64.txt', base64Encoded, 'utf8');

    // 2. vpn.json (Xray with Best Ping included)
    fs.writeFileSync('vpn.json', JSON.stringify(xrayConfigs, null, 4), 'utf8');

    // 3. vpn.yml – Clash
    const proxyNames = clashProxies.map(p => p.name);
    const selectorName = "انتخاب دستی";
    const urlTestName = "بهترین پینگ";

    const clashConfig = {
        "mixed-port": 7890,
        "ipv6": true,
        "allow-lan": false,
        "unified-delay": false,
        "log-level": "silent",
        "mode": "rule",
        "disable-keep-alive": false,
        "keep-alive-idle": 10,
        "keep-alive-interval": 15,
        "tcp-concurrent": true,
        "geo-auto-update": true,
        "geo-update-interval": 168,
        "external-controller": "127.0.0.1:9090",
        "external-controller-cors": { "allow-origins": ["*"], "allow-private-network": true },
        "external-ui": "ui",
        "external-ui-url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
        "profile": { "store-selected": true, "store-fake-ip": true },
        "dns": {
            "enable": true,
            "respect-rules": true,
            "use-system-hosts": false,
            "listen": "127.0.0.1:1053",
            "ipv6": false,
            "hosts": { "rule-set:category-ads-all": "rcode://refused" },
            "nameserver": [`https://8.8.8.8/dns-query#${selectorName}`],
            "proxy-server-nameserver": ["8.8.8.8#DIRECT"],
            "direct-nameserver": ["8.8.8.8#DIRECT"],
            "direct-nameserver-follow-policy": true,
            "nameserver-policy": { "rule-set:ir": "8.8.8.8#DIRECT" },
            "enhanced-mode": "redir-host"
        },
        "tun": {
            "enable": true,
            "stack": "mixed",
            "auto-route": true,
            "strict-route": true,
            "auto-detect-interface": true,
            "dns-hijack": ["any:53", "tcp://any:53"],
            "mtu": 9000
        },
        "sniffer": {
            "enable": true,
            "force-dns-mapping": true,
            "parse-pure-ip": true,
            "override-destination": true,
            "sniff": {
                "HTTP": { "ports": [80, 8080, 8880, 2052, 2082, 2086, 2095] },
                "TLS": { "ports": [443, 8443, 2053, 2083, 2087, 2096] }
            }
        },
        "proxies": clashProxies,
        "proxy-groups": [
            { "name": selectorName, "type": "select", "proxies": [urlTestName, ...proxyNames] },
            { "name": urlTestName, "type": "url-test", "proxies": proxyNames, "url": "https://www.gstatic.com/generate_204", "interval": 30, "tolerance": 50 }
        ],
        "rule-providers": {
            "category-ads-all": {
                "type": "http",
                "format": "text",
                "behavior": "domain",
                "path": "./ruleset/category-ads-all.txt",
                "interval": 86400,
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/category-ads-all.txt"
            },
            "ir": {
                "type": "http",
                "format": "text",
                "behavior": "domain",
                "path": "./ruleset/ir.txt",
                "interval": 86400,
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt"
            },
            "ir-cidr": {
                "type": "http",
                "format": "text",
                "behavior": "ipcidr",
                "path": "./ruleset/ir-cidr.txt",
                "interval": 86400,
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ircidr.txt"
            }
        },
        "rules": [
            "GEOIP,lan,DIRECT,no-resolve",
            "NETWORK,udp,REJECT",
            "RULE-SET,category-ads-all,REJECT",
            "RULE-SET,ir,DIRECT",
            "RULE-SET,ir-cidr,DIRECT",
            `MATCH,${selectorName}`
        ],
        "ntp": { "enable": true, "server": "time.cloudflare.com", "port": 123, "interval": 30 }
    };

    fs.writeFileSync('vpn.yml', JSON.stringify(clashConfig, null, 4), 'utf8');

    // 4. vpns.json – Sing-box
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
