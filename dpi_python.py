"""
Pure Python PCAP parser and DPI engine for cloud deployment.
Replicates the C++ DPI engine's functionality without needing compilation.
"""
import struct
import os

# Application signatures based on SNI/domain patterns
APP_SIGNATURES = {
    'youtube.com': 'YouTube',
    'googlevideo.com': 'YouTube',
    'ytimg.com': 'YouTube',
    'facebook.com': 'Facebook',
    'fbcdn.net': 'Facebook',
    'instagram.com': 'Instagram',
    'cdninstagram.com': 'Instagram',
    'twitter.com': 'Twitter/X',
    'x.com': 'Twitter/X',
    'twimg.com': 'Twitter/X',
    'tiktok.com': 'TikTok',
    'tiktokcdn.com': 'TikTok',
    'discord.com': 'Discord',
    'discordapp.com': 'Discord',
    'telegram.org': 'Telegram',
    't.me': 'Telegram',
    'spotify.com': 'Spotify',
    'scdn.co': 'Spotify',
    'google.com': 'Google',
    'googleapis.com': 'Google',
    'gstatic.com': 'Google',
    'github.com': 'GitHub',
    'githubusercontent.com': 'GitHub',
    'amazon.com': 'Amazon',
    'amazonaws.com': 'Amazon',
    'apple.com': 'Apple',
    'icloud.com': 'Apple',
    'cloudflare.com': 'Cloudflare',
    'zoom.us': 'Zoom',
    'zoomcdn.com': 'Zoom',
    'netflix.com': 'Netflix',
    'nflxvideo.net': 'Netflix',
    'microsoft.com': 'Microsoft',
    'whatsapp.com': 'WhatsApp',
    'whatsapp.net': 'WhatsApp',
    'snapchat.com': 'Snapchat',
    'reddit.com': 'Reddit',
    'redditmedia.com': 'Reddit',
    'linkedin.com': 'LinkedIn',
    'twitch.tv': 'Twitch',
}


def classify_domain(domain):
    """Classify a domain into an application name."""
    domain = domain.lower().strip()
    for pattern, app in APP_SIGNATURES.items():
        if domain.endswith(pattern) or domain == pattern:
            return app
    return None


def extract_sni(payload):
    """Extract SNI from TLS Client Hello."""
    try:
        if len(payload) < 6:
            return None
        # Check for TLS handshake
        content_type = payload[0]
        if content_type != 0x16:  # Not a handshake
            return None
        
        # TLS version
        tls_version = struct.unpack('!H', payload[1:3])[0]
        if tls_version < 0x0301 or tls_version > 0x0304:
            return None
        
        # Record length
        record_length = struct.unpack('!H', payload[3:5])[0]
        
        # Handshake type (should be Client Hello = 1)
        if len(payload) < 6 or payload[5] != 0x01:
            return None
        
        # Skip handshake header (4 bytes: type + length)
        pos = 9
        
        # Skip client version (2 bytes)
        pos += 2
        
        # Skip client random (32 bytes)
        pos += 32
        
        if pos >= len(payload):
            return None
        
        # Skip session ID
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        
        if pos + 2 >= len(payload):
            return None
        
        # Skip cipher suites
        cipher_suites_len = struct.unpack('!H', payload[pos:pos+2])[0]
        pos += 2 + cipher_suites_len
        
        if pos >= len(payload):
            return None
        
        # Skip compression methods
        comp_methods_len = payload[pos]
        pos += 1 + comp_methods_len
        
        if pos + 2 >= len(payload):
            return None
        
        # Extensions length
        extensions_len = struct.unpack('!H', payload[pos:pos+2])[0]
        pos += 2
        
        extensions_end = pos + extensions_len
        
        while pos + 4 < extensions_end and pos + 4 < len(payload):
            ext_type = struct.unpack('!H', payload[pos:pos+2])[0]
            ext_len = struct.unpack('!H', payload[pos+2:pos+4])[0]
            pos += 4
            
            if ext_type == 0x0000:  # SNI extension
                if pos + 5 < len(payload):
                    # Skip SNI list length (2 bytes) and type (1 byte)
                    sni_name_len = struct.unpack('!H', payload[pos+3:pos+5])[0]
                    sni_start = pos + 5
                    sni_end = sni_start + sni_name_len
                    if sni_end <= len(payload):
                        return payload[sni_start:sni_end].decode('ascii', errors='ignore')
                return None
            
            pos += ext_len
        
        return None
    except (struct.error, IndexError):
        return None


def extract_http_host(payload):
    """Extract Host header from HTTP request."""
    try:
        text = payload.decode('ascii', errors='ignore')
        if text.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
            for line in text.split('\r\n'):
                if line.lower().startswith('host:'):
                    return line.split(':', 1)[1].strip().split(':')[0]
        return None
    except:
        return None


def parse_pcap(filepath, block_app=None, block_ip=None):
    """
    Parse a PCAP file and analyze packets.
    Returns structured analysis results.
    """
    result = {
        "summary": {
            "total_packets": 0,
            "total_bytes": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "forwarded": 0,
            "dropped": 0
        },
        "thread_stats": {
            "LB0": 0, "LB1": 0,
            "FP0": 0, "FP1": 0, "FP2": 0, "FP3": 0
        },
        "apps": {},
        "domains": [],
        "output_file": ""
    }
    
    seen_domains = {}
    
    with open(filepath, 'rb') as f:
        # Read global header (24 bytes)
        global_header = f.read(24)
        if len(global_header) < 24:
            return result
        
        magic = struct.unpack('<I', global_header[0:4])[0]
        if magic == 0xa1b2c3d4:
            endian = '<'
        elif magic == 0xd4c3b2a1:
            endian = '>'
        else:
            return result
        
        packet_count = 0
        
        while True:
            # Read packet header (16 bytes)
            pkt_header = f.read(16)
            if len(pkt_header) < 16:
                break
            
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f'{endian}IIII', pkt_header)
            
            # Read packet data
            pkt_data = f.read(incl_len)
            if len(pkt_data) < incl_len:
                break
            
            packet_count += 1
            result["summary"]["total_packets"] += 1
            result["summary"]["total_bytes"] += orig_len
            
            # Simulate load balancer distribution
            if packet_count % 2 == 1:
                result["thread_stats"]["LB0"] += 1
                result["thread_stats"]["FP0"] += 1
            else:
                result["thread_stats"]["LB1"] += 1
                result["thread_stats"]["FP3"] += 1
            
            # Parse Ethernet header (14 bytes)
            if len(pkt_data) < 14:
                continue
            
            eth_type = struct.unpack('!H', pkt_data[12:14])[0]
            if eth_type != 0x0800:  # Not IPv4
                continue
            
            # Parse IP header
            ip_start = 14
            if len(pkt_data) < ip_start + 20:
                continue
            
            ip_header = pkt_data[ip_start:]
            ip_version = (ip_header[0] >> 4) & 0xF
            ip_ihl = (ip_header[0] & 0xF) * 4
            
            if ip_version != 4:
                continue
            
            protocol = ip_header[9]
            src_ip = '.'.join(str(b) for b in ip_header[12:16])
            dst_ip = '.'.join(str(b) for b in ip_header[16:20])
            
            # Check IP blocking
            blocked = False
            if block_ip and (src_ip == block_ip or dst_ip == block_ip):
                blocked = True
            
            transport_start = ip_start + ip_ihl
            
            if protocol == 6:  # TCP
                result["summary"]["tcp_packets"] += 1
                
                if len(pkt_data) < transport_start + 20:
                    continue
                
                src_port = struct.unpack('!H', pkt_data[transport_start:transport_start+2])[0]
                dst_port = struct.unpack('!H', pkt_data[transport_start+2:transport_start+4])[0]
                tcp_data_offset = ((pkt_data[transport_start+12] >> 4) & 0xF) * 4
                payload_start = transport_start + tcp_data_offset
                payload = pkt_data[payload_start:]
                
                app_type = 'Unknown'
                domain = None
                
                if dst_port == 443 or src_port == 443:
                    sni = extract_sni(payload)
                    if sni:
                        domain = sni
                        classified = classify_domain(sni)
                        app_type = classified if classified else 'HTTPS'
                    else:
                        app_type = 'HTTPS'
                elif dst_port == 80 or src_port == 80:
                    host = extract_http_host(payload)
                    if host:
                        domain = host
                        classified = classify_domain(host)
                        app_type = classified if classified else 'HTTP'
                    else:
                        app_type = 'HTTP'
                elif dst_port == 53 or src_port == 53:
                    app_type = 'DNS'
                
                # Check app blocking
                if block_app and app_type.lower() == block_app.lower():
                    blocked = True
                
                if domain and domain not in seen_domains:
                    seen_domains[domain] = app_type
                
                result["apps"][app_type] = result["apps"].get(app_type, 0) + 1
                
            elif protocol == 17:  # UDP
                result["summary"]["udp_packets"] += 1
                
                if len(pkt_data) < transport_start + 8:
                    continue
                
                src_port = struct.unpack('!H', pkt_data[transport_start:transport_start+2])[0]
                dst_port = struct.unpack('!H', pkt_data[transport_start+2:transport_start+4])[0]
                
                app_type = 'Unknown'
                if dst_port == 53 or src_port == 53:
                    app_type = 'DNS'
                
                if block_app and app_type.lower() == block_app.lower():
                    blocked = True
                
                result["apps"][app_type] = result["apps"].get(app_type, 0) + 1
            
            if blocked:
                result["summary"]["dropped"] += 1
            else:
                result["summary"]["forwarded"] += 1
    
    # Convert domains dict to list
    result["domains"] = [{"domain": d, "app": a} for d, a in seen_domains.items()]
    
    # Convert apps dict to sorted list
    total = result["summary"]["total_packets"]
    apps_list = []
    for name, count in sorted(result["apps"].items(), key=lambda x: -x[1]):
        pct = round((count / total) * 100, 1) if total > 0 else 0
        apps_list.append({"name": name, "count": count, "percent": pct})
    result["apps"] = apps_list
    
    return result
