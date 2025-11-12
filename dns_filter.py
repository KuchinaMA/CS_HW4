#!/usr/bin/env python3
import netfilterqueue
import argparse
from scapy.all import IP, UDP, DNS, DNSQR
import time

class DNSFilter:
    def __init__(self, rules_file='dns_rules.txt'):
        self.rules = []
        self.seen_requests = set()
        self.blocked_domains = set() 
        self.load_rules(rules_file)
        print(f"DNS Filter started with {len(self.rules)} rules")
    
    def load_rules(self, rules_file):
        try:
            with open(rules_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    
                    parts = line.split()
                    if len(parts) >= 3:
                        field = parts[0]
                        operator = parts[1]
                        value = ' '.join(parts[2:-1])
                        action = parts[-1]
                        
                        if value.startswith('"') and value.endswith('"'):
                            value = value[1:-1]
                        
                        self.rules.append({
                            'field': field,
                            'operator': operator,
                            'value': value,
                            'action': action
                        })
                        print(f"Loaded: {field} {operator} '{value}' -> {action}")
            
        except FileNotFoundError:
            print(f"Rules file {rules_file} not found, using defaults")
            self.set_default_rules()
    
    def set_default_rules(self):
        self.rules = [
            {'field': 'qname', 'operator': 'matches', 'value': 'malicious.com', 'action': 'drop'},
            {'field': 'qname', 'operator': 'matches', 'value': 'ads.com', 'action': 'drop'},
            {'field': 'qname', 'operator': 'matches', 'value': 'tracker.com', 'action': 'drop'},
            {'field': 'qtype', 'operator': '==', 'value': 'A', 'action': 'pass'},
            {'field': 'qname', 'operator': 'matches', 'value': 'google.com', 'action': 'pass'},
        ]
    
    def get_query_type_description(self, qtype):
        types = {
            1: 'IPv4',
            28: 'IPv6', 
            2: 'NS',
            5: 'CNAME',
            15: 'MX',
            16: 'TXT'
        }
        return types.get(qtype, f'type:{qtype}')
    
    def check_rule(self, rule, dns_data):
        field = rule['field']
        operator = rule['operator']
        value = rule['value']
        
        field_value = dns_data.get(field, '')
        
        try:
            if operator == '==':
                return str(field_value) == value
            elif operator == '!=':
                return str(field_value) != value
            elif operator == 'contains':
                return value.lower() in str(field_value).lower()
            elif operator == 'matches':
                return value in str(field_value)
        except:
            return False
        
        return False
    
    def process_packet(self, packet):
        try:
            pkt = IP(packet.get_payload())
            
            if pkt.haslayer(UDP) and pkt.haslayer(DNS):
                dns = pkt[DNS]
                sport, dport = pkt[UDP].sport, pkt[UDP].dport

                if dns.qr == 0 and dport == 53:
                    qname = dns.qd.qname.decode('utf-8').rstrip('.') if dns.qd.qname else ''
                    qtype = dns.qd.qtype
                    qtype_desc = self.get_query_type_description(qtype)
                    
                    request_id = f"{pkt.src}:{qname}:{qtype}"
                    
                    if request_id in self.seen_requests:
                        packet.accept()
                        return
                    
                    self.seen_requests.add(request_id)
                    if len(self.seen_requests) > 1000:
                        self.seen_requests.clear()
                    
                    dns_data = {
                        'qname': qname,
                        'qtype': qtype,
                        'qtype_desc': qtype_desc,
                        'src_ip': pkt.src,
                        'dst_ip': pkt.dst
                    }
                    
                    print(f"DNS REQUEST: {qname} ({qtype_desc}) from {pkt.src}")
                    
                    rule_matched = False
                    for rule in self.rules:
                        if self.check_rule(rule, dns_data):
                            if rule['action'] == 'drop':
                                print(f"BLOCKED REQUEST: {rule['field']} {rule['operator']} '{rule['value']}'")
                                self.blocked_domains.add(qname)
                                packet.drop()
                                rule_matched = True
                                break
                            elif rule['action'] == 'pass':
                                print(f"ALLOWED REQUEST: {rule['field']} {rule['operator']} '{rule['value']}'")
                                packet.accept()
                                rule_matched = True
                                break
                    
                    if not rule_matched:
                        print(f"ACCEPT REQUEST: {qname} (no rule matched)")
                        packet.accept()
                    return

                elif dns.qr == 1 and sport == 53:
                    if hasattr(dns, 'an') and dns.an:
                        for answer in dns.an:
                            if hasattr(answer, 'rrname'):
                                domain = answer.rrname.decode('utf-8').rstrip('.')
                                if domain in self.blocked_domains:
                                    print(f"BLOCKED RESPONSE: {domain} to {pkt.dst}")
                                    packet.drop()
                                    return
                    
                    print(f"DNS RESPONSE: to {pkt.dst}")
                    packet.accept()
                    return

            packet.accept()
            
        except Exception as e:
            print(f"Error: {e}")
            packet.accept()

def main():
    parser = argparse.ArgumentParser(description='DNS Filter with NFQUEUE')
    parser.add_argument('--rules', default='dns_rules.txt', help='Rules file path')
    parser.add_argument('--queue-num', type=int, default=5, help='NFQUEUE number')
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("DNS Filter with NFQUEUE")
    print("=" * 50)
    print(f"Rules file: {args.rules}")
    print(f"Queue number: {args.queue_num}")
    
    filter = DNSFilter(args.rules)
    queue = netfilterqueue.NetfilterQueue()
    
    try:
        queue.bind(args.queue_num, filter.process_packet)
        print(f"Filter running on queue {args.queue_num}")
        print("Press Ctrl+C to stop")
        print("-" * 50)
        
        queue.run()
        
    except KeyboardInterrupt:
        print("\nStopping filter...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        queue.unbind()

if __name__ == "__main__":
    main()