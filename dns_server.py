#!/usr/bin/env python3
import socket
import struct

class DNSServer:
    def __init__(self):
        self.dns_records = {
            b'google.com': '8.8.8.8',
            b'ya.ru': '87.250.250.242', 
            b'malicious.com': '1.2.3.4',
            b'ads.com': '5.6.7.8',
            b'tracker.com': '9.10.11.12',
            b'good-site.com': '192.168.30.10'
        }
    
    def parse_dns_query(self, data):
        try:
            transaction_id = data[:2]
            flags = data[2:4]
            questions = struct.unpack('!H', data[4:6])[0]

            qname_parts = []
            pos = 12
            while True:
                length = data[pos]
                if length == 0:
                    break
                qname_parts.append(data[pos+1:pos+1+length])
                pos += length + 1
            qname = b'.'.join(qname_parts)
            
            qtype = data[pos+1:pos+3]
            qclass = data[pos+3:pos+5]
            
            return transaction_id, qname, qtype, qclass
        except:
            return None, None, None, None
    
    def build_dns_response(self, transaction_id, qname, qtype, qclass, ip):
        flags = b'\x81\x80'
        questions = b'\x00\x01'
        answers = b'\x00\x01'
        authority = b'\x00\x00'
        additional = b'\x00\x00'
        
        header = transaction_id + flags + questions + answers + authority + additional

        question = b''
        for part in qname.split(b'.'):
            question += bytes([len(part)]) + part
        question += b'\x00' + qtype + qclass

        name = b'\xc0\x0c'
        type_a = b'\x00\x01'
        class_in = b'\x00\x01'
        ttl = b'\x00\x00\x0e\x10'
        rdlength = b'\x00\x04' 

        ip_parts = [int(part) for part in ip.split('.')]
        rdata = bytes(ip_parts)
        
        answer = name + type_a + class_in + ttl + rdlength + rdata
        
        return header + question + answer
    
    def handle_query(self, data, addr):
        transaction_id, qname, qtype, qclass = self.parse_dns_query(data)
        
        if qname:
            print(f"DNS Query: {qname.decode()} from {addr[0]}")
            
            if qname in self.dns_records:
                ip = self.dns_records[qname]
                print(f"DNS Response: {qname.decode()} -> {ip}")
                response = self.build_dns_response(transaction_id, qname, qtype, qclass, ip)
                return response
            else:
                print(f"DNS Not Found: {qname.decode()}")
                flags = b'\x81\x83'
                header = transaction_id + flags + b'\x00\x01\x00\x00\x00\x00\x00\x00'
                question = b''
                for part in qname.split(b'.'):
                    question += bytes([len(part)]) + part
                question += b'\x00' + qtype + qclass
                return header + question
        return None
    
    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0', 53))
        print("DNS Server started on port 53")
        
        while True:
            try:
                data, addr = sock.recvfrom(512)
                response = self.handle_query(data, addr)
                if response:
                    sock.sendto(response, addr)
            except Exception as e:
                print(f"Error: {e}")

if __name__ == "__main__":
    server = DNSServer()
    server.start()
