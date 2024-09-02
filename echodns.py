import configparser
import dnslib
import socket
import traceback
from concurrent.futures import ThreadPoolExecutor

from payload_decoders import apply_all_payload_decoders


def extract_payload_from_query(domain_name, base_domain):
  if domain_name.endswith(base_domain):
    base_length = len(base_domain.split('.'))
    payload = '.'.join(domain_name.split('.')[:-base_length])
    return payload
  return None


def reply_with_empty_response(dns_request, sock, addr):
  reply = dnslib.DNSRecord(header=dns_request.header, q=dns_request.q)
  sock.sendto(reply.pack(), addr)


def reply_with_A_record(dns_request, sock, addr, ip_address):
  reply = dnslib.DNSRecord(header=dns_request.header,
                           q=dns_request.q,
                           a=dnslib.RR(str(dns_request.q.qname),
                                       rdata=dnslib.A(ip_address),
                                       ttl=300))
  sock.sendto(reply.pack(), addr)


def handle_dns_query(data, addr, sock, base_domain):
  try:
    request = dnslib.DNSRecord.parse(data)
    domain_name = str(request.q.qname)
    payload = extract_payload_from_query(domain_name, base_domain)
    if not payload:
      reply_with_empty_response(request, sock, addr)
      return
    ip_address = apply_all_payload_decoders(payload)
    if ip_address:
      reply_with_A_record(request, sock, addr, ip_address)
    else:
      reply_with_empty_response(request, sock, addr)
  except:
    traceback.print_exc()
    reply_with_empty_response(request, sock, addr)


def main():
  config = configparser.ConfigParser()
  config.read('config.ini')
  bind_address = config['server']['bind_address']
  bind_port = int(config['server']['bind_port'])
  base_domain = config['server']['base_domain']

  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.bind((bind_address, bind_port))
  print(f"EchoDNS server is listening on {bind_address}:{bind_port}")

  with ThreadPoolExecutor(max_workers=20) as executor:
    while True:
      data, addr = sock.recvfrom(512)
      executor.submit(handle_dns_query, data, addr, sock, base_domain)


if __name__ == "__main__":
  main()
