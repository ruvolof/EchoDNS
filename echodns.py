import configparser
import dnslib
import socket
from concurrent.futures import ThreadPoolExecutor


def extract_ip_from_domain(domain_name, base_domain):
  if domain_name.endswith(base_domain):
    ip_part = domain_name.split('.')[0]
    ip_address = ip_part.replace('-', '.')
    return ip_address
  return None


def handle_dns_query(data, addr, sock, base_domain):
  request = dnslib.DNSRecord.parse(data)
  domain_name = str(request.q.qname)
  ip_address = extract_ip_from_domain(domain_name, base_domain)
  if ip_address:
    reply = dnslib.DNSRecord(
        header=request.header,
        q=request.q,
        a=dnslib.RR(domain_name, rdata=dnslib.A(ip_address), ttl=300))
    sock.sendto(reply.pack(), addr)
    print(f"Responded to {domain_name} with {ip_address}")
  else:
    print(f"Received unsupported query for {domain_name}")


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
