import configparser
import datetime
import dnslib
import grp
import os
import pwd
import socket
import traceback
from concurrent.futures import ThreadPoolExecutor

from payload_decoders import apply_all_payload_decoders


def log_with_time(message):
  print(f'{datetime.datetime.now()} - {message}')


def log_bad_request(src_ip, domain_name):
  msg = f'src_ip: {src_ip} - query: {domain_name} - status: BAD_DOMAIN'
  log_with_time(msg)


def log_valid_request(src_ip, domain_name, decoder, returned_ip):
  msg = (f'src_ip: {src_ip} - query: {domain_name} - decoded_with: '
         f'{decoder.__name__} - returned_ip: {returned_ip} - status: OK')
  log_with_time(msg)


def drop_privileges(uid_name='nobody', gid_name='nogroup'):
  running_uid = pwd.getpwnam(uid_name).pw_uid
  running_gid = grp.getgrnam(gid_name).gr_gid
  os.setgroups([])
  os.setgid(running_gid)
  os.setuid(running_uid)
  os.umask(0o77)
  if os.getuid() == 0 or os.getgid() == 0:
    raise Exception('Failed to drop root privileges. Exiting.')
  log_with_time('Dropped root privileges. Running as nobody.')


def extract_payload_from_query(domain_name, base_domain):
  if domain_name.endswith(base_domain):
    base_length = len(base_domain.split('.'))
    payload = '.'.join(domain_name.split('.')[:-base_length])
    return payload
  return None


def reply_with_empty_response(dns_request, sock, addr):
  sock.sendto(dns_request.reply().pack(), addr)


def reply_with_A_record(dns_request, sock, addr, ip_address):
  reply = dns_request.reply()
  reply.add_answer(dnslib.RR(str(dns_request.q.qname),
                             rdata=dnslib.A(ip_address),
                             ttl=300))
  sock.sendto(reply.pack(), addr)


def handle_dns_query(data, addr, sock, base_domain):
  try:
    dns_request = dnslib.DNSRecord.parse(data)
    domain_name = str(dns_request.q.qname)
    payload = extract_payload_from_query(domain_name, base_domain)
    if not payload:
      reply_with_empty_response(dns_request, sock, addr)
      log_bad_request(addr[0], domain_name)
      return
    ip_address, decoder = apply_all_payload_decoders(payload)
    if ip_address:
      reply_with_A_record(dns_request, sock, addr, ip_address)
      log_valid_request(addr[0], domain_name, decoder, ip_address)
    else:
      reply_with_empty_response(dns_request, sock, addr)
      log_bad_request(addr[0], domain_name)
  except:
    traceback.print_exc()


def main():
  config = configparser.ConfigParser()
  config.read('config.ini')
  bind_address = config['server']['bind_address']
  bind_port = int(config['server']['bind_port'])
  base_domain = config['server']['base_domain']

  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.bind((bind_address, bind_port))
  log_with_time(f'EchoDNS server is listening on {bind_address}:{bind_port}')

  drop_privileges()

  with ThreadPoolExecutor(max_workers=20) as executor:
    while True:
      data, addr = sock.recvfrom(512)
      executor.submit(handle_dns_query, data, addr, sock, base_domain)


if __name__ == '__main__':
  main()
