import socket


class PlainDecoder:
  @staticmethod
  def get_ip(payload):
    try:
      socket.inet_aton(payload)
      return payload
    except OSError:
      return None


class HiphenDecoder:
  @staticmethod
  def get_ip(payload):
    try:
      ip_address = payload.replace('-', '.')
      socket.inet_aton(ip_address)
      return ip_address
    except OSError:
      return None
    

class HexDecoder:
  @staticmethod
  def get_ip(payload):
    try:
      packed_ip = bytes.fromhex(payload)
      ip_address = socket.inet_ntoa(packed_ip)
      return ip_address
    except OSError:
      return None
    

payload_decoders = [PlainDecoder, HiphenDecoder, HexDecoder]


def apply_all_payload_decoders(payload):
  for decoder in payload_decoders:
    ip_address = decoder.get_ip(payload)
    if ip_address:
      print(f"Query decoded with {decoder}")
      return ip_address
  return None