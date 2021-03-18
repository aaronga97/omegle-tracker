# BOT DE OMEGLE: Te dice la ubicacion de la otra persona
import pyshark 
import requests
from pathlib import Path


def agarra_texto(path: Path):
    with open(path.absolute(), 'r') as f:
        return f.read().strip()

def genera_ips_privadas():
    ips_privadas = ["192.168.", "10."]
    ips_privadas.extend([f"172.{x}" for x in range(16, 32)])
    return ips_privadas

def censurar_ip(ip):
    octetos = ip.split('.')
    return f"{'.'.join(octetos[0:2])}.XXX.XXX" if CENSURA else ip

def impr(data):
    if data.get('bogon'):
        return
    print(f"{censurar_ip(data.get('ip'))}: {data.get('city')}, {data.get('region')}, {data.get('country')}")

def es_privada(ip_destino):
  for ip_priv in IPS_PRIVADAS:
          if ip_destino.startswith(ip_priv):
              return True

def obtener_ubicacion(ip):
    url = f"https://www.ipinfo.io/{ip}?token={token}"
    res = requests.get(url)
    return res.json()

def procesar_pkt(pkt):
    if "stun" not in pkt or "ip" not in pkt:
       return
    ip_destino = pkt.ip.dst
    if ip_destino in IPS_VISTAS or es_privada(ip_destino):
        return
    IPS_VISTAS.add(ip_destino)
    metadata = obtener_ubicacion(ip_destino)
    impr(metadata)


if __name__ == "__main__":
    CENSURA = True 
    IPS_VISTAS = set()
    IPS_PRIVADAS = genera_ips_privadas()

    token = agarra_texto(Path('./token.txt'))
    adaptador = input("(W)ifi o (E)thernet? ")
    adaptador = "Ethernet" if adaptador.lower() == 'e' else "Wi-Fi"

    print(f"Capturando en {adaptador}...")
    capture = pyshark.LiveCapture(interface=adaptador)
    capture.apply_on_packets(callback=procesar_pkt, packet_count=100000000)