from scapy.all import sniff, Raw
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
from scapy.sessions import TCPSession
from request import Request, DBController
from classifier import ThreatClassifier
from argparse import ArgumentParser
import urllib.parse

# Define command-line arguments
parser = ArgumentParser()
parser.add_argument('--port', type=int, default=80, help='Port number to sniff HTTP traffic on')

args = parser.parse_args()

# Initialize DB controller and ThreatClassifier
db = DBController()
threat_clf = ThreatClassifier()

header_fields = [...]

def get_header(packet):
    headers = {}
    for field in header_fields:
        f = getattr(packet[HTTPRequest], field)
        if f is not None and f != 'None':
            headers[field] = f.decode()

    return headers

def sniffing_function(packet):
    if packet.haslayer(HTTPRequest):
        req = Request()

        if packet.haslayer(IP):
            req.origin = packet[IP].src
        else:
            req.origin = 'localhost'

        req.host = urllib.parse.unquote(packet[HTTPRequest].Host.decode())
        req.request = urllib.parse.unquote(packet[HTTPRequest].Path.decode())
        req.method = packet[HTTPRequest].Method.decode()
        req.headers = get_header(packet)
        req.threat_type = 'None'

        if packet.haslayer(Raw):
            req.body = packet[Raw].load.decode()

        threat_clf.classify_request(req)
        db.save(req)

# Start sniffing
pkgs = sniff(prn=sniffing_function, filter=f'tcp dst port {args.port}', session=TCPSession)

# Close DB connection
db.close()
