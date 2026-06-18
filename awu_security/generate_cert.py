"""
generate_cert.py — توليد شهادة SSL للـ Security API
شغّله مرة واحدة فقط: py generate_cert.py
"""
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import DNSName, IPAddress
import ipaddress
import datetime
import os

KEY_FILE  = "ssl/api_key.pem"
CERT_FILE = "ssl/api_cert.pem"

os.makedirs("ssl", exist_ok=True)

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME,             "JO"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME,        "AWU Shopping"),
    x509.NameAttribute(NameOID.COMMON_NAME,              "127.0.0.1"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
    .add_extension(
        x509.SubjectAlternativeName([
            DNSName("localhost"),
            IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]),
        critical=False,
    )
    .sign(key, hashes.SHA256())
)

with open(KEY_FILE, "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))

with open(CERT_FILE, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("[+] SSL certificate generated:")
print(f"    Key:  {KEY_FILE}")
print(f"    Cert: {CERT_FILE}")
print("[+] Valid for 10 years")