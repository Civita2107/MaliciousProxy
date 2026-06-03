import os
import datetime
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class CertManager:
    def __init__(self, ca_cert_path='ca.crt', ca_key_path='ca.key'):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.certs_dir = 'certs/'
        self.ca_cert = None
        self.ca_key = None
        
        if not os.path.exists(self.certs_dir):
            os.makedirs(self.certs_dir)

    def _load_ca_material(self):
        if self.ca_cert is not None and self.ca_key is not None:
            return

        if not os.path.exists(self.ca_cert_path) or not os.path.exists(self.ca_key_path):
            raise FileNotFoundError('CA certificate or key is missing. Run generate_ca() first.')

        with open(self.ca_cert_path, 'rb') as cert_file:
            self.ca_cert = x509.load_pem_x509_certificate(cert_file.read())

        with open(self.ca_key_path, 'rb') as key_file:
            self.ca_key = serialization.load_pem_private_key(key_file.read(), password=None)

    def generate_ca(self):
        """Generates the Root CA with proper extensions for browser trust."""
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Malicious Proxy Root CA"),
        ])
        
        # Build the certificate using the freshly generated 'key' instance directly
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        ).add_extension(
            # For a Root CA, the authority identifier matches its own public key
            x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),
            critical=False,
        ).sign(key, hashes.SHA256())

        with open(self.ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(self.ca_key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        self.ca_cert = cert
        self.ca_key = key

    def get_cert(self, hostname):
        """Generates a site-specific certificate signed by your Root CA."""
        cert_path = os.path.join(self.certs_dir, f"{hostname}.crt")
        key_path = os.path.join(self.certs_dir, f"{hostname}.key")

        if os.path.exists(cert_path):
            return cert_path, key_path

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        self._load_ca_material()
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            self.ca_cert.subject
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
        ).not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(hostname)]),
            critical=False,
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        ).add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
            critical=False,
        ).sign(self.ca_key, hashes.SHA256())

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        return cert_path, key_path