# Script to initialize the CA and generate the necessary certificate files
from core.cert_manager import CertManager

def initialize_ca():
    print("[*] Initializing Root Certificate Authority...")
    manager = CertManager()
    manager.generate_ca()
    print("[+] CA generated successfully: ca.crt and ca.key are ready.")

if __name__ == "__main__":
    initialize_ca()