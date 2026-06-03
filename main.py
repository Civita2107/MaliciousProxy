import asyncio
import sys
from core.interceptor import Interceptor
from core.cert_manager import CertManager

async def main():
    print("--- Malicious Proxy ---")
    
    cert_manager = CertManager()
    interceptor = Interceptor(cert_manager)
    
    listen_host = '127.0.0.1'
    listen_port = 8080
    
    server = await asyncio.start_server(
        interceptor.handle_client, 
        listen_host, 
        listen_port
    )
    
    print(f"[*] Interceptor listening on {listen_host}:{listen_port}...")
    print("[*] Ensure your browser proxy is set to 127.0.0.1:8080")
    print("[!] Press Ctrl+C to stop the proxy safely.")

    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Shutting down proxy...")
        sys.exit(0)