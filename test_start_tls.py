import asyncio
import ssl

async def handle_client(reader, writer):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    try:
        await writer.start_tls(ctx)
    except Exception as e:
        print(f"Exception: {repr(e)}")

async def main():
    server = await asyncio.start_server(handle_client, '127.0.0.1', 8888)
    asyncio.create_task(server.serve_forever())
    reader, writer = await asyncio.open_connection('127.0.0.1', 8888)
    await asyncio.sleep(0.5)

asyncio.run(main())
