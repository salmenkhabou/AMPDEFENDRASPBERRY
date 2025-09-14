#!/usr/bin/env python3
import asyncio, websockets, datetime, os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGFILE = os.path.join(BASE_DIR, "ampdefend.log")

def log_event(msg):
    print(msg)
    with open(LOGFILE, "a") as f:
        f.write(f"{datetime.datetime.now()} - {msg}\n")

async def handler(websocket, path):
    attacker_ip = websocket.remote_address[0]
    log_event(f"New OCPP connection from {attacker_ip}")
    try:
        async for message in websocket:
            log_event(f"Received from {attacker_ip}: {message}")
            await websocket.send('{"status":"Accepted","currentTime":"2025-01-01T00:00:00Z"}')
    except Exception as e:
        log_event(f"Error with {attacker_ip}: {e}")

async def main():
    log_event("Fake EV Charger Honeypot listening on port 8080...")
    async with websockets.serve(handler, "0.0.0.0", 8080):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())

