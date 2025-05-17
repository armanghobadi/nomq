import uasyncio as asyncio
from machine import unique_id
from NoMQ.nomq import NoMQ
import network
import uhashlib
import ubinascii
import json
import time


# Wi-Fi credentials
SSID = "your_wifi_ssid"
PASSWORD = "your_wifi_password"


async def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if not wlan.isconnected():
        print("Connecting to Wi-Fi...")
        wlan.connect(SSID, PASSWORD)
        while not wlan.isconnected():
            await asyncio.sleep(1)
    print("Wi-Fi connected:", wlan.ifconfig())


async def main():
    try:
        await connect_wifi()
        nomq = NoMQ('nomq_config.json', 'INFO', 5)  # Enable debug logging
        # Generate authentication signature
        signature = nomq.gen_signature()
        # Subscribe to channel with authentication
        print("Subscribing to test_channel...")
        await nomq.subscribe(
            "test_channel",
            priority=0,
            signature=signature,

        )
        

        # Listen for incoming messages
        print("Starting to listen for messages...")
        listener = await nomq.listen()
        while True:
            msg = listener.mssg()
            if msg:
                try:
                    # Try to parse the message as JSON
                    parsed_msg = json.loads(msg['message'])
                    print(f"Received JSON: {msg['channel']} -> {parsed_msg}")
                except json.JSONDecodeError:
                    print(f"Received non-JSON: {msg['channel']} -> {msg['message']}")
            await asyncio.sleep(0.1)
    
    except Exception as e:
        print(f"Error in main: {e}")
        raise

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("Program terminated by user")
except Exception as e:
    print(f"Unexpected error: {e}")


