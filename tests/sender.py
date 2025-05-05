import network
import uasyncio as asyncio
from machine import Pin
from nomq import NoMQ  # Assume NoMQ class is in nomq.py
import time

# Wi-Fi credentials
SSID = "your_wifi_ssid"
PASSWORD = "your_wifi_password"

# NoMQ configuration
CHANNEL = "test/channel"
RECEIVER_IP = "0.0.0.0"  # Replace with receiver's IP address
PORT = 8888
ENCRYPTION_KEY = b'32_byte_hmac_key' * 2  # 32 bytes
HMAC_KEY = b'32_byte_hmac_key' * 2  # 32 bytes

async def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if not wlan.isconnected():
        print("Connecting to Wi-Fi...")
        wlan.connect(SSID, PASSWORD)
        while not wlan.isconnected():
            await asyncio.sleep(1)
    print("Wi-Fi connected:", wlan.ifconfig())

async def sender_task():
    # Initialize NoMQ
    nomq = NoMQ(
        ip='0.0.0.0',
        port=PORT,
        encryption_key=ENCRYPTION_KEY,
        hmac_key=HMAC_KEY,
        log_level='DEBUG'
    )
    
    try:
        # Publish messages periodically
        for i in range(5):  # Send 5 test messages
            message = f"Hello from sender, message #{i+1}"
            print(f"Sending: {message}")
            await nomq.publish(
                channel=CHANNEL,
                message=message,
                qos=2,  # Reliable delivery
                retain=True,  # Retain for new subscribers
                ttl=3600,  # 1 hour TTL
                ip=RECEIVER_IP,
                port=PORT
            )
            await asyncio.sleep(5)  # Wait 5 seconds between messages
    finally:
        nomq.close()

async def main():
    await connect_wifi()
    await sender_task()

# Run the sender
loop = asyncio.get_event_loop()
loop.run_until_complete(main())
