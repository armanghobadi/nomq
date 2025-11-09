import uasyncio as asyncio
from machine import unique_id
from nomq import NoMQ
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
        
        # Publish a JSON message
        message_json = {
                "device_id": ubinascii.hexlify(unique_id()).decode(),
                "timestamp": int(time.time()),
                "type": "advanced_environmental_sensor",
                "data": {
                    "temperature": {
                        "value": 25.3,
                        "unit": "Celsius",
                        "accuracy": 0.5
                    },
                    "humidity": {
                        "value": 60.5,
                        "unit": "Percent",
                        "accuracy": 2.0
                    },
                    "pressure": {
                        "value": 1013.2,
                        "unit": "hPa",
                        "accuracy": 1.0
                    },
                    "light_level": {
                        "value": 450,
                        "unit": "Lux",
                        "accuracy": 10
                    },
                    "co2_level": {
                        "value": 410,
                        "unit": "ppm",
                        "accuracy": 50
                    },
                    "noise_level": {
                        "value": 55,
                        "unit": "dB",
                        "accuracy": 3
                    },
                    "battery": {
                        "level": 85,
                        "unit": "Percent",
                        "voltage": 3.7,
                        "charging_status": "not_charging"
                    },
                    "power_usage": {
                        "value": 0.12,
                        "unit": "Watts",
                        "average_over": "1h"
                    }
                },
                "location": {
                    "latitude": 35.6895,
                    "longitude": 51.3890,
                    "altitude": 1185,
                    "geofence_id": "tehran_zone_1",
                    "indoor": False
                },
                "network": {
                    "connection_type": "WiFi",
                    "signal_strength": -65,
                    "unit": "dBm",
                    "mac_address": "24:6F:28:12:34:56",
                    "ip_address": "192.168.1.105",
                    "connected_ap": "IoT_Gateway_01"
                },
               

            }
        
        
        message = json.dumps(message_json)  # Serialize to string
          
        await nomq.publish(
            "test_channel",
            message,
            qos=2,
            retain=True,
            ip="255.255.255.255", #or Device IP Address
            port=8888,
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

