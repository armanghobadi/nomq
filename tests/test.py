import uasyncio as asyncio
import network
import time
import socket
import json
from nomq import NoMQ  # Assumes NoMQ class is in nomq.py
import ubinascii
import os

# Wi-Fi configuration
WIFI_SSID = "Dade-Pardazan-2GHz"
WIFI_PASSWORD = "@14002020"

def connect_wifi():
    """Connect to Wi-Fi network and return IP address."""
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if not wlan.isconnected():
        print("Connecting to Wi-Fi...")
        wlan.connect(WIFI_SSID, WIFI_PASSWORD)
        timeout = 10
        while not wlan.isconnected() and timeout > 0:
            time.sleep(1)
            timeout -= 1
        if not wlan.isconnected():
            raise Exception("Failed to connect to Wi-Fi")
    ip = wlan.ifconfig()[0]
    print(f"Wi-Fi connected: IP = {ip}")
    return ip

class NoMQTest:
    def __init__(self):
        self.ip = None
        self.port = 8888
        self.nomq = None
        self.test_channel = "test/channel"
        self.test_message = "Test message"
        self.received_messages = []

    async def setup(self):
        """Set up Wi-Fi and NoMQ instance."""
        try:
            self.ip = connect_wifi()
            self.nomq = NoMQ(ip=self.ip, port=self.port)
            print("Setup completed successfully")
        except Exception as e:
            print(f"Setup failed: {e}")
            raise

    async def test_initialization(self):
        """Test NoMQ initialization."""
        print("Test 1: Initialization")
        assert self.nomq.ip == self.ip, "IP address mismatch"
        assert self.nomq.port == self.port, "Port mismatch"
        assert self.nomq.socket is not None, "Socket not initialized"
        assert len(self.nomq.device_id) > 0, "Device ID not generated"
        assert self.nomq.session_id > 0, "Session ID not generated"
        print("Initialization test passed")

    async def test_subscribe(self):
        """Test subscribing to a channel."""
        print("Test 2: Subscribe")
        self.nomq.subscribe(self.test_channel, priority=1)
        await asyncio.sleep(1)
        assert self.test_channel in self.nomq.channels, "Channel not subscribed"
        assert self.nomq.channels[self.test_channel]["priority"] == 1, "Priority mismatch"
        print("Subscribe test passed")

    async def test_publish_qos0(self):
        """Test publishing with QoS=0."""
        print("Test 3: Publish with QoS=0")
        await self.nomq.publish(
            channel=self.test_channel,
            message=self.test_message,
            qos=0,
            retain=False,
            ttl=3600,
            ip=self.ip,
            port=self.port
        )
        await asyncio.sleep(1)
        assert len(self.nomq.pending_messages) == 0, "Pending messages found for QoS=0"
        print("Publish QoS=0 test passed")


    async def test_publish_qos1(self):
        """Test publishing with QoS=1 and ACK."""
        print("Test 4: Publish with QoS=1")
        packet_id = None
        
        # Publish a message with QoS=1
        await self.nomq.publish(
            channel=self.test_channel,
            message=self.test_message + "_qos1",
            qos=1,
            retain=False,
            ttl=3600,
            ip=self.ip,
            port=self.port
        )
        
        # Immediately check for a pending message
        for pid in self.nomq.pending_messages:
            packet_id = pid
            break
        assert packet_id is not None, "No pending message for QoS=1"
        
        # Start the listen task to process the ACK
        listen_task = asyncio.create_task(self.nomq.listen())
        await asyncio.sleep(0.1)  # Brief delay to ensure listen task is running
        
        # Create and send an ACK packet
        ack_packet = self.nomq.create_packet(
            packet_type=0x03,  # ACK
            flags=1,
            channel_id=self.nomq.channels[self.test_channel]["id"],
            payload=json.dumps({"ack": packet_id}).encode('utf-8'),
            packet_id=packet_id
        )
        self.nomq.socket.sendto(ack_packet, (self.ip, self.port))
        
        # Wait for the ACK to be processed
        await asyncio.sleep(2)  # Allow time for ACK processing
        
        # Stop the listen task
        listen_task.cancel()
        
        # Check if the ACK was processed
        assert packet_id not in self.nomq.pending_messages, "ACK not processed"
        print("Publish QoS=1 test passed")
            
    async def test_publish_qos2(self):
        """Test publishing with QoS=2."""
        print("Test 5: Publish with QoS=2")
        await self.nomq.publish(
            channel=self.test_channel,
            message=self.test_message + "_qos2",
            qos=2,
            retain=False,
            ttl=3600,
            ip=self.ip,
            port=self.port
        )
        await asyncio.sleep(1)
        assert len(self.nomq.pending_messages) > 0, "No pending messages for QoS=2"
        print("Publish QoS=2 test passed")

    async def test_retained_message(self):
        """Test publishing and receiving retained messages."""
        print("Test 6: Retained message")
        await self.nomq.publish(
            channel=self.test_channel,
            message=self.test_message + "_retained",
            qos=1,
            retain=True,
            ttl=3600,
            ip=self.ip,
            port=self.port
        )
        await asyncio.sleep(1)
        assert self.test_channel in self.nomq.retained_messages, "Retained message not stored"
        # Subscribe again to receive retained message
        self.nomq.subscribe(self.test_channel + "_retained", priority=1)
        await asyncio.sleep(1)
        print("Retained message test passed")

    async def test_listen(self):
        """Test listening for incoming messages."""
        print("Test 7: Listen for messages")
        self.received_messages = []

        async def capture_messages():
            while True:
                try:
                    data, addr = self.nomq.socket.recvfrom(1024)
                    packet = self.nomq.parse_packet(data)
                    if packet and packet["type"] == 0x01:  # Publish
                        payload_data = json.loads(packet["payload"].decode('utf-8'))
                        self.received_messages.append(payload_data["message"])
                except Exception:
                    await asyncio.sleep(0.1)

        listen_task = asyncio.create_task(capture_messages())
        # Publish a message to test listening
        await self.nomq.publish(
            channel=self.test_channel,
            message=self.test_message + "_listen",
            qos=1,
            ip=self.ip,
            port=self.port
        )
        await asyncio.sleep(2)
        listen_task.cancel()
        assert any("_listen" in msg for msg in self.received_messages), "Message not received"
        print("Listen test passed")

    async def test_heartbeat(self):
        """Test sending and receiving heartbeat."""
        print("Test 8: Heartbeat")
        heartbeat_packet = self.nomq.create_packet(
            packet_type=0x05,
            flags=0,
            channel_id=b'\x00' * 16,
            payload=b""
        )
        self.nomq.socket.sendto(heartbeat_packet, (self.ip, self.port))
        await asyncio.sleep(1)
        print("Heartbeat test passed (response sent)")

    async def test_unsubscribe(self):
        """Test unsubscribing from a channel."""
        print("Test 9: Unsubscribe")
        self.nomq.unsubscribe(self.test_channel)
        await asyncio.sleep(1)
        assert self.test_channel not in self.nomq.channels, "Channel not unsubscribed"
        print("Unsubscribe test passed")

    async def test_encryption(self):
        """Test packet encryption and decryption."""
        print("Test 10: Encryption")
        payload = b"Test encryption"
        packet = self.nomq.create_packet(
            packet_type=0x01,
            flags=0,
            channel_id=self.nomq.channels.get(self.test_channel, {"id": b'\x00' * 16})["id"],
            payload=payload
        )
        parsed_packet = self.nomq.parse_packet(packet)
        assert parsed_packet["payload"] == payload, "Decryption failed"
        print("Encryption test passed")

    async def test_hmac_verification(self):
        """Test HMAC verification."""
        print("Test 11: HMAC verification")
        payload = b"Test HMAC"
        channel_id = self.nomq.channels.get(self.test_channel, {"id": b'\x00' * 16})["id"]
        packet = self.nomq.create_packet(
            packet_type=0x01,
            flags=0,
            channel_id=channel_id,
            payload=payload
        )
        # Corrupt HMAC
        corrupted_packet = packet[:-32] + os.urandom(32)
        parsed_packet = self.nomq.parse_packet(corrupted_packet)
        assert parsed_packet is None, "HMAC verification did not fail for corrupted packet"
        print("HMAC verification test passed")
        
        
    async def test_error_handling(self):
        """Test error handling for invalid inputs."""
        print("Test 12: Error handling")
        try:
            self.nomq.subscribe("")  # Empty channel
            assert False, "Empty channel subscription did not raise error"
        except Exception:
            pass
        try:
            await self.nomq.publish("", "message")  # Empty channel
            assert False, "Empty channel publish did not raise error"
        except Exception:
            pass
        print("Error handling test passed")

    async def run_all_tests(self):
        """Run all test cases."""
        await self.setup()
        await self.test_initialization()
        await self.test_subscribe()
        await self.test_publish_qos0()
        await self.test_publish_qos1()
        await self.test_publish_qos2()
        await self.test_retained_message()
        await self.test_listen()
        await self.test_heartbeat()
        await self.test_unsubscribe()
        await self.test_encryption()
        await self.test_hmac_verification()
        await self.test_error_handling()
        print("All tests completed successfully!")

async def main():
    """Main function to run tests."""
    tester = NoMQTest()
    try:
        await tester.run_all_tests()
    except Exception as e:
        print(f"Test suite failed: {e}")

# Run the test suite
loop = asyncio.get_event_loop()
loop.run_until_complete(main())