import network
import uasyncio as asyncio
import time
import ubinascii
import os
import socket
import json

# Import the NoMQ class (assuming it's in the same directory)
from NoMQ.nomq import NoMQ, SimpleLogger

# WiFi credentials (replace with your own)
WIFI_SSID = "SSID"
WIFI_PASSWORD = "PASS"

# Test configuration
TEST_CHANNEL = "test/channel"
TEST_MESSAGE = "Test message"
TEST_PORT = 8888
TIMEOUT = 15  # Timeout for receive tests in seconds
INVALID_IP = "255.255.255.255"
INVALID_PORT = 9999
INVALID_CHANNEL = ""

# Logger instance for test output
logger = SimpleLogger(level='DEBUG')

def connect_wifi():
    """Connect to WiFi network and return IP address."""
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if not wlan.isconnected():
        logger.info("Connecting to WiFi...")
        wlan.connect(WIFI_SSID, WIFI_PASSWORD)
        start_time = time.time()
        while not wlan.isconnected():
            if time.time() - start_time > 10:
                logger.error("WiFi connection timeout")
                return None
            time.sleep(1)
        logger.info(f"WiFi connected. IP: {wlan.ifconfig()[0]}")
    return wlan.ifconfig()[0]

async def test_initialization():
    """Test NoMQ initialization and socket setup."""
    logger.info("Testing NoMQ initialization...")
    nomq = None
    try:
        nomq = NoMQ(ip='0.0.0.0', port=TEST_PORT, log_level='DEBUG')
        if nomq.socket is not None and nomq.running and nomq.poller is not None:
            logger.info("Initialization test: PASSED")
            return True
        else:
            logger.error("Initialization test: FAILED")
            return False
    except Exception as e:
        logger.error(f"Initialization test failed: {e}")
        return False
    finally:
        if nomq:
            nomq.close()

async def test_invalid_encryption_key():
    """Test initialization with invalid encryption key."""
    logger.info("Testing invalid encryption key...")
    try:
        nomq = NoMQ(encryption_key=b"short_key", log_level='DEBUG')
        logger.error("Invalid encryption key test: FAILED (should have raised ValueError)")
        return False
    except ValueError as e:
        logger.info(f"Invalid encryption key test: PASSED (caught: {e})")
        return True
    except Exception as e:
        logger.error(f"Invalid encryption key test failed: {e}")
        return False

async def test_subscribe(device_ip):
    """Test subscribing to a channel."""
    logger.info("Testing subscribe...")
    nomq = None
    try:
        nomq = NoMQ(ip='0.0.0.0', port=TEST_PORT, log_level='DEBUG')
        await nomq.subscribe(TEST_CHANNEL, priority=5)
        if TEST_CHANNEL in nomq.channels and nomq.channels[TEST_CHANNEL]["priority"] == 5:
            logger.info("Subscribe test: PASSED")
            return True
        else:
            logger.error("Subscribe test: FAILED")
            return False
    except Exception as e:
        logger.error(f"Subscribe test failed: {e}")
        return False
    finally:
        if nomq:
            nomq.close()


async def test_publish(device_ip):
    """Test publishing a message."""
    logger.info("Testing publish...")
    nomq = None
    try:
        nomq = NoMQ(ip='0.0.0.0', port=TEST_PORT, log_level='DEBUG')
        await nomq.publish(TEST_CHANNEL, TEST_MESSAGE, qos=2, retain=True, ip=device_ip, port=TEST_PORT)
        if nomq.retained_messages.get(TEST_CHANNEL) or nomq.pending_messages:
            logger.info("Publish test: PASSED")
            return True
        else:
            logger.error("Publish test: FAILED")
            return False
    except Exception as e:
        logger.error(f"Publish test failed: {e}")
        return False
    finally:
        if nomq:
            nomq.close()



async def test_receive(device_ip):
    """Test receiving a published message."""
    logger.info("Testing receive...")
    nomq = None
    try:
        nomq = NoMQ(ip='0.0.0.0', port=TEST_PORT, log_level='DEBUG')
        await nomq.subscribe(TEST_CHANNEL, priority=5)
        await nomq.publish(TEST_CHANNEL, TEST_MESSAGE, qos=2, ip=device_ip, port=TEST_PORT)
        logger.debug(f"Published message to {device_ip}:{TEST_PORT} on {TEST_CHANNEL}")
        await asyncio.sleep(0.5)  # Ensure network delivery

        start_time = time.time()
        received = False
        while time.time() - start_time < TIMEOUT:
            events = nomq.poller.poll(200)
            if events:
                try:
                    data, addr = nomq.socket.recvfrom(nomq.BUFFER_SIZE)
                    logger.debug(f"Received packet from {addr}, length: {len(data)}")
                    packet = nomq.parse_packet(data)
                    if packet and packet.get("channel") == TEST_CHANNEL:
                        payload_data = json.loads(packet["payload"].decode('utf-8'))
                        logger.debug(f"Payload: {payload_data}")
                        if payload_data["message"] == TEST_MESSAGE:
                            logger.info("Receive test: PASSED")
                            received = True
                            break
                except Exception as e:
                    logger.error(f"Error receiving packet: {e}")
            await asyncio.sleep(0.01)
        
        if not received:
            logger.error("Receive test: FAILED")
        return received
    except Exception as e:
        logger.error(f"Receive test failed: {e}")
        return False
    finally:
        if nomq:
            nomq.close()

async def test_unsubscribe(device_ip):
    """Test unsubscribing from a channel."""
    logger.info("Testing unsubscribe...")
    nomq = None
    try:
        nomq = NoMQ(ip='0.0.0.0', port=TEST_PORT, log_level='DEBUG')
        await nomq.subscribe(TEST_CHANNEL, priority=5)
        await nomq.unsubscribe(TEST_CHANNEL)
        if TEST_CHANNEL not in nomq.channels:
            logger.info("Unsubscribe test: PASSED")
            return True
        else:
            logger.error("Unsubscribe test: FAILED")
            return False
    except Exception as e:
        logger.error(f"Unsubscribe test failed: {e}")
        return False
    finally:
        if nomq:
            nomq.close()

async def test_cleanup_expired_messages(device_ip):
    """Test cleanup of expired messages."""
    logger.info("Testing cleanup of expired messages...")
    nomq = None
    try:
        nomq = NoMQ(ip='0.0.0.0', port=TEST_PORT, log_level='DEBUG')
        await nomq.publish(TEST_CHANNEL, TEST_MESSAGE, qos=2, retain=True, ttl=1, ip=device_ip, port=TEST_PORT)
        await asyncio.sleep(2)  # Wait for TTL to expire
        await nomq.cleanup_expired_messages()
        if not nomq.retained_messages.get(TEST_CHANNEL) and not nomq.pending_messages:
            logger.info("Cleanup expired messages test: PASSED")
            return True
        else:
            logger.error("Cleanup expired messages test: FAILED")
            return False
    except Exception as e:
        logger.error(f"Cleanup expired messages test failed: {e}")
        return False
    finally:
        if nomq:
            nomq.close()


async def test_heartbeat(device_ip):
    """Test sending and receiving heartbeat response."""
    logger.info("Testing heartbeat...")
    nomq = None
    try:
        nomq = NoMQ(ip='0.0.0.0', port=TEST_PORT, log_level='DEBUG')
        packet = nomq.create_packet(
            packet_type=0x05,  # Heartbeat
            flags=0,
            channel_id=b'\x00' * 16,
            payload=b""
        )
        nomq.socket.sendto(packet, (device_ip, TEST_PORT))
        start_time = time.time()
        received = False
        while time.time() - start_time < TIMEOUT:
            events = nomq.poller.poll(200)
            if events:
                data, addr = nomq.socket.recvfrom(nomq.BUFFER_SIZE)
                packet = nomq.parse_packet(data)
                if packet and packet["type"] == 0x05:
                    logger.info("Heartbeat test: PASSED")
                    received = True
                    break
            await asyncio.sleep(0.01)
        if not received:
            logger.error("Heartbeat test: FAILED")
        return received
    except Exception as e:
        logger.error(f"Heartbeat test failed: {e}")
        return False
    finally:
        if nomq:
            nomq.close()

async def test_session_renewal():
    """Test session ID renewal."""
    logger.info("Testing session renewal...")
    nomq = None
    try:
        nomq = NoMQ(ip='0.0.0.0', port=TEST_PORT, log_level='DEBUG')
        nomq.session_timeout = 1  # Set short timeout for testing
        old_session_id = nomq.session_id
        await asyncio.sleep(2)  # Wait for session to expire
        nomq.renew_session()
        if nomq.session_id != old_session_id:
            logger.info("Session renewal test: PASSED")
            return True
        else:
            logger.error("Session renewal test: FAILED")
            return False
    except Exception as e:
        logger.error(f"Session renewal test failed: {e}")
        return False
    finally:
        if nomq:
            nomq.close()

async def run_tests():
    """Run all tests."""
    device_ip = connect_wifi()
    if not device_ip:
        logger.error("Aborting tests due to WiFi connection failure")
        return

    results = {
        "initialization": await test_initialization(),
        "invalid_encryption_key": await test_invalid_encryption_key(),
        "subscribe": await test_subscribe(device_ip),
        "publish": await test_publish(device_ip),
        "receive": await test_receive(device_ip),
        "unsubscribe": await test_unsubscribe(device_ip),
        "cleanup_expired_messages": await test_cleanup_expired_messages(device_ip),
        "heartbeat": await test_heartbeat(device_ip),
        "session_renewal": await test_session_renewal()
    }

    # Summary
    logger.info("\nTest Summary:")
    passed = 0
    total = len(results)
    for test_name, result in results.items():
        status = "PASSED" if result else "FAILED"
        logger.info(f"{test_name}: {status}")
        if result:
            passed += 1
    
    logger.info(f"\n{passed}/{total} tests passed")

if __name__ == "__main__":
    try:
        asyncio.run(run_tests())
    except KeyboardInterrupt:
        logger.info("Tests interrupted by user")
    except Exception as e:
        logger.error(f"Test execution failed: {e}")
