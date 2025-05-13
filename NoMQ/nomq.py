import socket
import uhashlib
import hashlib
import json
import time
import uasyncio as asyncio
from machine import unique_id
import network
from ucryptolib import aes
import ubinascii
import os
import select
from logger import SimpleLogger

class NoMQ:
    """
    NoMQ (No Message Queue) is a lightweight, secure, and scalable messaging protocol designed for Internet of Things (IoT) applications.
    Built for resource-constrained devices like ESP32 and ESP8266 running MicroPython, NoMQ provides enterprise-grade security,
    reliable message delivery, and real-time communication without the overhead of traditional message brokers.
    
    """
    MAX_RETAINED_MESSAGES = 10  # Max retained messages per channel
    MAX_PENDING_MESSAGES = 100  # Max pending messages
    DEFAULT_TTL = 3600  # Default TTL in seconds
    BUFFER_SIZE = 512  # Buffer size for larger messages

    def __init__(self, ip='0.0.0.0', port=8888, encryption_key=None, hmac_key=None, 
                 use_ipv6=False, log_level='INFO', timeout=5):
        """
        Initialize NoMQ protocol for MicroPython.

        Args:
            ip (str): IP address to bind (default: '0.0.0.0').
            port (int): Port to bind (default: 8888).
            encryption_key (bytes): 32-byte AES encryption key (default: generated).
            hmac_key (bytes): HMAC key (default: generated).
            use_ipv6 (bool): Enable IPv6 support (default: False).
            log_level (str): Logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR').
            timeout (int): Socket timeout in seconds (default: 5).
        """
        self.logger = SimpleLogger(level=log_level)
        self.ip = ip
        self.port = port
        self.use_ipv6 = use_ipv6
        self.timeout = timeout
        self.socket = None
        self.device_id = self.get_device_id()
        self.session_id = self.generate_session_id()
        self.session_start = time.time()
        self.channels = {}  # Subscribed channels: {channel: {id, priority}}
        self.retained_messages = {}  # Retained messages per channel
        self.pending_messages = {}  # Messages awaiting acknowledgment
        self.encryption_key = encryption_key or os.urandom(32)
        self.hmac_key = hmac_key or os.urandom(32)
        if not encryption_key or not hmac_key:
            self.logger.warning("Using generated encryption/HMAC keys for security")
        if len(self.encryption_key) != 32:
            raise ValueError("Encryption key must be 32 bytes")
        self.salt = b'nomq_salt_2025'
        self.protocol_version = 0x01
        self.magic_number = 0xF1E2
        self.session_timeout = 300
        self.max_retries = 5
        self.heartbeat_interval = 30
        self.running = False
        self.poller = None
        self.initialize_socket()

    def initialize_socket(self):
        """
        Initialize UDP socket with IPv4 or IPv6 support and timeout.
        """
        try:
            if self.socket:
                self.socket.close()
        except Exception as e:
            self.logger.error(f"Error closing existing socket: {e}")

        family = socket.AF_INET6 if self.use_ipv6 else socket.AF_INET
        self.socket = socket.socket(family, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.settimeout(self.timeout)

        try:
            bind_addr = (self.ip, self.port, 0, 0) if self.use_ipv6 else (self.ip, self.port)
            self.socket.bind(bind_addr)
            self.poller = select.poll()
            self.poller.register(self.socket, select.POLLIN)
            self.running = True
            self.logger.info(f"NoMQ initialized on {self.ip}:{self.port} (IPv{'6' if self.use_ipv6 else '4'})")
        except OSError as e:
            self.logger.error(f"Socket bind failed: {e}")
            self.close()
            raise

    def reinitialize_socket(self):
        """
        Reinitialize socket in case of failure.
        """
        self.logger.warning("Reinitializing socket...")
        self.initialize_socket()

    def get_device_id(self):
        """
        Generate a unique device ID based on hardware MAC address.
        """
        mac = unique_id()
        return hashlib.sha256(mac).digest().hex()

    def generate_session_id(self):
        """
        Generate a unique session ID.
        """
        return int.from_bytes(os.urandom(8), 'big')

    def renew_session(self):
        """
        Renew session ID if session timeout is reached.
        """
        if time.time() - self.session_start > self.session_timeout:
            self.session_id = self.generate_session_id()
            self.session_start = time.time()
            self.logger.info("Session ID renewed")

    def generate_packet_id(self):
        """
        Generate a unique packet ID.
        """
        return int.from_bytes(os.urandom(4), 'big')

    def set_address(self, ip, port):
        """
        Update IP and port, and rebind the socket.
        """
        self.ip = ip
        self.port = port
        self.initialize_socket()
        self.logger.info(f"Address updated to {ip}:{port}")

    async def subscribe(self, channel, priority=0):
        """
        Subscribe to a channel with specified priority.

        Args:
            channel (str): Channel name.
            priority (int): Priority level (0-15).
        """
        try:
            if not isinstance(channel, str) or not channel:
                raise ValueError("Channel must be a non-empty string")
            channel_id = hashlib.sha256(channel.encode()).digest()[:16]
            if channel not in self.channels:
                self.channels[channel] = {"id": channel_id, "priority": min(max(priority, 0), 15)}
                self.logger.info(f"Subscribed to {channel} with priority {priority}")
                packet = self.create_packet(
                    packet_type=0x02,  # Subscribe
                    flags=priority & 0x0F,
                    channel_id=channel_id,
                    payload=channel.encode()
                )
                if packet:
                    self.socket.sendto(packet, (self.ip, self.port))
                    if channel in self.retained_messages:
                        for msg in self.retained_messages[channel]:
                            self.socket.sendto(msg, (self.ip, self.port))
                            self.logger.info(f"Sent retained message to {channel}")
                else:
                    self.logger.error("Failed to create subscribe packet")
        except Exception as e:
            self.logger.error(f"Subscribe failed: {e}")

    async def publish(self, channel, message, qos=2, retain=False, ttl=DEFAULT_TTL, priority=0, ip='0.0.0.0', port=8888):
        """
        Publish a message to a channel with enhanced reliability.

        Args:
            channel (str): Channel name.
            message (str): Message content.
            qos (int): Quality of Service (0-3).
            retain (bool): Retain message for new subscribers.
            ttl (int): Time-to-live in seconds.
            priority (int): Priority level (0-15).
            ip (str): Destination IP.
            port (int): Destination port.
        """
        try:
            if not isinstance(message, str):
                raise ValueError("Message must be a string")
            self.renew_session()
            channel_id = hashlib.sha256(channel.encode()).digest()[:16]
            packet_id = self.generate_packet_id()
            flags = (
                (qos & 0x03) |  # QoS (bits 0-1)
                (0x04 if retain else 0x00) |  # Retain (bit 2)
                ((min(max(priority, 0), 15) & 0x0F) << 4)  # Priority (bits 4-7)
            )
            
            message_data = {
                "device_id": self.device_id,
                "message": message,
                "timestamp": int(time.time())
            }
            payload = json.dumps(message_data).encode('utf-8')
            
            packet = self.create_packet(
                packet_type=0x01,  # Publish
                flags=flags,
                channel_id=channel_id,
                payload=payload,
                packet_id=packet_id,
                ttl=ttl
            )
            if not packet:
                self.logger.error("Failed to create publish packet")
                return
            
            retries = self.max_retries
            while retries > 0:
                try:
                    addr = (ip, port, 0, 0) if self.use_ipv6 else (ip, port)
                    self.socket.sendto(packet, addr)
                    self.logger.info(f"Published to {channel}: {message}")
                    
                    if retain:
                        if channel not in self.retained_messages:
                            self.retained_messages[channel] = []
                        self.retained_messages[channel].append(packet)
                        if len(self.retained_messages[channel]) > self.MAX_RETAINED_MESSAGES:
                            self.retained_messages[channel].pop(0)
                    
                    if qos > 0:
                        if len(self.pending_messages) < self.MAX_PENDING_MESSAGES:
                            self.pending_messages[packet_id] = {
                                "packet": packet,
                                "channel": channel,
                                "ip": ip,
                                "port": port,
                                "retries": self.max_retries,
                                "timestamp": time.time(),
                                "ttl": ttl
                            }
                        else:
                            self.logger.warning("Pending messages limit reached, dropping message")
                    break
                except OSError as e:
                    self.logger.error(f"Error sending packet: {e}")
                    retries -= 1
                    await asyncio.sleep(2 ** (self.max_retries - retries))
            
            if retries == 0:
                self.logger.error(f"Failed to send packet after {self.max_retries} retries")
        except Exception as e:
            self.logger.error(f"Publish failed: {e}")

    async def listen(self):
        """
        Listen for incoming packets asynchronously using select.
        """
        self.running = True
        while self.running:
            try:
                events = self.poller.poll(100)  # Wait for 100ms
                if events:
                    data, addr = self.socket.recvfrom(self.BUFFER_SIZE)
                    packet = self.parse_packet(data)
                    if not packet:
                        continue
                    
                    channel = packet.get("channel")
                    if channel not in self.channels:
                        self.logger.warning(f"Received packet on unsubscribed channel: {channel}")
                        continue
                    
                    if packet["type"] == 0x01:  # Publish
                        try:
                            payload_data = json.loads(packet["payload"].decode('utf-8'))
                            self.logger.info(f"Received message on {channel}: {payload_data['message']}")
                            qos = packet["flags"] & 0x03
                            if qos in (1, 2, 3):
                                await self.send_ack(packet, addr, qos=qos)
                        except Exception as e:
                            self.logger.error(f"Error processing publish packet: {e}")
                    
                    elif packet["type"] == 0x03:  # Ack
                        if packet["packet_id"] in self.pending_messages:
                            del self.pending_messages[packet["packet_id"]]
                            self.logger.info(f"Received ACK for packet ID {packet['packet_id']}")
                    
                    elif packet["type"] == 0x05:  # Heartbeat
                        await self.send_heartbeat_response(addr)
                
                await self.cleanup_expired_messages()
            
            except OSError as e:
                self.logger.error(f"Socket error: {e}")
                self.reinitialize_socket()
            except Exception as e:
                self.logger.error(f"Error in listen: {e}")
            await asyncio.sleep(0.01)

    def create_packet(self, packet_type, flags, channel_id, payload, packet_id=None, ttl=DEFAULT_TTL):
        """
        Create a packet with AES-256-CBC encryption and HMAC.

        Packet structure:
        - Control Header (20 bytes): magic(2), version(1), type(1), flags(2), packet_id(4), session_id(8), ttl(2)
        - Security Header (24 bytes): iv(16), timestamp(8)
        - Data Header (20 bytes): channel_id(16), payload_length(4)
        - Payload (variable): encrypted payload (AES-256-CBC with PKCS#7 padding)
        - HMAC (32 bytes): SHA-256 HMAC
        """
        try:
            if packet_id is None:
                packet_id = self.generate_packet_id()
            
            iv = os.urandom(16)
            timestamp = int(time.time())
            
            # PKCS#7 padding
            pad_length = 16 - (len(payload) % 16)
            padded_payload = payload + bytes([pad_length] * pad_length)
            
            # Encrypt payload
            cipher = aes(self.encryption_key, 2, iv)
            encrypted_payload = iv + cipher.encrypt(padded_payload)
            
            # Create headers
            control_header = (
                self.magic_number.to_bytes(2, 'big') +
                self.protocol_version.to_bytes(1, 'big') +
                packet_type.to_bytes(1, 'big') +
                flags.to_bytes(2, 'big') +
                packet_id.to_bytes(4, 'big') +
                self.session_id.to_bytes(8, 'big') +
                ttl.to_bytes(2, 'big')
            )
            security_header = (
                iv +
                timestamp.to_bytes(8, 'big')
            )
            data_header = (
                channel_id +
                len(encrypted_payload).to_bytes(4, 'big')
            )
            
            # Calculate HMAC
            hmac_obj = uhashlib.sha256(control_header + security_header + data_header + encrypted_payload + self.hmac_key)
            hmac = hmac_obj.digest()
            
            return control_header + security_header + data_header + encrypted_payload + hmac
        except Exception as e:
            self.logger.error(f"Error creating packet: {e}")
            return None

    def parse_packet(self, data):
        """
        Parse and validate a received packet with enhanced security checks.
        """
        try:
            if len(data) < 36 + 32:
                self.logger.warning("Packet too short")
                return None
            
            # Parse control header
            magic = int.from_bytes(data[:2], 'big')
            if magic != self.magic_number:
                self.logger.warning("Invalid magic number")
                return None
            
            version = data[2]
            if version != self.protocol_version:
                self.logger.warning("Unsupported protocol version")
                return None
            
            packet_type = data[3]
            flags = int.from_bytes(data[4:6], 'big')
            packet_id = int.from_bytes(data[6:10], 'big')
            session_id = int.from_bytes(data[10:18], 'big')
            ttl = int.from_bytes(data[18:20], 'big')
            
            # Parse security header
            iv = data[20:36]
            timestamp = int.from_bytes(data[36:44], 'big')
            if abs(time.time() - timestamp) > 60:
                self.logger.warning("Possible replay attack detected")
                return None
            
            # Parse data header
            channel_id = data[44:60]
            payload_length = int.from_bytes(data[60:64], 'big')
            if len(data) < 64 + payload_length + 32:
                self.logger.warning("Invalid packet length")
                return None
            encrypted_payload = data[64:64 + payload_length]
            received_hmac = data[64 + payload_length:]
            
            # Verify HMAC
            hmac_obj = uhashlib.sha256(data[:64 + payload_length] + self.hmac_key)
            calculated_hmac = hmac_obj.digest()
            if calculated_hmac != received_hmac:
                self.logger.warning("HMAC verification failed")
                return None
            
            # Decrypt payload
            iv = encrypted_payload[:16]
            cipher = aes(self.encryption_key, 2, iv)
            decrypted_payload = cipher.decrypt(encrypted_payload[16:])
            pad_length = decrypted_payload[-1]
            if not (1 <= pad_length <= 16 and all(decrypted_payload[-i] == pad_length for i in range(1, pad_length + 1))):
                self.logger.warning("Invalid padding")
                return None
            payload = decrypted_payload[:-pad_length]
            
            # Find channel
            channel = None
            for ch, ch_info in self.channels.items():
                if ch_info["id"] == channel_id:
                    channel = ch
                    break
            
            return {
                "type": packet_type,
                "flags": flags,
                "packet_id": packet_id,
                "session_id": session_id,
                "ttl": ttl,
                "channel": channel,
                "timestamp": timestamp,
                "payload": payload
            }
        
        except Exception as e:
            self.logger.error(f"Error parsing packet: {e}")
            return None

    async def send_ack(self, packet, addr, qos):
        """
        Send an acknowledgment packet.
        """
        try:
            channel_id = hashlib.sha256(packet["channel"].encode()).digest()[:16]
            ack_packet = self.create_packet(
                packet_type=0x03,  # Ack
                flags=qos & 0x03,
                channel_id=channel_id,
                payload=json.dumps({"ack": packet["packet_id"]}).encode('utf-8'),
                packet_id=packet["packet_id"]
            )
            if ack_packet:
                self.socket.sendto(ack_packet, addr)
                self.logger.info(f"Sent ACK for packet ID {packet['packet_id']} with QoS {qos}")
        except Exception as e:
            self.logger.error(f"Error sending ACK: {e}")

    async def send_heartbeat_response(self, addr):
        """
        Send a heartbeat response.
        """
        try:
            packet = self.create_packet(
                packet_type=0x05,  # Heartbeat
                flags=0,
                channel_id=b'\x00' * 16,
                payload=b""
            )
            if packet:
                self.socket.sendto(packet, addr)
                self.logger.info(f"Sent heartbeat response to {addr}")
        except Exception as e:
            self.logger.error(f"Error sending heartbeat: {e}")

    async def unsubscribe(self, channel):
        """
        Unsubscribe from a channel.
        """
        try:
            if channel in self.channels:
                channel_id = self.channels[channel]["id"]
                packet = self.create_packet(
                    packet_type=0x04,  # Unsubscribe
                    flags=0,
                    channel_id=channel_id,
                    payload=channel.encode()
                )
                if packet:
                    self.socket.sendto(packet, (self.ip, self.port))
                    del self.channels[channel]
                    self.logger.info(f"Unsubscribed from {channel}")
            else:
                self.logger.warning(f"Channel {channel} not subscribed")
        except Exception as e:
            self.logger.error(f"Error unsubscribing: {e}")

    async def cleanup_expired_messages(self):
        """
        Remove expired retained and pending messages based on TTL.
        """
        current_time = time.time()
        
        # Clean up retained messages
        for channel in list(self.retained_messages.keys()):
            self.retained_messages[channel] = [
                msg for msg in self.retained_messages[channel]
                if self.parse_packet(msg).get("timestamp", 0) + self.parse_packet(msg).get("ttl", self.DEFAULT_TTL) > current_time
            ]
            if not self.retained_messages[channel]:
                del self.retained_messages[channel]
        
        # Clean up pending messages
        for packet_id in list(self.pending_messages.keys()):
            msg = self.pending_messages[packet_id]
            if msg["timestamp"] + msg["ttl"] < current_time:
                del self.pending_messages[packet_id]
                self.logger.info(f"Removed expired pending message ID {packet_id}")

    def close(self):
        """
        Clean up resources and close the socket.
        """
        try:
            self.running = False
            if self.socket:
                if self.poller:
                    self.poller.unregister(self.socket)
                self.socket.close()
                self.socket = None
            self.channels.clear()
            self.retained_messages.clear()
            self.pending_messages.clear()
            self.logger.info("NoMQ resources cleaned up")
        except Exception as e:
            self.logger.error(f"Error closing NoMQ: {e}")

    def __del__(self):
        """
        Ensure resources are cleaned up on object destruction.
        """
        self.close()

