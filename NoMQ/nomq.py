import socket
import uhashlib
import hashlib
import struct
import time
import uasyncio as asyncio
from machine import unique_id
import network
from ucryptolib import aes
import ubinascii
import os
import select
import json
import gc

#LOGGER
from logger import SimpleLogger

class NoMQ:
    """
    NoMQ: Lightweight, secure messaging protocol for IoT devices running MicroPython.
    Designed for industrial use with high reliability, security, and efficiency.
    
    Features:
    - AES-CBC encryption with HMAC-SHA256 authentication
    - Reliable message delivery with QoS levels (0, 1, 2)
    - Memory-efficient design for ESP32/ESP8266
    - Real-time communication without brokers
    - Robust error handling and network resilience
    - Message retrieval via listen().mssg() for processed messages
    """
    # Configuration constants
    MAX_RETAINED_MESSAGES = 5
    MAX_PENDING_MESSAGES = 50
    MAX_CHANNELS = 20
    MAX_PAYLOAD_SIZE = 1024
    DEFAULT_TTL = 3600
    BUFFER_SIZE = 2048
    HEARTBEAT_INTERVAL = 30
    SESSION_TIMEOUT = 300
    MAX_RETRIES = 3
    TIMESTAMP_WINDOW = 30
    NONCE_WINDOW = 100
    MAX_BACKOFF = 60
    PROTOCOL_VERSION = 1
    MAGIC_NUMBER = 0x4E4D  # 'NM'

    def __init__(self, config_file='nomq_config.json', log_level='INFO', timeout=5):
        """
        Initialize NoMQ with configuration and logging.
        
        Args:
            config_file (str): Path to encrypted configuration file.
            log_level (str): Logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR').
            timeout (float): Socket timeout in seconds.
        
        Raises:
            RuntimeError: If config loading or socket initialization fails.
        """
        self.logger = SimpleLogger(level=log_level)
        self.timeout = timeout
        self.device_id = self._get_device_id()
        self.session_id = self._generate_session_id()
        self.session_start = time.time()
        self.channels = []
        self.retained_messages = {}
        self.pending_messages = {}
        self.nonce_set = []
        self.socket = None
        self.poller = None
        self.running = False
        self.backoff_count = 0
        self._load_config(config_file)
        self._initialize_socket()
        self.logger.info(f"NoMQ initialized on {self.ip}:{self.port} (IPv{'6' if self.use_ipv6 else '4'})")

    def _load_config(self, config_file):
        """
        Load and decrypt configuration from file.
        
        Args:
            config_file (str): Path to encrypted config file.
        
        Raises:
            RuntimeError: If config is invalid or decryption fails.
        """
        try:
            with open(config_file, 'r') as f:
                encrypted_data = ubinascii.a2b_base64(f.read().strip())
            
            if len(encrypted_data) < 16 or len(encrypted_data) % 16 != 0:
                raise ValueError("Invalid encrypted config data length")

            config_key = hashlib.sha256(b"nomq_config_key").digest()
            iv = encrypted_data[:16]
            cipher = aes(config_key, 2, iv)
            padded_data = cipher.decrypt(encrypted_data[16:])
            
            pad_len = padded_data[-1]
            if pad_len < 1 or pad_len > 16 or not all(b == pad_len for b in padded_data[-pad_len:]):
                raise ValueError("Incorrect padding in config data")
            
            config_data = padded_data[:-pad_len]
            config = json.loads(config_data.decode('utf-8'))

            self.ip = config.get('ip', '0.0.0.0')
            self.port = config.get('port', 8888)
            self.use_ipv6 = config.get('use_ipv6', False)
            self.encryption_key = ubinascii.unhexlify(config.get('encryption_key'))
            self.hmac_key = ubinascii.unhexlify(config.get('hmac_key'))
            if len(self.encryption_key) != 32 or len(self.hmac_key) != 32:
                raise ValueError("Encryption and HMAC keys must be 32 bytes")
        except (OSError, ValueError, TypeError) as e:
            self.logger.error(f"Failed to load config: {e}")
            raise RuntimeError(f"Config load failed: {e}")

    def create_config(self, config_dict, output_file):
        """
        Encrypt and save configuration to a file.
        
        Args:
            config_dict (dict): Configuration dictionary (ip, port, use_ipv6, encryption_key, hmac_key).
            output_file (str): Path to save encrypted config file.
        
        Raises:
            OSError: If file writing fails.
        """
        try:
            config_data = json.dumps(config_dict).encode('utf-8')
            config_key = hashlib.sha256(b"nomq_config_key").digest()
            iv = os.urandom(16)
            cipher = aes(config_key, 2, iv)
            pad_len = 16 - (len(config_data) % 16)
            padded_data = config_data + bytes([pad_len] * pad_len)
            encrypted_data = iv + cipher.encrypt(padded_data)
            with open(output_file, 'w') as f:
                f.write(ubinascii.b2a_base64(encrypted_data).decode('utf-8'))
            self.logger.info(f"Config saved to {output_file}")
        except (OSError, TypeError) as e:
            self.logger.error(f"Failed to save config: {e}")
            raise

    def _initialize_socket(self):
        """
        Initialize UDP socket with proper configuration.
        
        Raises:
            RuntimeError: If socket binding fails.
        """
        try:
            if self.socket:
                self.socket.close()
                self.socket = None
        except OSError as e:
            self.logger.error(f"Error closing socket: {e}")

        family = socket.AF_INET6 if self.use_ipv6 else socket.AF_INET
        try:
            self.socket = socket.socket(family, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.settimeout(self.timeout)
            bind_addr = (self.ip, self.port, 0, 0) if self.use_ipv6 else (self.ip, self.port)
            self.socket.bind(bind_addr)
            self.poller = select.poll()
            self.poller.register(self.socket, select.POLLIN)
            self.running = True
            self.backoff_count = 0
            self.logger.info("Socket initialized successfully")
        except OSError as e:
            self.logger.error(f"Socket initialization failed: {e}")
            self.close()
            raise RuntimeError(f"Socket bind failed: {e}")

    async def _reinitialize_socket(self):
        """
        Reinitialize socket with exponential backoff.
        
        Raises:
            RuntimeError: If max reinitialization attempts are reached.
        """
        self.logger.warning("Reinitializing socket...")
        self.backoff_count += 1
        backoff_time = min(2 ** self.backoff_count, self.MAX_BACKOFF)
        self.logger.info(f"Waiting {backoff_time} seconds before socket reinitialization")
        await asyncio.sleep(backoff_time)
        try:
            self._initialize_socket()
            self.logger.info("Socket reinitialized successfully")
        except RuntimeError as e:
            self.logger.error(f"Socket reinitialization failed: {e}")
            if self.backoff_count < 5:
                await self._reinitialize_socket()
            else:
                self.logger.error("Max socket reinitialization attempts reached")
                self.close()
                raise RuntimeError("Failed to reinitialize socket")

    def _get_device_id(self):
        """Generate unique device ID based on MAC address."""
        mac = unique_id()
        return hashlib.sha256(mac).digest().hex()

    def _generate_session_id(self):
        """Generate a random session ID."""
        return int.from_bytes(os.urandom(4), 'big')

    def _generate_packet_id(self):
        """Generate a random packet ID."""
        return int.from_bytes(os.urandom(4), 'big')

    def _renew_session(self):
        """Renew session if timeout is reached."""
        if time.time() - self.session_start > self.SESSION_TIMEOUT:
            self.session_id = self._generate_session_id()
            self.session_start = time.time()
            self.nonce_set = []
            self.logger.info("Session renewed")

    def _cleanup_nonces(self):
        """Clean up expired nonces to prevent memory overflow."""
        current_time = time.time()
        self.nonce_set = [n for n in self.nonce_set if n['timestamp'] + self.TIMESTAMP_WINDOW > current_time]
        while len(self.nonce_set) > self.NONCE_WINDOW:
            self.nonce_set.pop(0)  # Simulate deque behavior
        if len(self.nonce_set) % 10 == 0:  # Reduce gc.collect calls
            gc.collect()

    def gen_signature(self, message="auth"):
        """
        Generate HMAC-SHA256 signature for authentication.
        
        Args:
            message (str or bytes): Message to sign.
        
        Returns:
            bytes: HMAC-SHA256 signature.
        
        Raises:
            ValueError: If message is not bytes or string.
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        elif not isinstance(message, (bytes, bytearray)):
            raise ValueError(f"Message must be bytes or string, got {type(message)}")
        return uhashlib.sha256(message + self.hmac_key).digest()

    async def authenticate(self, signature, message, addr):
        """
        Authenticate a device using HMAC-SHA256 without storing state.
        
        Args:
            signature (bytes): Received HMAC-SHA256 signature.
            message (str or bytes): Message to verify.
            addr (tuple): Device address (ip, port).
        
        Returns:
            bool: True if authenticated, False otherwise.
        """
        try:
            if isinstance(message, str):
                message_bytes = message.encode('utf-8')
            elif isinstance(message, (bytes, bytearray)):
                message_bytes = message
            else:
                raise ValueError(f"Message must be bytes or string, got {type(message)}")
            
            computed_signature = uhashlib.sha256(message_bytes + self.hmac_key).digest()
            if computed_signature == signature:
                self.logger.info(f"Device {addr} authenticated successfully")
                return True
            self.logger.warning(f"Authentication failed for {addr}")
            return False
        except (ValueError, TypeError) as e:
            self.logger.error(f"Authentication error: {e}")
            return False

    async def subscribe(self, channel, priority=0, signature=None, message=None, addr=None):
        """
        Subscribe to a channel with optional authentication.
        
        Args:
            channel (str): Channel name to subscribe to.
            priority (int): Subscription priority (0-15).
            signature (bytes): HMAC-SHA256 signature for authentication.
            message (str or bytes): Authentication message.
            addr (tuple): Device address for authentication.
        
        Raises:
            ValueError: If channel is invalid.
            RuntimeError: If max channel limit is reached.
        """
        try:
            if not isinstance(channel, str) or not channel:
                raise ValueError("Channel must be a non-empty string")
            if len(self.channels) >= self.MAX_CHANNELS:
                raise RuntimeError("Max channel limit reached")
            if signature and message and addr:
                if not await self.authenticate(signature, message, addr):
                    return

            channel_id = hashlib.sha256(channel.encode()).digest()[:16]
            if channel not in [ch['name'] for ch in self.channels]:
                self.channels.append({"name": channel, "id": channel_id, "priority": min(max(priority, 0), 15)})
                self.logger.info(f"Subscribed to {channel} with priority {priority}")
                packet = self._create_packet(
                    packet_type=0x02,
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
        except (ValueError, RuntimeError, OSError) as e:
            self.logger.error(f"Subscribe failed: {e}")

    async def publish(self, channel, message, qos=1, retain=False, ttl=DEFAULT_TTL, priority=0, ip='255.255.255.255', port=8888, signature=None, auth_message=None):
        """
        Publish a message to a channel with QoS and optional authentication.
        
        Args:
            channel (str): Channel to publish to.
            message (str): Message to publish.
            qos (int): Quality of Service (0, 1, 2).
            retain (bool): Whether to retain the message.
            ttl (int): Time-to-live in seconds.
            priority (int): Message priority (0-15).
            ip (str): Destination IP address.
            port (int): Destination port.
            signature (bytes): HMAC-SHA256 signature for authentication.
            auth_message (str or bytes): Authentication message.
        
        Raises:
            ValueError: If message is invalid or exceeds size limits.
            OSError: If network errors occur.
        """
        try:
            if not isinstance(message, str):
                raise ValueError(f"Message must be a string, got {type(message)}")
            if len(message) == 0:
                raise ValueError("Message cannot be empty")
            if len(message) > self.MAX_PAYLOAD_SIZE:
                raise ValueError(f"Message exceeds max payload size ({self.MAX_PAYLOAD_SIZE} bytes)")
            if signature and auth_message:
                if not await self.authenticate(signature, auth_message, (ip, port)):
                    return

            self._renew_session()
            channel_id = hashlib.sha256(channel.encode()).digest()[:16]
            packet_id = self._generate_packet_id()
            flags = (
                (qos & 0x03) |
                (0x04 if retain else 0x00) |
                ((min(max(priority, 0), 15) & 0x0F) << 4)
            )

            timestamp = int(time.time())
            nonce = self._generate_packet_id()
            encoded_message = message.encode('utf-8')
            raw_payload = bytearray()
            raw_payload.extend(struct.pack('!QII', timestamp, nonce, len(encoded_message)))
            raw_payload.extend(encoded_message)
            payload = bytes(raw_payload)

            packet = self._create_packet(
                packet_type=0x01,
                flags=flags,
                channel_id=channel_id,
                payload=payload,
                packet_id=packet_id,
                ttl=ttl
            )
            if not packet:
                self.logger.error("Failed to create publish packet")
                return

            retries = self.MAX_RETRIES
            while retries > 0:
                try:
                    addr = (ip, port, 0, 0) if self.use_ipv6 else (ip, port)
                    self.socket.sendto(packet, addr)
                    self.logger.info(f"Published to {channel}: {message}")

                    if retain:
                        if channel not in self.retained_messages:
                            self.retained_messages[channel] = []
                        self.retained_messages[channel].append(packet)
                        self._limit_retained_messages(channel)

                    if qos > 0:
                        if len(self.pending_messages) < self.MAX_PENDING_MESSAGES:
                            self.pending_messages[packet_id] = {
                                "packet": packet,
                                "channel": channel,
                                "ip": ip,
                                "port": port,
                                "retries": self.MAX_RETRIES,
                                "timestamp": time.time(),
                                "ttl": ttl,
                                "state": "PUBLISH_SENT" if qos == 2 else None
                            }
                        else:
                            self.logger.warning("Pending messages limit reached")
                    break
                except OSError as e:
                    self.logger.error(f"Send error: {e}")
                    retries -= 1
                    await asyncio.sleep(2 ** (self.MAX_RETRIES - retries))
            if retries == 0:
                self.logger.error(f"Failed to send packet after {self.MAX_RETRIES} retries")
        except (ValueError, OSError) as e:
            self.logger.error(f"Publish failed: {e}")

    def _limit_retained_messages(self, channel):
        """Limit retained messages based on memory constraints."""
        max_allowed = min(self.MAX_RETAINED_MESSAGES, 10)
        while len(self.retained_messages[channel]) > max_allowed:
            self.retained_messages[channel].pop(0)
        gc.collect()

    def _limit_pending_messages(self):
        """Limit pending messages based on memory constraints."""
        max_allowed = min(self.MAX_PENDING_MESSAGES, 50)
        while len(self.pending_messages) > max_allowed:
            oldest_key = next(iter(self.pending_messages))
            del self.pending_messages[oldest_key]
        gc.collect()

    def _create_packet(self, packet_type, flags, channel_id, payload, packet_id=None, ttl=DEFAULT_TTL):
        """
        Create an encrypted packet with HMAC.
        
        Args:
            packet_type (int): Type of packet (e.g., 0x01 for publish).
            flags (int): Packet flags (QoS, retain, priority).
            channel_id (bytes): 16-byte channel identifier.
            payload (bytes): Packet payload.
            packet_id (int): Unique packet ID (optional).
            ttl (int): Time-to-live in seconds.
        
        Returns:
            bytes: Encrypted packet or None if creation fails.
        """
        try:
            if not isinstance(payload, (bytes, bytearray)):
                raise ValueError(f"Payload must be bytes, got {type(payload)}")
            if packet_id is None:
                packet_id = self._generate_packet_id()

            nonce = os.urandom(16)
            timestamp = int(time.time())

            cipher = aes(self.encryption_key, 2, nonce)
            pad_len = 16 - (len(payload) % 16)
            padded_payload = payload + bytes([pad_len] * pad_len)
            encrypted_payload = cipher.encrypt(padded_payload)
            encrypted_payload = nonce + encrypted_payload

            control_header = (
                self.MAGIC_NUMBER.to_bytes(2, 'big') +
                self.PROTOCOL_VERSION.to_bytes(1, 'big') +
                packet_type.to_bytes(1, 'big') +
                flags.to_bytes(1, 'big') +
                packet_id.to_bytes(4, 'big') +
                self.session_id.to_bytes(4, 'big') +
                ttl.to_bytes(2, 'big')
            )
            security_header = (
                nonce +
                timestamp.to_bytes(4, 'big')
            )
            data_header = (
                channel_id +
                len(encrypted_payload).to_bytes(2, 'big')
            )

            hmac_obj = uhashlib.sha256(control_header + security_header + data_header + encrypted_payload + self.hmac_key)
            hmac = hmac_obj.digest()

            return control_header + security_header + data_header + encrypted_payload + hmac
        except (ValueError, TypeError) as e:
            self.logger.error(f"Packet creation error: {e}")
            return None

    def _parse_packet(self, data):
        """
        Parse an incoming packet and verify its integrity.
        
        Args:
            data (bytes): Raw packet data.
        
        Returns:
            dict: Parsed packet or None if invalid.
        """
        try:
            if len(data) < 53 + 32:
                self.logger.warning("Packet too short")
                return None

            magic = int.from_bytes(data[:2], 'big')
            if magic != self.MAGIC_NUMBER:
                self.logger.warning("Invalid magic number")
                return None

            version = data[2]
            if version != self.PROTOCOL_VERSION:
                self.logger.warning("Unsupported protocol version")
                return None

            packet_type = data[3]
            flags = data[4]
            packet_id = int.from_bytes(data[5:9], 'big')
            session_id = int.from_bytes(data[9:13], 'big')
            ttl = int.from_bytes(data[13:15], 'big')

            nonce = data[15:31]
            timestamp = int.from_bytes(data[31:35], 'big')
            if abs(time.time() - timestamp) > self.TIMESTAMP_WINDOW:
                self.logger.warning("Possible replay attack")
                return None

            channel_id = data[35:51]
            payload_length = int.from_bytes(data[51:53], 'big')
            if len(data) < 53 + payload_length + 32:
                self.logger.warning("Invalid packet length")
                return None
            encrypted_payload = data[53:53 + payload_length]
            received_hmac = data[53 + payload_length:]

            hmac_obj = uhashlib.sha256(data[:53 + payload_length] + self.hmac_key)
            calculated_hmac = hmac_obj.digest()
            if calculated_hmac != received_hmac:
                self.logger.warning("HMAC verification failed")
                return None

            iv = encrypted_payload[:16]
            ciphertext = encrypted_payload[16:]
            cipher = aes(self.encryption_key, 2, iv)
            padded_payload = cipher.decrypt(ciphertext)
            pad_len = padded_payload[-1]
            if pad_len < 1 or pad_len > 16 or not all(b == pad_len for b in padded_payload[-pad_len:]):
                self.logger.warning("Invalid padding")
                return None
            payload = padded_payload[:-pad_len]

            channel = None
            for ch in self.channels:
                if ch["id"] == channel_id:
                    channel = ch["name"]
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
        except (ValueError, TypeError) as e:
            self.logger.error(f"Packet parsing error: {e}")
            return None

    async def send_ack(self, packet, addr, qos):
        """
        Send an acknowledgment packet for QoS.
        
        Args:
            packet (dict): Parsed packet to acknowledge.
            addr (tuple): Destination address.
            qos (int): Quality of Service level.
        """
        try:
            channel_id = hashlib.sha256(packet["channel"].encode()).digest()[:16]
            ack_packet = self._create_packet(
                packet_type=0x03,
                flags=qos & 0x03,
                channel_id=channel_id,
                payload=struct.pack('!I', packet["packet_id"]),
                packet_id=packet["packet_id"]
            )
            if ack_packet:
                self.socket.sendto(ack_packet, addr)
                self.logger.info(f"Sent ACK for packet ID {packet['packet_id']} with QoS {qos}")
        except OSError as e:
            self.logger.error(f"ACK send error: {e}")

    async def send_heartbeat_response(self, addr):
        """
        Send a heartbeat response to maintain connection.
        
        Args:
            addr (tuple): Destination address.
        """
        try:
            packet = self._create_packet(
                packet_type=0x05,
                flags=0,
                channel_id=b'\x00' * 16,
                payload=b""
            )
            if packet:
                self.socket.sendto(packet, addr)
                self.logger.info(f"Sent heartbeat to {addr}")
        except OSError as e:
            self.logger.error(f"Heartbeat send error: {e}")

    async def handle_qos2(self, packet, addr):
        """
        Handle QoS 2 handshake (PUBREC, PUBREL, PUBCOMP).
        
        Args:
            packet (dict): Parsed packet.
            addr (tuple): Source address.
        """
        try:
            packet_id = packet["packet_id"]
            channel_id = hashlib.sha256(packet["channel"].encode()).digest()[:16]
            
            if packet["type"] == 0x01 and (packet["flags"] & 0x03) == 2:
                # Send PUBREC
                pubrec = self._create_packet(
                    packet_type=0x06,  # PUBREC
                    flags=0,
                    channel_id=channel_id,
                    payload=struct.pack('!I', packet_id),
                    packet_id=packet_id
                )
                if pubrec:
                    self.socket.sendto(pubrec, addr)
                    self.pending_messages[packet_id] = {
                        "state": "PUBREC_SENT",
                        "packet": packet,
                        "addr": addr,
                        "timestamp": time.time(),
                        "ttl": packet["ttl"]
                    }
                    self.logger.info(f"Sent PUBREC for packet ID {packet_id}")

            elif packet["type"] == 0x07:  # PUBREL
                if packet_id in self.pending_messages and self.pending_messages[packet_id]["state"] == "PUBREC_SENT":
                    # Send PUBCOMP
                    pubcomp = self._create_packet(
                        packet_type=0x08,  # PUBCOMP
                        flags=0,
                        channel_id=channel_id,
                        payload=struct.pack('!I', packet_id),
                        packet_id=packet_id
                    )
                    if pubcomp:
                        self.socket.sendto(pubcomp, addr)
                        del self.pending_messages[packet_id]
                        self.logger.info(f"Sent PUBCOMP for packet ID {packet_id}")

            elif packet["type"] == 0x06:  # PUBREC
                if packet_id in self.pending_messages and self.pending_messages[packet_id]["state"] == "PUBLISH_SENT":
                    # Send PUBREL
                    pubrel = self._create_packet(
                        packet_type=0x07,  # PUBREL
                        flags=0,
                        channel_id=channel_id,
                        payload=struct.pack('!I', packet_id),
                        packet_id=packet_id
                    )
                    if pubrel:
                        self.socket.sendto(pubrel, addr)
                        self.pending_messages[packet_id]["state"] = "PUBREL_SENT"
                        self.logger.info(f"Sent PUBREL for packet ID {packet_id}")

            elif packet["type"] == 0x08:  # PUBCOMP
                if packet_id in self.pending_messages and self.pending_messages[packet_id]["state"] == "PUBREL_SENT":
                    del self.pending_messages[packet_id]
                    self.logger.info(f"QoS 2 completed for packet ID {packet_id}")
        except OSError as e:
            self.logger.error(f"QoS 2 handling error: {e}")

    async def unsubscribe(self, channel):
        """
        Unsubscribe from a channel.
        
        Args:
            channel (str): Channel to unsubscribe from.
        """
        try:
            for i, ch in enumerate(self.channels):
                if ch["name"] == channel:
                    channel_id = ch["id"]
                    packet = self._create_packet(
                        packet_type=0x04,
                        flags=0,
                        channel_id=channel_id,
                        payload=channel.encode()
                    )
                    if packet:
                        self.socket.sendto(packet, (self.ip, self.port))
                        self.channels.pop(i)
                        self.logger.info(f"Unsubscribed from {channel}")
                    return
            self.logger.warning(f"Channel {channel} not subscribed")
        except OSError as e:
            self.logger.error(f"Unsubscribe error: {e}")

    async def cleanup_expired_messages(self):
        """Clean up expired retained and pending messages."""
        current_time = time.time()
        for channel in list(self.retained_messages.keys()):
            self.retained_messages[channel] = [
                msg for msg in self.retained_messages[channel]
                if self._parse_packet(msg).get("timestamp", 0) + self._parse_packet(msg).get("ttl", self.DEFAULT_TTL) > current_time
            ]
            if not self.retained_messages[channel]:
                del self.retained_messages[channel]

        for packet_id in list(self.pending_messages.keys()):
            msg = self.pending_messages[packet_id]
            if msg["timestamp"] + msg["ttl"] < current_time:
                del self.pending_messages[packet_id]
                self.logger.info(f"Removed expired message ID {packet_id}")
        self._limit_pending_messages()

    async def listen(self):
        """
        Listen for incoming messages and process them.
        Returns an object with a `mssg` method to retrieve processed messages.
        
        Returns:
            Listener: Object with mssg() method to access messages.
        """
        class Listener:
            def __init__(self, nomq):
                self.nomq = nomq
                self.message_queue = []

            def mssg(self):
                """Retrieve the next processed message from the queue."""
                return self.message_queue.pop(0) if self.message_queue else None

        listener = Listener(self)
        self.running = True
        while self.running:
            try:
                events = self.poller.poll(100)
                if not events:
                    await asyncio.sleep(0.1)
                    continue

                data, addr = self.socket.recvfrom(self.BUFFER_SIZE)
                packet = self._parse_packet(data)
                if not packet or not isinstance(packet, dict):
                    self.logger.error(f"Packet parsing failed from {addr}")
                    continue

                channel = packet.get("channel")
                if not channel:
                    self.logger.warning(f"Missing channel in packet from {addr}")
                    continue

                if channel not in [ch['name'] for ch in self.channels]:
                    self.logger.warning(f"Unsubscribed channel: {channel}")
                    continue

                signature = data[-32:]
                message = data[:-32]
                if not await self.authenticate(signature, message, addr):
                    self.logger.warning(f"Unauthenticated device: {addr}")
                    continue

                if packet.get("type") == 0x01:  # Publish packet
                    payload = packet.get("payload")
                    if not payload or len(payload) < 20:
                        self.logger.error(f"Invalid payload from {addr}")
                        continue

                    try:
                        timestamp, nonce, msg_len = struct.unpack('!QII', payload[:20])
                        message_bytes = payload[20:20 + msg_len]
                        # Validate payload before decoding
                        if msg_len > len(message_bytes):
                            self.logger.error(f"Invalid message length from {addr}")
                            continue
                        try:
                            message = message_bytes.decode('utf-8')
                        except Exception as e:
                            self.logger.error(f"Message decode error from {addr}: {e}")
                            continue

                        if any(n['nonce'] == nonce for n in self.nonce_set):
                            self.logger.warning("Replay attack detected")
                            continue

                        self.nonce_set.append({'nonce': nonce, 'timestamp': time.time()})
                        self._cleanup_nonces()

                        self.logger.info(f"Received on {channel}: {message}")
                        listener.message_queue.append({"channel": channel, "message": message})

                        qos = packet["flags"] & 0x03
                        if qos == 1:
                            await self.send_ack(packet, addr, qos=qos)
                        elif qos == 2:
                            await self.handle_qos2(packet, addr)

                    except (ValueError, Exception) as e:
                        self.logger.error(f"Publish packet error from {addr}: {e}")

                elif packet.get("type") == 0x03:  # ACK
                    packet_id = packet.get("packet_id")
                    if packet_id in self.pending_messages:
                        del self.pending_messages[packet_id]
                        self.logger.info(f"ACK received for packet ID {packet_id}")

                elif packet.get("type") in (0x06, 0x07, 0x08):  # QoS 2 packets
                    await self.handle_qos2(packet, addr)

                elif packet.get("type") == 0x05:  # Heartbeat
                    await self.send_heartbeat_response(addr)

                await self.cleanup_expired_messages()

            except OSError as e:
                self.logger.error(f"Socket error: {e}")
                await self._reinitialize_socket()
            except ValueError as e:
                self.logger.error(f"Value error: {e}")
            except Exception as e:
                self.logger.error(f"Unexpected error: {e}")
                await asyncio.sleep(0.1)

            await asyncio.sleep(0.1)

        return listener

    def close(self):
        """Clean up resources and close the socket."""
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
            self.nonce_set.clear()
            self.logger.info("NoMQ resources cleaned up")
        except OSError as e:
            self.logger.error(f"Close error: {e}")

    def __del__(self):
        """Ensure resources are cleaned up on object deletion."""
        self.close()
