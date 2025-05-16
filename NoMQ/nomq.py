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
from logger import SimpleLogger

class NoMQ:
    """
    NoMQ: Lightweight, secure messaging protocol for IoT devices running MicroPython.
    Features:
    - AES-CBC encryption and digital signature authentication
    - Reliable message delivery with QoS and acknowledgments
    - Memory-efficient design for ESP32/ESP8266
    - Real-time communication without brokers
    """
    MAX_RETAINED_MESSAGES = 5
    MAX_PENDING_MESSAGES = 50
    MAX_CHANNELS = 20
    MAX_PAYLOAD_SIZE = 256
    DEFAULT_TTL = 3600
    BUFFER_SIZE = 256
    HEARTBEAT_INTERVAL = 30
    SESSION_TIMEOUT = 300
    MAX_RETRIES = 3
    MAX_AUTH_DEVICES = 50
    TIMESTAMP_WINDOW = 30
    NONCE_WINDOW = 100
    MAX_BACKOFF = 60

    def __init__(self, config_file='nomq_config.json', log_level='INFO', timeout=5):
        self.logger = SimpleLogger(level=log_level)
        self.magic_number = 0x4E4D  # 'NM'
        self.protocol_version = 1
        self.used_nonces = []
        self.load_config(config_file)
        self.device_id = self.get_device_id()
        self.session_id = self.generate_session_id()
        self.session_start = time.time()
        self.channels = []
        self.retained_messages = {}
        self.pending_messages = {}
        self.nonce_counter = 0
        self.authenticated_devices = set()
        self.socket = None
        self.poller = None
        self.running = False
        self.timeout = timeout
        self.backoff_count = 0
        self.initialize_socket()
        self.logger.info(f"NoMQ initialized on {self.ip}:{self.port} (IPv{'6' if self.use_ipv6 else '4'})")

    def load_config(self, config_file):
        try:
            with open(config_file, 'r') as f:
                encrypted_data = ubinascii.a2b_base64(f.read().strip())
            
            if len(encrypted_data) < 16 or len(encrypted_data) % 16 != 0:
                raise ValueError("Invalid encrypted data length")

            config_key = hashlib.sha256(b"nomq_config_key").digest()
            iv = encrypted_data[:16]
            cipher = aes(config_key, 2, iv)
            padded_data = cipher.decrypt(encrypted_data[16:])
            
            pad_len = padded_data[-1]
            if pad_len < 1 or pad_len > 16 or not all(b == pad_len for b in padded_data[-pad_len:]):
                raise ValueError("Incorrect padding")
            
            config_data = padded_data[:-pad_len]
            config = json.loads(config_data.decode('utf-8'))

            self.ip = config.get('ip', '0.0.0.0')
            self.port = config.get('port', 8888)
            self.use_ipv6 = config.get('use_ipv6', False)
            self.encryption_key = ubinascii.unhexlify(config.get('encryption_key'))
            self.hmac_key = ubinascii.unhexlify(config.get('hmac_key'))
            self.public_key = ubinascii.unhexlify(config.get('public_key'))
            if len(self.encryption_key) != 32 or len(self.hmac_key) != 32:
                raise ValueError("Encryption and HMAC keys must be 32 bytes")
        except Exception as e:
            self.logger.error(f"Config load failed: {e}")
            raise

    def initialize_socket(self):
        try:
            if self.socket:
                self.socket.close()
        except Exception as e:
            self.logger.error(f"Error closing socket: {e}")

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
            self.backoff_count = 0
        except OSError as e:
            self.logger.error(f"Socket bind failed: {e}")
            self.close()
            raise

    async def reinitialize_socket(self):
        self.logger.warning("Reinitializing socket...")
        self.backoff_count += 1
        backoff_time = min(2 ** self.backoff_count, self.MAX_BACKOFF)
        self.logger.info(f"Waiting {backoff_time} seconds before socket reinitialization")
        await asyncio.sleep(backoff_time)
        try:
            self.initialize_socket()
            self.logger.info("Socket reinitialized successfully")
        except Exception as e:
            self.logger.error(f"Socket reinitialization failed: {e}")
            if self.backoff_count < 5:
                await self.reinitialize_socket()
            else:
                self.logger.error("Max socket reinitialization attempts reached")
                self.close()

    def get_device_id(self):
        mac = unique_id()
        return hashlib.sha256(mac).digest().hex()

    def generate_session_id(self):
        return int.from_bytes(os.urandom(4), 'big')

    def renew_session(self):
        if time.time() - self.session_start > self.SESSION_TIMEOUT:
            self.session_id = self.generate_session_id()
            self.session_start = time.time()
            self.nonce_counter = 0
            self.cleanup_nonces()
            self.logger.info("Session ID renewed")

    def cleanup_nonces(self):
        current_time = time.time()
        self.used_nonces = [n for n in self.used_nonces if n['timestamp'] + self.TIMESTAMP_WINDOW > current_time]
        if len(self.used_nonces) > self.NONCE_WINDOW:
            self.used_nonces = self.used_nonces[-self.NONCE_WINDOW:]
        gc.collect()

    def generate_packet_id(self):
        return int.from_bytes(os.urandom(4), 'big')

    async def authenticate(self, signature, message, addr):
        try:
            if isinstance(message, str):
                message = message.encode('utf-8')
            elif not isinstance(message, (bytes, bytearray)):
                raise ValueError(f"Message must be bytes or string, got {type(message)}")
            
            computed_signature = uhashlib.sha256(message + self.public_key).digest()
            if computed_signature == signature:
                if len(self.authenticated_devices) >= self.MAX_AUTH_DEVICES:
                    self.authenticated_devices.pop()
                self.authenticated_devices.add(addr)
                self.logger.info(f"Device {addr} authenticated")
                return True
            self.logger.warning(f"Authentication failed for {addr}")
            return False
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False

    async def subscribe(self, channel, priority=0, signature=None, message=None, addr=None):
        try:
            if not isinstance(channel, str) or not channel:
                raise ValueError("Channel must be a non-empty string")
            if len(self.channels) >= self.MAX_CHANNELS:
                self.logger.error("Max channel limit reached")
                return
            if signature and message and addr:
                if isinstance(message, str):
                    message = message.encode('utf-8')
                if not await self.authenticate(signature, message, addr):
                    return

            channel_id = hashlib.sha256(channel.encode()).digest()[:16]
            if channel not in [ch['name'] for ch in self.channels]:
                self.channels.append({"name": channel, "id": channel_id, "priority": min(max(priority, 0), 15)})
                self.logger.info(f"Subscribed to {channel} with priority {priority}")
                packet = self.create_packet(
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
        except Exception as e:
            self.logger.error(f"Subscribe failed: {e}")

    async def publish(self, channel, message, qos=2, retain=False, ttl=DEFAULT_TTL, priority=0, ip='0.0.0.0', port=8888, signature=None, auth_message=None):
        try:
            if not isinstance(message, str):
                raise ValueError(f"Message must be a string, got {type(message)}")
            if len(message) == 0:
                raise ValueError("Message cannot be empty")
            if len(message) > self.MAX_PAYLOAD_SIZE:
                raise ValueError(f"Message exceeds max payload size ({self.MAX_PAYLOAD_SIZE} bytes)")
            if signature and auth_message:
                if isinstance(auth_message, str):
                    auth_message = auth_message.encode('utf-8')
                if not await self.authenticate(signature, auth_message, (ip, port)):
                    return

            self.renew_session()
            channel_id = hashlib.sha256(channel.encode()).digest()[:16]
            packet_id = self.generate_packet_id()
            flags = (
                (qos & 0x03) |
                (0x04 if retain else 0x00) |
                ((min(max(priority, 0), 15) & 0x0F) << 4)
            )

            # ساخت payload بدون فشرده‌سازی
            timestamp = int(time.time())
            nonce = self.nonce_counter
            self.nonce_counter += 1
            encoded_message = message.encode('utf-8')
            raw_payload = bytearray()
            raw_payload.extend(struct.pack('!QII', timestamp, nonce, len(encoded_message)))
            raw_payload.extend(encoded_message)
            payload = bytes(raw_payload)
            self.logger.debug(f"Payload length: {len(payload)}")

            packet = self.create_packet(
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
                        self.limit_retained_messages(channel)

                    if qos > 0:
                        if len(self.pending_messages) < self.MAX_PENDING_MESSAGES:
                            self.pending_messages[packet_id] = {
                                "packet": packet,
                                "channel": channel,
                                "ip": ip,
                                "port": port,
                                "retries": self.MAX_RETRIES,
                                "timestamp": time.time(),
                                "ttl": ttl
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
        except Exception as e:
            self.logger.error(f"Publish failed: {e}")
            raise

    def limit_retained_messages(self, channel):
        mem_free = gc.mem_free()
        max_allowed = min(self.MAX_RETAINED_MESSAGES, mem_free // (self.BUFFER_SIZE * 2))
        if max_allowed < 1:
            max_allowed = 1
        while len(self.retained_messages[channel]) > max_allowed:
            self.retained_messages[channel].pop(0)
        gc.collect()

    def limit_pending_messages(self):
        mem_free = gc.mem_free()
        max_allowed = min(self.MAX_PENDING_MESSAGES, mem_free // (self.BUFFER_SIZE * 2))
        if max_allowed < 1:
            max_allowed = 1
        while len(self.pending_messages) > max_allowed:
            oldest_key = next(iter(self.pending_messages))
            del self.pending_messages[oldest_key]
        gc.collect()

    def cleanup_nonces(self):
        now = time.time()
        self.used_nonces = [n for n in self.used_nonces if now - n['timestamp'] < 60]

        # سقف تعداد: 1000 مورد آخر
        if len(self.used_nonces) > 1000:
            self.used_nonces = self.used_nonces[-1000:]

    
    async def listen(self):
        self.running = True
        while self.running:
            try:
                events = self.poller.poll(50)
                if not events:
                    await asyncio.sleep(0.1)
                    continue

                data, addr = self.socket.recvfrom(self.BUFFER_SIZE)

                if addr not in self.authenticated_devices:
                    self.logger.warning(f"Unauthenticated device: {addr}")
                    continue

                packet = self.parse_packet(data)
                if not packet or not isinstance(packet, dict):
                    self.logger.error(f"Packet parsing failed from {addr}. Raw data: {data}")
                    continue

                channel = packet.get("channel")
                if not channel:
                    self.logger.warning(f"Missing channel in packet from {addr}")
                    continue

                if channel not in [ch['name'] for ch in self.channels]:
                    self.logger.warning(f"Unsubscribed channel: {channel}")
                    continue

                if packet.get("type") == 0x01:
                    payload = packet.get("payload")
                    if not payload or len(payload) < 20:
                        self.logger.error(f"Invalid payload from {addr}")
                        continue

                    try:
                        timestamp, nonce, msg_len = struct.unpack('!QII', payload[:20])
                        message = payload[20:20 + msg_len].decode('utf-8')

                        if any(n['nonce'] == nonce for n in self.used_nonces):
                            self.logger.warning("Replay attack detected")
                            continue

                        self.used_nonces.append({'nonce': nonce, 'timestamp': time.time()})
                        self.cleanup_nonces()

                        self.logger.info(f"Received on {channel}: {message}")

                        qos = packet["flags"] & 0x03
                        if qos in (1, 2, 3):
                            await self.send_ack(packet, addr, qos=qos)

                    except Exception as e:
                        self.logger.error(f"Publish packet error from {addr}: {e}")

                elif packet.get("type") == 0x03:
                    packet_id = packet.get("packet_id")
                    if packet_id in self.pending_messages:
                        del self.pending_messages[packet_id]
                        self.logger.info(f"ACK received for packet ID {packet_id}")

                elif packet.get("type") == 0x05:
                    await self.send_heartbeat_response(addr)

                await self.cleanup_expired_messages()

            except OSError as e:
                self.logger.error(f"Socket error: {e}")
                await self.reinitialize_socket()

            except Exception as e:
                self.logger.error(f"Listen error: {e}")

            await asyncio.sleep(0.1)
        
    def create_packet(self, packet_type, flags, channel_id, payload, packet_id=None, ttl=DEFAULT_TTL):
        try:
            if not isinstance(payload, (bytes, bytearray)):
                raise ValueError(f"Payload must be bytes, got {type(payload)}")
            if packet_id is None:
                packet_id = self.generate_packet_id()

            nonce = os.urandom(16)
            timestamp = int(time.time())

            cipher = aes(self.encryption_key, 2, nonce)
            pad_len = 16 - (len(payload) % 16)
            padded_payload = payload + bytes([pad_len] * pad_len)
            encrypted_payload = cipher.encrypt(padded_payload)
            encrypted_payload = nonce + encrypted_payload

            control_header = (
                self.magic_number.to_bytes(2, 'big') +
                self.protocol_version.to_bytes(1, 'big') +
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
        except Exception as e:
            self.logger.error(f"Packet creation error: {e}")
            return None

    def parse_packet(self, data):
        try:
            if len(data) < 32 + 32:
                self.logger.warning("Packet too short")
                return None

            magic = int.from_bytes(data[:2], 'big')
            if magic != self.magic_number:
                self.logger.warning("Invalid magic number")
                return None

            version = data[2]
            if version != self.protocol_version:
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
        except Exception as e:
            self.logger.error(f"Packet parsing error: {e}")
            return None

    async def send_ack(self, packet, addr, qos):
        try:
            channel_id = hashlib.sha256(packet["channel"].encode()).digest()[:16]
            ack_packet = self.create_packet(
                packet_type=0x03,
                flags=qos & 0x03,
                channel_id=channel_id,
                payload=struct.pack('!I', packet["packet_id"]),
                packet_id=packet["packet_id"]
            )
            if ack_packet:
                self.socket.sendto(ack_packet, addr)
                self.logger.info(f"Sent ACK for packet ID {packet['packet_id']} with QoS {qos}")
        except Exception as e:
            self.logger.error(f"ACK send error: {e}")

    async def send_heartbeat_response(self, addr):
        try:
            packet = self.create_packet(
                packet_type=0x05,
                flags=0,
                channel_id=b'\x00' * 16,
                payload=b""
            )
            if packet:
                self.socket.sendto(packet, addr)
                self.logger.info(f"Sent heartbeat to {addr}")
        except Exception as e:
            self.logger.error(f"Heartbeat send error: {e}")

    async def unsubscribe(self, channel):
        try:
            for i, ch in enumerate(self.channels):
                if ch["name"] == channel:
                    channel_id = ch["id"]
                    packet = self.create_packet(
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
        except Exception as e:
            self.logger.error(f"Unsubscribe error: {e}")

    async def cleanup_expired_messages(self):
        current_time = time.time()
        for channel in list(self.retained_messages.keys()):
            self.retained_messages[channel] = [
                msg for msg in self.retained_messages[channel]
                if self.parse_packet(msg).get("timestamp", 0) + self.parse_packet(msg).get("ttl", self.DEFAULT_TTL) > current_time
            ]
            if not self.retained_messages[channel]:
                del self.retained_messages[channel]

        for packet_id in list(self.pending_messages.keys()):
            msg = self.pending_messages[packet_id]
            if msg["timestamp"] + msg["ttl"] < current_time:
                del self.pending_messages[packet_id]
                self.logger.info(f"Removed expired message ID {packet_id}")
        self.limit_pending_messages()

    def close(self):
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
            self.authenticated_devices.clear()
            self.used_nonces.clear()
            self.logger.info("NoMQ resources cleaned up")
        except Exception as e:
            self.logger.error(f"Close error: {e}")

    def __del__(self):
        self.close()


