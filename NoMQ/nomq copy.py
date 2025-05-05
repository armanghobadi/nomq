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

class NoMQ:
    def __init__(self, ip='0.0.0.0', port=8888, encryption_key=None, hmac_key=None):
        """
        Initialize NoMQ protocol for real-world IoT applications.
        """
        self.ip = ip
        self.port = port
        self.socket = None
        self.device_id = self.get_device_id()
        self.session_id = self.generate_session_id()
        self.channels = {}  # Subscribed channels: {channel: {id, priority}}
        self.retained_messages = {}  # Retained messages per channel
        self.pending_messages = {}  # Messages awaiting acknowledgment
        self.encryption_key = encryption_key or b'NoMQSecureKey123NoMQSecureKey123'  # 32-byte key
        self.hmac_key = hmac_key or b'NoMQHmacSecret1234567890'  # HMAC key
        self.salt = b'nomq_salt_2025'
        self.protocol_version = 0x01
        self.magic_number = 0xF1E2
        self.session_timeout = 300  # Session timeout in seconds
        self.max_retries = 5
        self.heartbeat_interval = 30  # Heartbeat interval in seconds
        self._init_socket()

    def _init_socket(self):
        """
        Initialize UDP socket with error handling.
        """
        try:
            if self.socket:
                self.socket.close()
        except:
            pass
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.socket.bind((self.ip, self.port))
        except OSError as e:
            print(f"Socket bind failed: {e}")
            raise
        print(f"NoMQ initialized on {self.ip}:{self.port}")

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
        self._init_socket()

    def subscribe(self, channel, priority=0):
        """
        Subscribe to a channel with specified priority.
        """
        try:
            channel_id = hashlib.sha256(channel.encode()).digest()[:16]
            if channel not in self.channels:
                self.channels[channel] = {"id": channel_id, "priority": priority}
                print(f"Subscribed to {channel} with priority {priority}")
                packet = self.create_packet(
                    packet_type=0x02,  # Subscribe
                    flags=priority & 0x0F,
                    channel_id=channel_id,
                    payload=channel.encode()
                )
                self.socket.sendto(packet, (self.ip, self.port))
                if channel in self.retained_messages:
                    for msg in self.retained_messages[channel]:
                        self.socket.sendto(msg, (self.ip, self.port))
                        print(f"Sent retained message to {channel}")
        except Exception as e:
            print(f"Subscribe failed: {e}")

    async def publish(self, channel, message, qos=2, retain=False, ttl=3600, priority=0, ip='0.0.0.0', port=8888):
        """
        Publish a message to a channel with advanced options.
        """
        try:
            channel_id = hashlib.sha256(channel.encode()).digest()[:16]
            packet_id = self.generate_packet_id()
            flags = (
                (qos & 0x03) |  # QoS (bits 0-1)
                (0x04 if retain else 0x00) |  # Retain (bit 2)
                ((priority & 0x0F) << 4)  # Priority (bits 4-7)
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
            
            retries = self.max_retries
            while retries > 0:
                try:
                    self.socket.sendto(packet, (ip, port))
                    print(f"Published to {channel}: {message}")
                    
                    if retain:
                        if channel not in self.retained_messages:
                            self.retained_messages[channel] = []
                        self.retained_messages[channel].append(packet)
                    
                    if qos > 0:
                        self.pending_messages[packet_id] = {
                            "packet": packet,
                            "channel": channel,
                            "ip": ip,
                            "port": port,
                            "retries": self.max_retries,
                            "timestamp": time.time(),
                            "ttl": ttl
                        }
                    break
                except OSError as e:
                    print(f"Error sending packet: {e}")
                    retries -= 1
                    await asyncio.sleep(2 ** (self.max_retries - retries))  # Exponential backoff
            
            if retries == 0:
                print(f"Failed to send packet after {self.max_retries} retries.")
        except Exception as e:
            print(f"Publish failed: {e}")

    async def listen(self):
        """
        Listen for incoming packets asynchronously using UDP socket.
        """
        while True:
            try:
                # Set socket to non-blocking mode
                self.socket.settimeout(0)
                try:
                    data, addr = self.socket.recvfrom(1024)  # Reduced buffer size
                    packet = self.parse_packet(data)
                    if not packet:
                        continue
                    
                    channel = packet.get("channel")
                    if channel not in self.channels:
                        print(f"Received packet on unsubscribed channel: {channel}")
                        continue
                    
                    if packet["type"] == 0x01:  # Publish
                        try:
                            payload_data = json.loads(packet["payload"].decode('utf-8'))
                            print(f"Received message on {channel}: {payload_data['message']}")
                            if packet["flags"] & 0x03 == 1:  # QoS 1
                                await self.send_ack(packet, addr, qos=1)
                            elif packet["flags"] & 0x03 == 2:  # QoS 2
                                await self.send_ack(packet, addr, qos=2)
                            elif packet["flags"] & 0x03 == 3:  # QoS 3
                                await self.send_ack(packet, addr, qos=3)
                        except Exception as e:
                            print(f"Error processing publish packet: {e}")
                    
                    elif packet["type"] == 0x03:  # Ack
                        if packet["packet_id"] in self.pending_messages:
                            del self.pending_messages[packet["packet_id"]]
                            print(f"Received ACK for packet ID {packet['packet_id']}")
                    
                    elif packet["type"] == 0x05:  # Heartbeat
                        await self.send_heartbeat_response(addr)
                
                except OSError as e:
                    # No data available, continue loop
                    if e.args[0] in (11, 110):  # EAGAIN or ETIMEDOUT
                        pass
                    else:
                        print(f"Socket error: {e}")
            except Exception as e:
                print(f"Error in listen: {e}")
            await asyncio.sleep(0.1)  # Prevent tight loop

    def create_packet(self, packet_type, flags, channel_id, payload, packet_id=None, ttl=3600):
        """
        Create a packet with advanced security using AES-CBC.
        """
        try:
            if packet_id is None:
                packet_id = self.generate_packet_id()
            
            iv = os.urandom(16)  # Initialization Vector for CBC
            timestamp = int(time.time())
            
            # Encrypt payload with AES-256-CBC
            cipher = aes(self.encryption_key, 2, iv)  # AES-256-CBC mode with IV
            pad_length = 16 - (len(payload) % 16)
            padded_payload = payload + bytes([pad_length] * pad_length)
            encrypted_payload = iv + cipher.encrypt(padded_payload)
            
            # Create control header
            control_header = (
                self.magic_number.to_bytes(2, 'big') +
                self.protocol_version.to_bytes(1, 'big') +
                packet_type.to_bytes(1, 'big') +
                flags.to_bytes(2, 'big') +
                packet_id.to_bytes(4, 'big') +
                self.session_id.to_bytes(8, 'big') +
                ttl.to_bytes(2, 'big')
            )
            
            # Create security header
            security_header = (
                iv +
                timestamp.to_bytes(8, 'big')
            )
            
            # Create data header
            data_header = (
                channel_id +
                len(encrypted_payload).to_bytes(4, 'big')
            )
            
            # Calculate HMAC
            hmac_obj = uhashlib.sha256(control_header + security_header + data_header + encrypted_payload + self.hmac_key)
            hmac = hmac_obj.digest()
            
            return control_header + security_header + data_header + encrypted_payload + hmac
        except Exception as e:
            print(f"Error creating packet: {e}")
            return None

    def parse_packet(self, data):
        """
        Parse and validate a received packet.
        """
        try:
            if len(data) < 36 + 32:  # Minimum packet size (control + security + data + HMAC)
                print("Packet too short")
                return None
            
            # Parse control header
            magic = int.from_bytes(data[:2], 'big')
            if magic != self.magic_number:
                print("Invalid magic number")
                return None
            
            version = data[2]
            if version != self.protocol_version:
                print("Unsupported protocol version")
                return None
            
            packet_type = data[3]
            flags = int.from_bytes(data[4:6], 'big')
            packet_id = int.from_bytes(data[6:10], 'big')
            session_id = int.from_bytes(data[10:18], 'big')
            ttl = int.from_bytes(data[18:20], 'big')
            
            # Parse security header
            iv = data[20:36]
            timestamp = int.from_bytes(data[36:44], 'big')
            if abs(time.time() - timestamp) > 60:  # Check for replay attack
                print("Possible replay attack detected")
                return None
            
            # Parse data header
            channel_id = data[44:60]
            payload_length = int.from_bytes(data[60:64], 'big')
            encrypted_payload = data[64:64 + payload_length]
            received_hmac = data[64 + payload_length:]
            
            # Verify HMAC
            hmac_obj = uhashlib.sha256(data[:64 + payload_length] + self.hmac_key)
            calculated_hmac = hmac_obj.digest()
            if calculated_hmac != received_hmac:
                print("HMAC verification failed")
                return None
            
            # Decrypt payload
            iv = encrypted_payload[:16]  # Extract IV from payload
            cipher = aes(self.encryption_key, 2, iv)  # AES-256-CBC mode with IV
            decrypted_payload = cipher.decrypt(encrypted_payload[16:])  # Skip IV
            pad_length = decrypted_payload[-1]
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
            print(f"Error parsing packet: {e}")
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
                print(f"Sent ACK for packet ID {packet['packet_id']} with QoS {qos}")
        except Exception as e:
            print(f"Error sending ACK: {e}")

    async def send_heartbeat_response(self, addr):
        """
        Send a heartbeat response to keep the session alive.
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
                print(f"Sent heartbeat response to {addr}")
        except Exception as e:
            print(f"Error sending heartbeat: {e}")

    def unsubscribe(self, channel):
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
                    print(f"Unsubscribed from {channel}")
            else:
                print(f"Channel {channel} not subscribed")
        except Exception as e:
            print(f"Error unsubscribing: {e}")

