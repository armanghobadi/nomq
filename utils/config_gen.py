from ucryptolib import aes
import ubinascii
import json
import hashlib
import os

config = {
    "ip": "0.0.0.0",
    "port": 8888, 
    "use_ipv6": False,
    "encryption_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", # just Sample
    "hmac_key": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"  # just Sample
}
config_data = json.dumps(config).encode('utf-8')
config_key = hashlib.sha256(b"nomq_config_key").digest()
iv = os.urandom(16)
cipher = aes(config_key, 2, iv)
pad_len = 16 - (len(config_data) % 16)
padded_data = config_data + bytes([pad_len] * pad_len)
encrypted_data = iv + cipher.encrypt(padded_data)
with open('nomq_config.json', 'w') as f:
    f.write(ubinascii.b2a_base64(encrypted_data).decode('utf-8'))

#Run on MicroPython Device