import hashlib
import base64

def hash_sha3_256(message):
  hasher = hashlib.sha3_256()
  hasher.update(message)
  return hasher.digest()

def hash_base64(hash_bytes):
  hash_b64 = base64.b64encode(hash_bytes).decode()
  return hash_b64

def base64_to_bytes(base64_str):
  return base64.b64decode(base64_str)
