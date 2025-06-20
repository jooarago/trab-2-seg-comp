import primos
from primos import random_bigint_within_range
from rsa import rsa_encrypt
from rsa import rsa_decrypt
import hashlib

def gen_mask_mgf1(seed, k): # ref: https://en.wikipedia.org/wiki/Mask_generation_function
    hash_size = 20
    result = b''
    iterations = (k + hash_size - 1) // hash_size
    
    for i in range(iterations):
        input_data = seed + i.to_bytes(4, byteorder='big')
        hash_result = hashlib.sha1(input_data).digest()
        result += hash_result

    return result[:k]

def xor_bytes(a, b): # in this function a and b have to be of type 'byte'...
    if len(a) != len(b):
        print("len(a):", len(a))
        print("len(b):", len(b))
        raise ValueError("Entries a and b not of the same size...")
    
    res = bytearray(len(a))
    
    for i in range(len(a)):
        res[i] = a[i] ^ b[i]
    return bytes(res)

# the file content (msg_in_bytes) cannot be very large.
def oaep_encode(msg_in_bytes, k, label): # ref: https://en.m.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
    hash_len = 20
    hash_label = hashlib.sha1(label).digest()

    padding_string_len = k - len(msg_in_bytes) - 2*hash_len - 2

    db = bytearray()
    db.extend(hash_label)
    db.extend(b'\x00' * padding_string_len)
    db.append(0x01)
    db.extend(msg_in_bytes)

    seed = random_bigint_within_range(0, 256**hash_len - 1)

    seed = seed.to_bytes(hash_len, byteorder='big')

    db_mask = gen_mask_mgf1(seed, k-hash_len-1)
    db_masked = xor_bytes(db, db_mask)

    seed_mask = gen_mask_mgf1(db_masked, hash_len)
    seed_masked = xor_bytes(seed, seed_mask)

    padded_message = bytearray()
    padded_message.append(0x00)
    padded_message.extend(seed_masked)
    padded_message.extend(db_masked)

    return bytes(padded_message)

def oaep_decode(padded_message, k, label):
    hash_len = 20
    hash_label = hashlib.sha1(label).digest()

    byte00 = padded_message[0]
    seed_masked = padded_message[1:1+hash_len]
    db_masked = padded_message[1+hash_len:]

    seed_mask = gen_mask_mgf1(db_masked, hash_len)
    seed = xor_bytes(seed_masked, seed_mask)

    db_mask = gen_mask_mgf1(seed, k-hash_len-1)
    db = xor_bytes(db_masked, db_mask)

    hash_label_obtained = db[:hash_len]
    if hash_label_obtained != hash_label:
        raise ValueError("Invalid padding: different hash labels...")

    flag_founded_separator = False
    for i in range(hash_len, len(db)):
        if db[i] == 0x01:
            flag_founded_separator = True
            break
        elif db[i] != 0x00:
            raise ValueError("Invalid padding: PS consisting of non 0x00...")

    if not flag_founded_separator:
        raise ValueError("Invalid padding: separator not found...")

    return db[i+1:]

def cypher(msg_in_bytes, key):
    n, e = key
    k = (n.bit_length() + 7)//8

    msg_encoded = oaep_encode(msg_in_bytes, k, b"")
    msg_encoded_int = int.from_bytes(msg_encoded, byteorder='big')

    msg_cyphered = rsa_encrypt(msg_encoded_int, key)
    return msg_cyphered.to_bytes(k, byteorder='big')

def decypher(msg_cyphered_bytes, key):
    n, d = key
    k = (n.bit_length()+7)//8

    msg_cyphered_int = int.from_bytes(msg_cyphered_bytes, byteorder='big')
    msg_encoded_int = rsa_decrypt(msg_cyphered_int, key)

    msg_encoded = msg_encoded_int.to_bytes(k, byteorder='big')
    msg_decoded = oaep_decode(msg_encoded, k, b"")

    return msg_decoded

