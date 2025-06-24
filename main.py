import primos
import rsa
import oaep
import hash
import json

enc_keys = []
def gerador_de_assinatura(filepath):
    # getting file content
    with open(filepath, 'rb') as f:
        msg_in_bytes = f.read()

    # getting primes and keys
    print("Gerando primos e chaves...")
    p = primos.gera_primo()
    q = primos.gera_primo()
    key_pub, key_priv = rsa.gen_rsa_key(p, q)
    enc_keys.append([key_pub, key_priv])

    # encoding...
    print("Cifrando...")
    msg_encoded = oaep.cypher(msg_in_bytes, key_pub)

    # decoding...
    print("Decifrando...")
    msg_decoded = oaep.decypher(msg_encoded, key_priv)

    # showing results...
    print("Original:", msg_in_bytes.decode('utf-8', errors='replace'))
    print("Cifrada:", hash.hash_base64(msg_encoded))
    print("Decifrada:", msg_decoded.decode('utf-8', errors='replace'))
    print("Sucesso???", msg_in_bytes == msg_decoded)

    # hashing...
    print("Hashing...")
    hash_original = hash.hash_sha3_256(msg_in_bytes)
    sig_bytes = oaep.cypher(hash_original, key_priv)
    sig_b64 = hash.hash_base64(sig_bytes)
    mensagem_b64 = hash.hash_base64(msg_in_bytes)
    signed_data = {"mensagem_base64": mensagem_b64,"assinatura": sig_b64}

    # saving signed data...
    print("Salvando...")
    with open("msg_assinada.json", "w") as f:
        json.dump(signed_data, f)

def verificador_de_assinatura(filepath):
    # getting file content
    with open(filepath, 'r') as f:
        signed_data = json.load(f)

    # getting signature and message
    mensagem_b64 = signed_data["mensagem_base64"]
    sig_b64 = signed_data["assinatura"]

    # getting fixed-length hash from signature
    sig_bytes = hash.base64_to_bytes(sig_b64)
    hash_msg_original = oaep.decypher(sig_bytes, enc_keys[0][0]) # using public key to decrypt
    print("Assinatura:", sig_b64)
    # getting fixed-length hash from message
    msg_bytes = hash.base64_to_bytes(mensagem_b64)
    msg_hash = hash.hash_sha3_256(msg_bytes)

    print("Hash obtido pela Assinatura:", hash.hash_base64(msg_hash))
    print("Hash obtido pelo conteúdo da mensagem:", hash.hash_base64(hash_msg_original))

    # showing results...
    print("Verificando assinatura:", msg_hash == hash_msg_original)

while True:
    x = input("Digite qualquer coisa para gerar uma assinatura,  ou 'sair' para sair: ")
    if x == "sair":
        break
    else:
        filepath = input("Digite o caminho do arquivo: ")
        gerador_de_assinatura(filepath)
        verificador_de_assinatura("msg_assinada.json")
    
