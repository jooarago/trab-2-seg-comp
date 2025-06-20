import primos
import rsa
import oaep

def teste_rsa_oaep_txt(filepath):
    # getting file content
    with open(filepath, 'rb') as f:
        msg_in_bytes = f.read()

    # getting primes and keys
    print("Gerando primos e chaves...")
    p = primos.gera_primo()
    q = primos.gera_primo()
    key_pub, key_priv = rsa.gen_rsa_key(p, q)

    # encoding...
    print("Cifrando...")
    msg_encoded = oaep.cypher(msg_in_bytes, key_pub)

    # decoding...
    print("Decifrando...")
    msg_decoded = oaep.decypher(msg_encoded, key_priv)

    # showing results...
    print("Original:", msg_in_bytes.decode('utf-8', errors='replace'))
    print("Decifrada:", msg_decoded.decode('utf-8', errors='replace'))
    print("Sucesso???", msg_in_bytes == msg_decoded)

teste_rsa_oaep_txt("teste.txt")