from primos import gera_primo
from math import gcd

def find_mod_inv(a, m): # ref: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
    old_r, r = a, m
    old_s, s = 1, 0
    old_t, t = 0, 1

    while(r!=0):
        quotient = (old_r//r)
        old_r, r = r, (old_r-(quotient*r))
        old_s, s = s, (old_s-(quotient*s))
        old_t, t = t, (old_t-(quotient*t))

    if(r!=1):
        return None
    else:
        return t%m

from primos import gera_primo
from math import gcd

def find_mod_inv(a, m): # ref: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
    old_r, r = a, m
    old_s, s = 1, 0
    old_t, t = 0, 1

    while(r!=0):
        quotient = (old_r//r)
        old_r, r = r, (old_r-(quotient*r))
        old_s, s = s, (old_s-(quotient*s))
        old_t, t = t, (old_t-(quotient*t))

    if old_r != 1:
        return None
    else:
        return old_s % m  # Corrigido: deve retornar old_s, não t

def gen_rsa_key(prime1, prime2): # ref: https://pt.wikipedia.org/wiki/RSA_(sistema_criptogr%C3%A1fico)#Implementa%C3%A7%C3%A3o
    n = prime1 * prime2
    phi = (prime1 - 1) * (prime2 - 1)

    # Começar com e = 3 e encontrar um valor coprimo com phi
    e = 3
    while gcd(e, phi) != 1:
        e += 2  # Incrementar por 2 para manter ímpar
    
    # Agora que temos um e coprimo com phi, calcular d
    d = find_mod_inv(e, phi)
    
    if d is None:
        print("Falha em achar inverso modular... trying again...")
        new_prime1 = gera_primo()
        new_prime2 = gera_primo()
        return gen_rsa_key(new_prime1, new_prime2)

    key_pub = [n, e]
    key_priv = [n, d]

    return [key_pub, key_priv]

def rsa_encrypt(msg, key_pub):
    n = key_pub[0]
    e = key_pub[1]

    return pow(msg, e, n)

def rsa_decrypt(msg_encrypted, key_priv):
    n = key_priv[0]
    d = key_priv[1]

    return pow(msg_encrypted, d, n)

