import time

add_in_seed = 0

def seed_bigint():
    global add_in_seed
    tempo = int(time.time() * 1000) # maybe i could use just time.time()
    add_in_seed += 1  # so consecutive calls never return same seed
    return tempo + add_in_seed


def random_bigint(): # LCG algorithm
    modulus = 2**32
    multiplier = 1664525
    increment = 1013904223
    seed = seed_bigint()
    result = (seed * multiplier + increment) % modulus
    return result

def random_bigint_1024():
    res = 0
    for i in range(32):
        aux = random_bigint() << (32*i)
        res |= aux
    return res

def random_bigint_within_range(n, m):
    if n >= m:
        raise ValueError("n has to be lesser than m!")
    return n + random_bigint() % (m-n+1)


def random_bigint_1024_within_range(n, m):
    if n >= m:
        raise ValueError("n has to be lesser than m!")
    return n + random_bigint_1024() % (m - n + 1)

def fast_modular_exponentiation(base, exponent, modulus):
    res = 1
    base = base % modulus
    while exponent != 0:
        if (exponent&1) == 1:
            res = (res * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return res

def miller_rabin_test(n, d):
    a = random_bigint_within_range(2, n - 2)
    x = fast_modular_exponentiation(a, d, n)
    if x == 1 or x == n - 1:
        return True
    while d != n - 1:
        x = (x * x) % n
        d *= 2
        if x == 1:
            return False
        if x == n - 1:
            return True
    return False

def iterate_miller_rabin(n, k):
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    d = n - 1
    while d % 2 == 0:
        d //= 2
    for i in range(k):
        if not miller_rabin_test(n, d):
            return False
    return True

def gera_primo():
    while True:
        n = random_bigint_1024()
        if iterate_miller_rabin(n, 3):
            return n