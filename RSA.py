import libnum
import random


bits_length = 56  # number of bits to match key length

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def get_keys():
    
    #p = Crypto.Util.number.getPrime(bits, randfunc=get_random_bytes)
    #q = Crypto.Util.number.getPrime(bits, randfunc=get_random_bytes)
    p = libnum.generate_prime(bits_length)
    q= libnum.generate_prime(bits_length)
    n = p * q
    PHI = (p - 1) * (q - 1)

    e = 65537    
    #Use Euclid's Algorithm to verify that e and phi(n) are comprime
    g = gcd(e, PHI)
    while g != 1:
        e = random.randrange(1, PHI)
        g = gcd(e, PHI)

    d = libnum.invmod(e, PHI)
        #  public, private, n
    return d, e, n

# string -> byte[] -> int
# 

def RSA_encrypt(message_bytes, public_key, n):
    return pow(int.from_bytes(message_bytes,"big"), public_key, n)


def RSA_decrypt(cypher_int, private_key, n):
    return pow(cypher_int, private_key, n)

'''def RSA_encrypt(plaintext:str, public_key, n):
    cipher = [(ord(char) ** public_key) % n for char in plaintext]
    return cipher


def RSA_decrypt(ciphertext, private_key, n):
    plain = [chr((char ** private_key) % n) for char in ciphertext]
    return ''.join(plain)'''

def test_for_RSA():    
    public, private, n = get_keys()
    print(int.from_bytes(b"Hi there",'big'))
    enc = RSA_encrypt(b"Hi there",public,n)
    print(enc)
    print(int.to_bytes(RSA_decrypt(enc,private,n),length=8,byteorder ='big').decode())
#test_for_RSA()