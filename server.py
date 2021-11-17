import socket
import time
from blowfish_algo import *
import base64
from RSA import RSA_encrypt
import pickle
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey

def send_encrypted_message(message, blowfish_object):
    encrypt_msg = b"".join(cipher.encrypt_ecb_cts(message))
    # send Blowfish encrypted message to client
    conn.send(encrypt_msg)
    # Generate and send Signature
    signature = Ecdsa.sign(message.decode(), sig_private_key)
    conn.send(pickle.dumps(signature))

def receive_message_from_client(cipher_object):
    message_from_client = ''
    while message_from_client=='':
        message_from_client = conn.recv(1024)
    decrypted_message = b"".join(cipher_object.decrypt_ecb_cts(message_from_client))
    return decrypted_message.decode()



print("\nWelcome to Chat Room\n")
print("Initializing....\n")
time.sleep(1)

s = socket.socket()
host = socket.gethostname()
ip = socket.gethostbyname(host)
port = 1234
s.bind((host, port))
print(host, "(", ip, ")\n")
name=input(str("Enter your name: "))

s.listen(1)
print("\nWaiting for incoming connections...\n")
conn, addr = s.accept()
print("Received connection from ", addr[0], "(", addr[1], ")\n")

s_name = conn.recv(1024)
s_name = s_name.decode()
print(s_name, "has connected to the chat room\nEnter [e] to exit chat room\n")
conn.send(name.encode())

# receive client's n and public key
n = int(conn.recv(1024).decode())
public_key = int(conn.recv(1024).decode())

# Blowfish key
Blowfish_key = b"admin_key"
# Send key length
key_len = len(Blowfish_key)
conn.send(str(key_len).encode())

# encrypted Blowfish key using RSA encryption with client's public key
blowfish_encrypted_key = RSA_encrypt(Blowfish_key, public_key, n)
# send encrypted Blowfish key to client
conn.send(str(blowfish_encrypted_key).encode())
cipher = Cipher(Blowfish_key)


# Generate Signature Keys
sig_private_key = PrivateKey()
sig_public_key = sig_private_key.publicKey()
# Send signature public key to client 
conn.send(pickle.dumps(sig_public_key))
# Now we can start chatting!
while True:
    message_len = 0
    while message_len<8:
        message = input(str("Me (minimum 8 chars): "))
        if message == "[e]":
            message = b"Left chat room!"
            send_encrypted_message(message,cipher)
            conn.close()
            print("\n")
            exit()
        message =message.encode()
        message_len = len(message)

    send_encrypted_message(message,cipher)
    message = receive_message_from_client(cipher)
    print('Client: ',message)

