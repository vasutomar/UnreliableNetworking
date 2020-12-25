import socket
import time 
import random as rd
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random

file_offset = 0
chunks = []
textfile = open('crime-and-punishment.txt','r')

while True:
    chunk = textfile.read(252)
    if chunk == '':
        break
    chunks.append(chunk)

print(len(chunks))