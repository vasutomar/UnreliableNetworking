import socket
import time 
import random as rd
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
import os.path
from os import path

#find out what these do
def pad(s):
    #return s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
    return s + (16 - len(s) % 16) * bytes([(16 - len(s) % 16)])
def unpad(s):
    return s[:-ord(s[len(s) - 1:])]

# Represents integers from 0-255 in one byte
def toByte(s):
    #return chr(s).encode('utf-8')
    return bytes([s]) 
    #return bytes("\x{:02x}".format(s).encode('utf-8'))

# Returns 0-255 byte to integer
def fromByte(s):
    return ord(s)

def unreliableSend(packet, sock, user, errRate):
    if errRate < rd.randint(0,100):
        sock.sendto(packet, user)

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server
user = (HOST, PORT)
status = "Start"

errRate = 10 # Average Error rate of the unreliable channel
TIMEOUT = 0.0001 # Timeout value
N = 1 # Go-back-N N

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)     # Create UDP socket
sock.bind((HOST,PORT))

# rsaDecryptor = PKCS1_OAEP.new(key)
mode = 'Handshaking'

while True:
    try:
        if mode == 'Handshaking':
            data, user = sock.recvfrom(1024)

            #Get Public Key from server
            packet_type = data[0]
            packet_size = data[1]
            public_key = data[len(data)-212:len(data)].decode('utf-8')
            text_file   = data[2:len(data)-212].decode('utf-8')
            #print(text_file)
            #print(packet_type, ' ', packet_size, ' ', text_file, ' ', public_key)

            publicKey = RSA.import_key(public_key)
            rsaEncryptor = PKCS1_OAEP.new(publicKey)
            session_key = Random.get_random_bytes(32)

            packet = toByte(0) + toByte(len(session_key))
            packet +=session_key
            print('normal packet : ', packet)
            packet = rsaEncryptor.encrypt(packet)
            print('encrypted packet : ', packet)

            # sending to server
            unreliableSend(packet, sock, user, errRate)
            mode = 'potty'
    except Exception as ex:
        print(str(ex))


        
