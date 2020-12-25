import socket
import time 
import random as rd
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
import os.path
from os import path

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
sock.settimeout(TIMEOUT)

random = Random.get_random_bytes(32)
AEScipher = AES.new(random, AES.MODE_ECB)


# rsaDecryptor = PKCS1_OAEP.new(key)
mode = 'Handshaking'
expectedACK = 0      # packet sequence number sent in the ack packet
chunks = []             # Chunks of the file
handshakeACK = True
sequenceNo = 0

#function to convert the file into chunks
def prepareChunks(filename):
    targetFile = open(filename,'r')
    while True:
        chunk = targetFile.read(252)
        if chunk == '':
            break
        chunks.append(chunk)

number_of_packets = len(chunks)
packet = toByte(2)

while True:
    try:
        if mode == 'Handshaking':
            data, user = sock.recvfrom(1024)

            #Get Public Key from server
            packet_type = data[0]
            packet_size = data[1]
            public_key = data[len(data)-212:len(data)].decode('utf-8')
            text_file   = data[2:len(data)-212].decode('utf-8')
            print('Requested file : ', text_file)
            
            if(path.exists(text_file)==False):
                print("File does not exist")
                exit(1)

            prepareChunks(text_file)

            publicKey = RSA.import_key(public_key) # Converting client public key to be used by RSA
            rsaEncryptor = PKCS1_OAEP.new(publicKey) # RSA Encryptor
            session_key = Random.get_random_bytes(32) # AES Key to be used for data encryption
            AEScipher = AES.new(session_key, AES.MODE_ECB)
            print('Session key for data encryption : ', session_key)

            # creating Packet
            packet = toByte(0) + toByte(len(session_key)) 
            packet +=session_key
            packet = rsaEncryptor.encrypt(packet) #Encrypting packet using RSA

            # sending packet to server
            unreliableSend(packet, sock, user, errRate)
            
            mode = 'DataTransfer'
        
        if mode == 'DataTransfer':
            data, user = sock.recvfrom(1024)
            data = AEScipher.decrypt(pad(data))
            packetType = data[0]
            sequenceNo = data[1]

            if packetType == 1: #ACK Packet
                if handshakeACK == True:
                    handshakeACK = False
                    print('Sending packet number : 0')
                    length = len(chunks[0])
                    packet = toByte(2) + toByte(length) + toByte(0) + chunks[0].encode('utf-8')
                    packet = AEScipher.encrypt(pad(packet))
                    unreliableSend(packet,sock,user,errRate)
                    
                elif handshakeACK == False:
                    if expectedACK == sequenceNo:
                        sequenceNo +=1
                        print('sending packet number :', sequenceNo)
                        if sequenceNo == len(chunks) :
                            print('Transmission complete')
                            exit(0)
                        length = len(chunks[sequenceNo])
                        
                        packet = toByte(2) + toByte(length) + toByte(sequenceNo) + chunks[sequenceNo].encode('utf-8')
                        packet = AEScipher.encrypt(pad(packet))

                        expectedACK = (expectedACK+1)%256
                        unreliableSend(packet, sock, user, errRate)

            elif packetType == 3:
                #fin packet
                pass
    except Exception as ex:
        packet = toByte(2)+ toByte(len(chunks[sequenceNo])) + toByte(sequenceNo) + chunks[sequenceNo].encode('utf-8')
        packet = AEScipher.encrypt(pad(packet))
        expectedACK = (expectedACK+1)%256
        unreliableSend(packet,sock,user,errRate)


        
