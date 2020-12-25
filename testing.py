import socket
import time 
import random as rd
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random

rsaKey = RSA.generate(1024)                                 # Generate RSA public and Private keys
private_key = rsaKey.export_key()                           # Export private key.
public_key = rsaKey.publickey().export_key('OpenSSH')       # Export public key. 
                                                            # Public key will be shared.
publicKey = RSA.import_key(public_key)                      # Convert RSA keys to be usable by 
privateKey = RSA.import_key(private_key)                    # Encryptors

rsaEncryptor = PKCS1_OAEP.new(publicKey)                    # RSA has separate decoder and encoders
rsaDecryptor = PKCS1_OAEP.new(privateKey)                   # Which have different keys

valu =b'\x00 \xcc\x9b\x98-\xb5\x80\xa9Px\x8e`=?\x00^\xe4r\xff\xe5kC\xf0?\xd5\xa71n\xd5\xb0\x1cP='
v = rsaEncryptor.encrypt(valu)
print(rsaDecryptor.decrypt(v))