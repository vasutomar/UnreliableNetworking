import socket

UDP_IP = "127.0.0.1"
UDP_PORT = 5005
MESSAGE = (b"Hello client")

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP,UDP_PORT))
while True:
    data, addr = sock.recvfrom(4096)
    sock.sendto(MESSAGE,addr)
    print(str(data))