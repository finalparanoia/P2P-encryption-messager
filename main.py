#encoding=utf-8
import socket
import time
import configparser
import threading
import base64
import pyotp
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

#基础配置
p_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
config = configparser.ConfigParser()
config.read('config.ini')
remote_ip = config.get('remote','ip')
remote_port = int(config.get('remote','port'))
key_seed = str(config.get('key','seed'))
name = socket.gethostname()
ip = socket.gethostbyname(name)
secretKey = base64.b32encode(key_seed.encode(encoding="utf-8"))
totp = pyotp.TOTP(secretKey)

#收发
def send(data,ip,port):
#    data = data.encode("utf-8")
    p_socket.sendto(data,(ip,port))
def pre_recv(port):
    p_socket.bind((ip, port))
def recv(port):
    recv_info = p_socket.recvfrom(1024)
    recv_info = recv_info[0]
    return recv_info

#加解密
def add_to_16(text):
    if len(text.encode('utf-8')) % 16:
        add = 16 - (len(text.encode('utf-8')) % 16)
    else:
        add = 0
    text = text + ('\0' * add)
    return text
def encrypt(text):
    key = add_to_16(str(totp.now())).encode('utf-8')
    iv = key
    mode = AES.MODE_CBC
    text = add_to_16(text).encode('utf-8')
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(text)
    return b2a_hex(cipher_text)
def decrypt(text):
    key = add_to_16(str(totp.now())).encode('utf-8')
    iv = key
    mode = AES.MODE_CBC
    cryptos = AES.new(key, mode, iv)
    plain_text = cryptos.decrypt(a2b_hex(text))
    return bytes.decode(plain_text).rstrip('\0')

#输入显示
def inputtext():
    data = str(input("\n\033[0;36;40m>>>\033[0m\n"))
    data = name+"@"+ip+"\n"+"===>"+data
    data = encrypt(data)
    return data
def outputtext(recv_info):
#    data = recv_info.decode("utf-8")
    data = decrypt(recv_info)
    print("\033[4;32;40m\n["+time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+"]\033[0m")
    print("\033[0;47;40m"+data+"\033[0m")
    print("\n\033[0;36;40m>>>\033[0m")

#循环逻辑
def out_loop():
    while True:
        pre_recv(remote_port)
        while True:
            outputtext(recv(remote_port))
def in_loop():
    while True:
        data = inputtext()
        send(data,remote_ip,remote_port)

def main():
    threading._start_new_thread(out_loop,())
    in_loop()

main()
