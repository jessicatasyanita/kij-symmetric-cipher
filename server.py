
import socket
import threading
import os
from Crypto.Cipher import AES
import base64
import sys

key = "This is a key123"
iv = "This is an IV456"
# obj = AES.new(key, AES.MODE_CBC, iv)
obj = AES.new('This is a key123'.encode("utf8"), AES.MODE_CBC, 'This is an IV456'.encode("utf8"))

def RetrFile(name, sock):
    lineNo = 0
    filename = sock.recv(1024)
    if os.path.isfile(filename):
        sock.send("EXISTS " + str(os.path.getsize(filename)))
        fileSize = int(os.path.getsize(filename))
        userResponse = sock.recv(1024)
        if userResponse[:2] == 'OK':
            with open(filename, 'rb') as f:
                totalSent = 0
                bytesToSend = f.read(1024)
                print(lineNo," original Data:",bytesToSend)
                lineNo += 1
                totalSent += 1024
                sock.send(bytesToSend)
                print("{0:.2f}".format((totalSent/float(fileSize))*100)+ "% Done")
    
                while (fileSize - totalSent) >= 1024 and totalSent < fileSize:
                    
                    bytesToSend = f.read(1024)
                    encryptedData = obj.encrypt(bytesToSend)
                    sock.send(encryptedData)
                    totalSent += 1024
                    print("{0:.2f}".format((totalSent/float(fileSize))*100)+ "% Done")
            
                if (fileSize - totalSent) < 1024 and totalSent < fileSize:
                    
                    bytesToSend = f.read(1024)
                    sock.send(bytesToSend)
                    totalSent += (fileSize - totalSent)
                    print("{0:.2f}".format((totalSent/float(fileSize))*100)+ "% Done")
                
                print("File Transfer Completed")
                
        sock.close()
    else:
        sock.send("ERR ")

    sock.close()

def Main():
    host = ''
    port = 8080

    s = socket.socket()
    s.bind((host,port))
    s.listen(5)

    print ("Server Listening on Port:", port)
    while True:
        c, addr = s.accept()
        print("client connedted ip:<" + str(addr) + ">")
        t = threading.Thread(target=RetrFile, args=("RetrThread", c))
        t.start()

    s.close()

if __name__ == '__main__':
    Main()
