
import socket
from Crypto.Cipher import AES
import base64
import sys

# from psutil import long

key = "This is a key123"
iv = "This is an IV456"
# obj = AES.new(key, AES.MODE_CBC, iv)
obj = AES.new('This is a key123'.encode("utf8"), AES.MODE_CBC, 'This is an IV456'.encode("utf8"))

def Main():
    
    if len(sys.argv) < 3:
        print("Please Enter IP Address and Port Number")
        # print(sys.argv)
        # return
    
    # host = sys.argv[1]
    # print(host)
    host = '0.0.0.0'
    # port = int(sys.argv[2])
    # print(port)
    port = 8080
    
    s = socket.socket()
    s.connect((host, port))
    lineNo = 1

    filename = input("Filename? -> ")
    if filename != 'q':
        s.send(filename)
        data = s.recv(1024)
        if data[:6] == 'EXISTS':
            fileSize = int(data[6:])
            message = input("File exists, " + str(fileSize) +" Bytes, download? (Y/N)? -> ")
            if message == 'Y':
                s.send("OK")
                f = open('new_'+filename, 'wb')
                data = s.recv(1024)
                totalRecv = len(data)
                lineNo += 1
                f.write(data)
                print("{0:.2f}".format((totalRecv/float(fileSize))*100)+ "% Done")
                
                while (fileSize - totalRecv) >= 1024:
                
                    data = s.recv(1024)
                    originalData = obj.decrypt(data)
                    totalRecv += 1024
                    lineNo += 1
                    f.write(originalData)
                    print("{0:.2f}".format((totalRecv/float(fileSize))*100)+ "% Done")
                
                if (fileSize - totalRecv) < 1024 and totalRecv < fileSize:
                
                    data = s.recv(1024)
                    totalRecv += (fileSize - totalRecv)
                    f.write(data)
                    print("{0:.2f}".format((totalRecv/float(fileSize))*100)+ "% Done")
            
                print("{0:.2f}".format((totalRecv/float(fileSize))*100)+ "% Done")
                print("Download Completed")
                f.close()
        else:
            print("File Does Not Exist!")
    s.close()


if __name__ == '__main__':
    Main()
