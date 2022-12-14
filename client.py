import socket
import os
import pyAesCrypt
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Hash import SHA
import sys
import time
import io
from Crypto import Random
from base64 import *
from aes_cfb import AES_CFB_ENC, AES_CFB_DEC, b64encode, pad, unpad

# define ip and port
HOST = 'localhost'
PORT = 8080
# socket configuration
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

# set buffersize and password for client-server encryption
bufferSize = 1024
password = 'kijc-its-2022'

# do data encryption for client-server


def encryptData(msg):
    pbdata = str.encode(msg)
    fileInput = io.BytesIO(pbdata)
    fileCipher = io.BytesIO()
    pyAesCrypt.encryptStream(fileInput, fileCipher, password, bufferSize)
    dataToSend = fileCipher.getvalue()
    return dataToSend

# do data decryption for client-server


def decryptData(msg):
    fileCipher = io.BytesIO()
    fDec = io.BytesIO()

    fileCipher = io.BytesIO(msg)
    ctlen = len(fileCipher.getvalue())
    fileCipher.seek(0)

    pyAesCrypt.decryptStream(fileCipher, fDec, password, bufferSize, ctlen)
    decrypted = str(fDec.getvalue().decode())
    return decrypted

# do file encryption with AES


def encryptFileAES(filename):
    start = time.time()
    blockSize = 64*1024
    outputFile = "(aes)"+filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)
    key = b'0123456789ABCDEF'
    encryptor = AES.new(key, AES.MODE_CBC, IV)

    # read binary
    with open(filename, 'rb') as inFile:
        # write binary
        with open(outputFile, 'wb') as outFile:
            outFile.write(filesize.encode('utf-8'))
            outFile.write(IV)
            while True:
                block = inFile.read(blockSize)
                if len(block) == 0:
                    break
                elif len(block) % 16 != 0:
                    block += b' '*(16-(len(block) % 16))
                outFile.write(encryptor.encrypt(block))

                # make new file for base64
                base64_fileName = "base64_aes_" + filename
                f = open(base64_fileName, "a")
                base64_file = (b64encode(encryptor.encrypt(block)))
                f.write(str(base64_file))
                f.close()

    end = time.time()
    runtime = (end-start) * 10**3
    try:
        return 'Encryption process for file ' + filename + ' complete.\n' + 'execution time ' + str(runtime) + 'ms.\n'
    except:
        return 'Oops! There is an error while encrypting.\n'

# decrypt file AES


def decryptFileAES(filename):
    start = time.time()
    blockSize = 64*1024
    outputFile = "(dec)" + filename

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(16)
        key = b'0123456789ABCDEF'
        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                block = infile.read(blockSize)

                if len(block) == 0:
                    break

                outfile.write(decryptor.decrypt(block))

            outfile.truncate(filesize)

    end = time.time()
    runtime = (end - start) * 10**3
    try:
        return 'Decryption process for file ' + filename + ' complete.\n' + 'execution time ' + str(runtime) + 'ms.\n'
    except:
        return 'Oops! There is an error while decrypting.\n'

# Encrypt file DES


def encryptFileDES(filename):
    start = time.time()
    blockSize = 64*1024
    outputFile = "(des)"+filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(8)
    key = b'kijc2022'
    encryptor = DES.new(key, DES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                block = infile.read(blockSize)

                if len(block) == 0:
                    break
                elif len(block) % 16 != 0:
                    block += b' '*(16-(len(block) % 16))

                outfile.write(encryptor.encrypt(block))

                # make new file for base64
                base64_fileName = "base64_des_" + filename
                f = open(base64_fileName, "a")
                base64_file = (b64encode(encryptor.encrypt(block)))
                f.write(str(base64_file))
                f.close()

    end = time.time()
    runtime = (end - start) * 10**3
    try:
        return 'Encryption process for file ' + filename + ' complete.\n' + 'execution time ' + str(runtime) + 'ms.\n'
    except:
        return 'Oops! There is an error while encrypting.\n'

# Decrypt file DES


def decryptFileDES(filename):
    start = time.time()
    blockSize = 64*1024
    outputFile = "(dec)" + filename

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(8)
        key = b'kijc2022'
        decryptor = DES.new(key, DES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                block = infile.read(blockSize)

                if len(block) == 0:
                    break

                outfile.write(decryptor.decrypt(block))

            outfile.truncate(filesize)

    end = time.time()
    runtime = (end - start) * 10**3
    try:
        return 'Decryption process for file ' + filename + ' complete.\n' + 'execution time ' + str(runtime) + 'ms.\n'
    except:
        return 'Oops! There is an error while decrypting.\n'

# encrypt file RC4


def encryptFileRC4(filename):
    start = time.time()
    chunksize = 64*1024
    outputFile = "(rc4)"+filename
    filesize = str(os.path.getsize(filename)).zfill(16)

    key = b'Very long and confidential key'
    nonce = os.urandom(16)
    tempkey = SHA.new(key+nonce).digest()
    encryptor = ARC4.new(tempkey)

    with open(filename, 'rb') as infile:  # rb means read in binary
        with open(outputFile, 'wb') as outfile:  # wb means write in the binary mode
            outfile.write(filesize.encode('utf-8'))
            outfile.write(nonce)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' '*(16-(len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))
                # make new file for base64
                base64_fileName = "base64_rc4_" + filename
                f = open(base64_fileName, "a")
                base64_file = (b64encode(encryptor.encrypt(chunk)))
                f.write(str(base64_file))
                f.close()

    end = time.time()
    runtime = (end - start) * 10 ** 3
    try:
        return 'Encryption process for file ' + filename + ' complete.\n' + 'execution time ' + str(runtime) + 'ms.\n'
    except:
        return 'Oops! There is an error while encrypting.\n'

# decrypt file RC4


def decryptFileRC4(filename):
    start = time.time()
    chunksize = 64*1024
    outputFile = "(dec)" + filename

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        key = b'Very long and confidential key'
        nonce = infile.read(16)
        tempkey = SHA.new(key+nonce).digest()
        decryptor = ARC4.new(tempkey)
        # decryptor= DES.new(key, DES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(filesize)

    end = time.time()
    runtime = (end - start) * 10 ** 3
    try:
        return 'Decryption process for file ' + filename + ' complete.\n' + 'execution time ' + str(runtime) + 'ms.\n'
    except:
        return 'Oops! There is an error while decrypting.\n'

# encrypt file with AES CFB


def encryptFileAESCFB(filename):
    start = time.time()
    outputFile = "(aes_cfb)"+filename
    ivnya = '0123456789ABCDEF'
    key = '0123456789ABCDEF'

    with open(filename, 'r', encoding='utf-8') as infile:
        with open(outputFile, 'w') as outfile:
            chunk = infile.read().replace('\n', '')
            chunk = pad(str(chunk))
            aescfb_fileName = "(aes_cfb)" + filename
            f = open(aescfb_fileName, "a", encoding="utf-8")
            outfile = AES_CFB_ENC(chunk, key, ivnya)
            f.write(outfile)
            f.close()

    end = time.time()
    runtime = (end - start) * 10 ** 3
    try:
        return 'Encryption process for file ' + filename + ' complete.\n' + 'execution time ' + str(runtime) + 'ms.\n'
    except:
        return 'Oops! There is an error while encrypting.\n'

# decrypt file with AES CFB


def decryptFileAESCFB(filename):
    start = time.time()
    outputFile = "(dec)" + filename
    with open(filename, 'r', encoding='utf-8') as infile:
        ivnya = '0123456789ABCDEF'
        key = '0123456789ABCDEF'

        with open(outputFile, 'w') as outfile:
            chunk = infile.read()
            # chunk = unpad(chunk)
            f = open(outputFile, "a", encoding='utf-8')
            aescfb_file = AES_CFB_DEC(chunk, key, ivnya)
            f.write(aescfb_file)
            f.close()
            # outfile.write(format(unpad(AES_CBC_INV(chunk, key, IV))))
    end = time.time()
    runtime = (end - start) * 10 ** 3
    try:
        return 'Decryption process for file ' + filename + ' complete.\n' + 'execution time ' + str(runtime) + 'ms.\n'
    except:
        return 'Oops! There is an error while decrypting.\n'


def sendFile(sock, file):
    try:
        with open(file, 'rb') as f:
            fileData = f.read()
            # Begin sending file
            sock.sendall(fileData)
            time.sleep(1)
            sock.sendall('EOFX'.encode())
        f.close()
        return '> Download: ' + file + ' complete.\n'
    except:
        return '> Error downloading file: ' + file + '.\n'


s.sendall(encryptData('SYMMETRIC CIPHER\n'))
s.sendall(encryptData('EOFX'))

while 1:
    data = s.recv(1024)
    decrypted = decryptData(data)
    # quit program
    if decrypted == "quit":
        print('\nProcess end, thankyou!')
        break
    # do the encryption or decryption for file
    elif decrypted[:15] == "encryptFileAES " or decrypted[:15] == "decryptFileAES ":
        try:
            args = dict(e.split('=') for e in decrypted[15:].split(', '))
            if len(args['file']):
                pass
            else:
                args = 0
        except:
            args = 0
            s.sendall(encryptData('Error: invalid arguments.\n'))
        if args:
            if (decrypted[:15] == "encryptFileAES "):
                s.sendall(encryptData(encryptFileAES(args['file'])))
            if (decrypted[:15] == "decryptFileAES "):
                s.sendall(encryptData(decryptFileAES(args['file'])))
        s.sendall(encryptData('EOFX'))
    elif decrypted[:15] == "encryptFileDES " or decrypted[:15] == "decryptFileDES ":
        try:
            args = dict(e.split('=') for e in decrypted[15:].split(', '))
            if len(args['file']):
                pass
            else:
                args = 0
        except:
            args = 0
            s.sendall(encryptData('Error: invalid arguments.\n'))
        if args:
            if (decrypted[:15] == "encryptFileDES "):
                s.sendall(encryptData(encryptFileDES(args['file'])))
            if (decrypted[:15] == "decryptFileDES "):
                s.sendall(encryptData(decryptFileDES(args['file'])))
        s.sendall(encryptData('EOFX'))
    elif decrypted[:15] == "encryptFileRC4 " or decrypted[:15] == "decryptFileRC4 ":
        try:
            args = dict(e.split('=') for e in decrypted[15:].split(', '))
            if len(args['file']):
                pass
            else:
                args = 0
        except:
            args = 0
            s.sendall(encryptData(
                'Error: invalid arguments.\n'))
        if args:
            if decrypted[:15] == "encryptFileRC4 ":
                s.sendall(encryptData(encryptFileRC4(args['file'])))
            if decrypted[:15] == "decryptFileRC4 ":
                s.sendall(encryptData(decryptFileRC4(args['file'])))
        s.sendall(encryptData('EOFX'))
    elif decrypted[:18] == "encryptFileAESCFB " or decrypted[:18] == "decryptFileAESCFB ":
        try:
            args = dict(e.split('=') for e in decrypted[18:].split(', '))
            if len(args['file']):
                pass
            else:
                args = 0
        except:
            args = 0
            s.sendall(encryptData(
                'Error: invalid arguments.\n'))
        if args:
            if decrypted[:18] == "encryptFileAESCFB ":
                s.sendall(encryptData(encryptFileAESCFB(args['file'])))
            if decrypted[:18] == "decryptFileAESCFB ":
                s.sendall(encryptData(decryptFileAESCFB(args['file'])))
        s.sendall(encryptData('EOFX'))
    elif decrypted[:12] == "downloadFile":
        try:
            if os.path.isfile(decrypted[13:]):
                filemsg = sendFile(s, decrypted[13:])
                s.sendall(encryptData(filemsg))
                s.sendall(encryptData('EOFX'))
        except:
            s.sendall(encryptData('Error: file not found.\n'))
            s.sendall(encryptData('EOFX'))

    elif decrypted[:10] == 'uploadFile':
        g = open(decrypted[11:], 'wb')
        while True:
            l = s.recv(1024)
            try:
                if l.decode() == 'EOFX':
                    break
            except:
                pass
            g.write(l)
        g.close()
        s.sendall(encryptData('EOFX'))
    else:
        s.sendall(encryptData('Command Not Found\n'))

s.close()
