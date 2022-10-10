import socket,os
import pyAesCrypt
from Crypto.Cipher import AES, DES
import io
from Crypto import Random
from base64 import *

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
	blockSize = 64*1024
	outputFile = "(aes)"+filename
	filesize = str(os.path.getsize(filename)).zfill(16)
	IV = Random.new().read(16)
	key = b'0123456789ABCDEF'
	encryptor = AES.new(key, AES.MODE_CBC, IV)

	#read binary
	with open(filename, 'rb') as inFile:
		#write binary 
		with open(outputFile, 'wb') as outFile:
			outFile.write(filesize.encode('utf-8'))
			outFile.write(IV)
			while True:
				block = inFile.read(blockSize)
				if len(block) == 0:
					break
				elif len(block)%16 != 0:
					block += b' '*(16-(len(block)%16))
				outFile.write(encryptor.encrypt(block))

				# make new file for base64
				base64_fileName = "base64_" + filename
				f = open(base64_fileName, "a")
				base64_file = (b64encode(encryptor.encrypt(block)))
				f.write(str(base64_file))
				f.close()
	try:
		return 'Encryption process for file ' + filename + ' complete.\n'
	except:
		return 'Oops! There is an error while encrypting.\n'

# decrypt file AES
def decryptFileAES(filename):
	blockSize = 64*1024
	outputFile = "(dec)" + filename

	with open(filename, 'rb') as inFile:
		filesize = int(inFile.read(16))
		IV = inFile.read(16)
		key = b'0123456789ABCDEF'
		decryptor= AES.new(key, AES.MODE_CBC, IV)

		with open(outputFile, 'wb') as outFile:
			while True:
				block = inFile.read(blockSize)
				if len(block) == 0:
					break
				outFile.write(decryptor.decrypt(block))
			outFile.truncate(filesize)
	try:
		return 'Decryption process for file ' + filename + ' complete.\n'
	except:
		return 'Oops! There is an error while decrypting.\n'

# Encrypt file DES
def encryptFileDES(filename):
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
				elif len(block)%16 != 0:
					block += b' '*(16-(len(block)%16))

				outfile.write(encryptor.encrypt(block))
	try:
		return 'Encryption process for file ' + filename + ' complete.\n'
	except:
		return 'Oops! There is an error while encrypting.\n'

# Decrypt file DES
def decryptFileDES(filename):
	blockSize = 64*1024
	outputFile = "(dec)" + filename

	with open(filename, 'rb') as infile:
		filesize = int(infile.read(16))
		IV = infile.read(8)
		key = b'kijc2022'
		decryptor= DES.new(key, DES.MODE_CBC, IV)

		with open(outputFile, 'wb') as outfile:
			while True:
				block = infile.read(blockSize)

				if len(block) == 0:
					break

				outfile.write(decryptor.decrypt(block))

			outfile.truncate(filesize)
	try:
		return 'Decryption process for file ' + filename + ' complete.\n'
	except:
		return 'Oops! There is an error while decrypting.\n'

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
			if len(args['file']): pass
			else: args = 0
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
	else:
		s.sendall(encryptData('Command Not Found\n'))
s.close()