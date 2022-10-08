import socket,os
import pyAesCrypt
from Crypto.Cipher import AES
import io
from Crypto import Random

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
	try:
		return 'Encryption process for file ' + filename + ' complete.\n'
	except:
		return 'Oops! There is an error while encrypting.\n'

# Decrypt file AES
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
	else:
		s.sendall(encryptData('Command Not Found\n'))
s.close()