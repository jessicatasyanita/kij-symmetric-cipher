import socket
import pyAesCrypt
import io

# socket configuration
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.bind(('0.0.0.0', 8080))
c.listen(1)

# set buffersize and password for client-server encryption
bufferSize = 1024
password = 'kijc-its-2022'

s,a = c.accept()

# do data encryption for client-server
def encryptData(msg):
	pbdata = str.encode(msg)
	fileInput = io.BytesIO(pbdata)
	fileCipher = io.BytesIO()
	# try use different library for AES
	pyAesCrypt.encryptStream(fileInput, fileCipher, password, bufferSize)
	dataToSend = fileCipher.getvalue()
	return dataToSend

# do data decryption for client-server
def decryptData(msg):
	# initialize
	fileCipher = io.BytesIO()
	fDec = io.BytesIO()

	fileCipher = io.BytesIO(msg)
	ctlen = len(fileCipher.getvalue())
	fileCipher.seek(0)

	pyAesCrypt.decryptStream(fileCipher, fDec, password, bufferSize, ctlen)
	decrypted = str(fDec.getvalue().decode())
	return decrypted

while True:
	# receive the data 
	data = s.recv(1024)
	try:
		decrypted = decryptData(data)
	except ValueError:
		print('> Oops! Decryption process erorr.\n')
		pass
	# check for eof or command
	if decrypted.endswith("EOFX") == True:
		# get the next command
		nextcmd = input("[command]: ")
		if nextcmd == 'quit':
			print('\nProcess end, thankyou!')
			s.send(encryptData(nextcmd))
			break
		else: s.send(encryptData(nextcmd))	
	# we haven't reached EOF, print
	else:
		print(decrypted, end = '')