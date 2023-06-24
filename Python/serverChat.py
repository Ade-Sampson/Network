#Ade Sampson Project
import socket
import sys
from threading import Thread
import time
import signal
#Size of Buffer
buffer_size=8192

stop = False
port = 12000
initHello = "HELLO"
initAuth = "AUTHYES"
initAuthNo = "AUTHNO"
#List of authorized users, matched to users
knownUserName = ["test1", "test2", "test3", "ade"]
knownPassword = ["p000", "p000", "p000", "p984"]
#connectTrack keeps track of connections
connectTrack = []
#connectUser keeps track of users
connectUser = set()

# Create TCP socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error as msg:
    print("Error: could not create socket")
    print("Description: " + str(msg))
    sys.exit()

# Bind to listening port
try:
    host=''  # Bind to all interfaces
    s.bind((host,port))
except socket.error as msg:
    print("Error: unable to bind on port %d" % port)
    print("Description: " + str(msg))
    sys.exit()

# Listen
try:
    backlog=50  # Number of incoming connections that can wait
                # to be accept()'ed before being turned away
    s.listen(backlog)
except socket.error as msg:
    print("Error: unable to listen()")
    print("Description: " + str(msg))
    sys.exit()    

print("Listening socket bound to port %d" % port)

# threads running as Daemon's, will shutdown on their own when exiting
def shutDown(a,b):  
	print("Terminating threads...")
	sys.exit()
  
# function to send message
def sendM(message, s):
	raw_bytes = bytes(message,'ascii')
	try:
		bytes_sent = s.send(raw_bytes)
	except socket.error as msg:
		print("Error: send() failed")
		print("Description: " + str(msg))
		sys.exit()

#  Main threaded function
def threadedConnect(client_s):
	# Receive data
	cList = []
	authenticate = False
	deleteFromSet = True
	#parse authorization details from client
	while True:
		try:
			raw_bytes = client_s.recv(buffer_size)
			if len(raw_bytes) != 0:
				string_ascii = raw_bytes.decode('ascii')
				string_ascii.rstrip('\n')
				nString = string_ascii.split(':')
				if nString[0] == "AUTH":
					for _ in nString[1]:
						if _ == ':':
							client_s.close()
					for _ in nString[2]:
						if _ == ':':
							client_s.close()
					for i in range(len(knownUserName)):
						if nString[1] == knownUserName[i] and nString[2] == knownPassword[i]:
							authenticate = True
			if authenticate == True:
				sendM(initAuth, client_s)
				time.sleep(1)
				connectTrack.append((nString[1], client_s))#tuple ADD
				connectUser.add(nString[1])
				signIn = "SIGNIN:" + nString[1] + "\n"

				for _ in connectTrack:
					sendM(signIn, _[1])
				print("authenticate")
				break
			else:
				sendM(initAuthNo, client_s)
				print("authenticate nate")

		except:
			pass
	#after authentication, parse input from client
	while True:
		cList = ""
		try:
			raw_bytes = client_s.recv(buffer_size)
			if len(raw_bytes) != 0:
				string_ascii = raw_bytes.decode('ascii')
				mString = string_ascii.split(':')
				print(string_ascii)
				string_ascii.rstrip('\n')
				if string_ascii == "LIST":
					print(connectUser)
					for client in sorted(connectUser):
						if client == list(sorted(connectUser))[-1]:
							cList += client
						else:
							cList += client + ", "
					sendM(cList, client_s)  
				
				elif mString[0] == "TO":
					for _ in connectTrack:
						if _[0] == mString[1]:
							sendMessage = "FROM:" + nString[1] + ":" + mString[2] + "\n"
							print(sendMessage)
							sendM(sendMessage, _[1])

				elif string_ascii == "BYE":
					signOff = "SIGNOFF:" + nString[1] + "\n"
					for _ in connectTrack:
						sendM(signOff, _[1])
					try:
						client_s.close()
						for _ in connectTrack:
							if  _[1] == client_s:
								connectTrack.remove(_)

						for _ in connectTrack:
							if _[0] == nString[1]:
								deleteFromSet = False
						if deleteFromSet == True:
							connectUser.remove(nString[1])
						deleteFromSet = True
						break
					except socket.error as msg:
						print("Error: unable to close client socket.")
						print("Error: unable to close " + nString[1] + "'s socket." )
						print("Description: " + str(msg))
						sys.exit()
				
		except:
			pass



# Accept an incoming request, loop for webserver
# Signal allows for smoother shutdown
signal.signal(signal.SIGINT, shutDown)
while True:
	try:
	    (client_s, client_addr) = s.accept()
	except socket.error as msg:
	    print("Error: unable to accept()")
	    print("Description: " + str(msg))
	    sys.exit()

	print("Accepted incoming connection from client")
	print("Client IP, Port = %s" % str(client_addr))
	

	try:
		raw_bytes = client_s.recv(buffer_size)
	except socket.error as msg:
		print("Trying to get bytes")
		print("Error: unable to recv()")
		print("Description: " + str(msg))
		sys.exit()
    
	time.sleep(1)
	string_ascii = raw_bytes.decode('ascii')
	print(string_ascii)
	if string_ascii != "HELLO":
		print("this exit")
		sys.exit()
	# Send initial HELLO to client
	sendM(initHello, client_s)

	thread = Thread(target=threadedConnect, args=[client_s], daemon = True)
	thread.start()
	




# Close both sockets
try:
    #client_s.close()
    s.close()
except socket.error as msg:
    print("Error: unable to close() socket")
    print("Description: " + str(msg))
    sys.exit()

print("Sockets closed, now exiting")

