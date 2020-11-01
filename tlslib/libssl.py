import socket as socket
import tlslib.librsa as rsa
import tlslib.libdes as des
import tlslib.ca as ca
import tlslib.libhmac as hmac
import random
import json
import time

class MySSL:
    class clientSSL:
        def __init__(self,targetPort):
            self.sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
            self.sock.connect((socket.gethostname(), targetPort))
            self.public_key=""
            self.clientRsa=rsa.MyRSA("client")

        def clientHandshake(self):
            #hello
            self.sock.send(json.dumps({
                "data":"client_hello",
                "support algorithm":["RSA"]
            }).encode('utf-8'))

            #server certificate
            msg=json.loads(self.sock.recv(65536).decode('utf-8'))
            verify_result=ca.verify(msg['crt'])
            if verify_result:
                print("[ client ]  "+msg['data'],"\npublic_key :\n",msg['crt']["Public Key"],"\ncertificate verification : ",verify_result,"\n")
            else:
                print("[ client ]  certificate failed!\n[ client ]  socket closed.\n")
                # self.sock.close()
            self.public_key=msg['crt']["Public Key"]
            
            #client certificate
            key=str(random.randint(10000000,99999999))
            with open('./client/sessionKey.des','w') as f:
                f.write(key)

            encryptedKey=self.clientRsa.encrypt(key,self.public_key)
            if msg["certificate request"]==0:
                self.sock.send(json.dumps({
                    "crypto algorithm":"des",
                    "data":encryptedKey
                }).encode('utf-8'))

            #finish
            self.hmac=hmac.MyHMAC("client")
            msg=json.loads(self.sock.recv(65536).decode('utf-8'))
            if msg["ChangeCipherSpec"]==1:
                msg=self.hmac.verify(msg)
                if msg['data']!="":
                    print("[ client ]  "+msg['data']+"\n")
                else:
                    print("[ client ]  server msg verify failed!\n[ client ]  socket closed.\n")
                    self.sock.close()

            msg={
                "ChangeCipherSpec":1,
                "data":"client finish_handshake"
            }
            self.sock.send(json.dumps(self.hmac.encrypt_sign(msg)).encode('utf-8'))
            
        def clientSend(self,msg):
            msg={
                "data":msg
            }
            self.sock.send(json.dumps(self.hmac.encrypt_sign(msg)).encode('utf-8'))

        def clientRecv(self):
            msg=json.loads(self.sock.recv(65536).decode('utf-8'))
            msg=self.hmac.verify(msg)
            if msg['data']!="":
                print("[ client ]  "+msg['data']+"\n")
                return True,msg['data']
            else:
                print("[ client ]  server msg verify failed!\n[ client ]  socket closed.\n")
                self.sock.close()
                return False,""

    class serverSSL:
        def __init__(self,listenPort):
            self.sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
            self.sock.bind((socket.gethostname(), listenPort))
            self.sock.listen(5)
            self.clientSocket=None

            self.serverRsa=rsa.MyRSA("server")

        def serverHandshake(self):
            #1st handshake
            self.clientSocket,addr=self.sock.accept()      
            msg=json.loads(self.clientSocket.recv(65536).decode('utf-8'))
            algorithm=msg["support algorithm"][0]
            print("[ server ]  "+msg['data']+"\nalgorithm:"+algorithm+"\n")

            #server certificate
            crt={
                "Subject":"tlsServer",
                "Public Key":ca.getPublicKey(self.serverRsa)
            }

            crt=ca.getCa(crt)
            with open("./server/ca.json","w") as f:
                f.write(json.dumps(crt))
            with open("./server/ca.json","r") as f:
                crt=json.loads(f.read())

            print("check",ca.verify(crt))
            self.clientSocket.send(json.dumps({
                "data":"server_hello",
                "crt":crt,
                "certificate request":0,
                "algorithm":algorithm
            }).encode('utf-8'))

            #client certificate
            msg=json.loads(self.clientSocket.recv(65536).decode('utf-8'))
            if msg["crypto algorithm"]=="des":
                key=self.serverRsa.decrypt(msg["data"])
                print("[ server ]  change sessionKey\nkey : "+key+"\n")

            with open("./server/sessionKey.des","w") as f:
                f.write(key)

            #finish
            self.hmac=hmac.MyHMAC("server")
            msg={
                "ChangeCipherSpec":1,
                "data":"server finish_handshake"
            }
            self.clientSocket.send(json.dumps(self.hmac.encrypt_sign(msg)).encode('utf-8'))

            msg=json.loads(self.clientSocket.recv(65536).decode('utf-8'))
            if msg["ChangeCipherSpec"]==1:
                msg=self.hmac.verify(msg)
                if msg['data']!="":
                    print("[ server ]  "+msg['data']+"\n")
                else:
                    print("[ server ]  client msg verify failed!\n[ server ]  socket closed.\n")
                    self.clientSocket.close()

        def serverSend(self,msg): 
            msg={
                "data":msg
            }
            self.clientSocket.send(json.dumps(self.hmac.encrypt_sign(msg)).encode('utf-8'))

        def serverSecv(self):
            msg=json.loads(self.clientSocket.recv(65536).decode('utf-8'))
            msg=self.hmac.verify(msg)
            if msg['data']!="":
                print("[ server ]  "+msg['data']+"\n")
                return True,msg['data']
            else:
                print("[ server ]  client msg verify failed!\n[ server ]  socket closed.\n")
                self.clientSocket.close()
                return False,""


    def __init__(self,subject,port):
        self.subject=subject

        if self.subject=="client":
            self.ssl=self.clientSSL(port)

        elif self.subject=="server":
            self.ssl=self.serverSSL(port)

    #return True if verification finished successfully else return False
    def handshake(self):
        if self.subject=="client":
            return self.ssl.clientHandshake()
        elif self.subject=="server":
            return self.ssl.serverHandshake()

    #return msg recieved from other side
    def sendMsg(self,msg):
        if self.subject=="client":
            return self.ssl.clientSend(msg)
        elif self.subject=="server":
            return self.ssl.serverSend(msg)

    #return True & data if verified successfully else False & None
    def recvMsg(self):
        if self.subject=="client":
            return self.ssl.clientRecv()
        elif self.subject=="server":
            return self.ssl.serverSecv()
