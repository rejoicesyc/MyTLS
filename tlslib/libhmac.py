from Crypto.Hash import SHA
import tlslib.libdes as des

class MyHMAC:
    def __init__(self,subject):
        self.subject=subject
        self.key="./"+self.subject+"/sessionKey.des"

    def encrypt_sign(self,msg):
        with open(self.key,"r") as f:
            key=str(f.read())

        data=msg['data']

        digest=SHA.new()
        digest.update(data.encode("utf8"))
        msg["hmac"]=digest.hexdigest()

        myDes=des.MyDES(key)
        msg['data']=myDes.encrypt(data).decode('utf-8')

        return msg 

    def verify(self,msg):
        with open(self.key,"r") as f:
            key=str(f.read())

        myDes=des.MyDES(key)
        decryptedMsg=myDes.decrypt(msg['data'])
        msg['data']=decryptedMsg

        digest=SHA.new()
        digest.update(decryptedMsg.encode("utf8"))
        hmac=digest.hexdigest()

        if hmac==msg['hmac']:
            return msg
        else:
            return ""
        
        
