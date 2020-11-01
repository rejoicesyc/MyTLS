from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
import base64
from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature

class MyRSA:
    def __init__(self,subject):
        self.subject=subject
        self.private_key="./"+self.subject+"/private_"+self.subject+".rsa"
        self.public_key="./"+self.subject+"/public_"+self.subject+".rsa"

        random_generator = Random.new().read
        rsa = RSA.generate(2048, random_generator)
        private_key = rsa.exportKey()
        public_key = rsa.publickey().exportKey()

        with open(self.private_key, 'wb') as f:
            f.write(private_key)
        
        with open(self.public_key, 'wb') as f:
            f.write(public_key)

    def encrypt(self,message,pub_key):
        if pub_key=="":
            with open(self.public_key,"r") as f:
                pub_key = str(f.read())
                
        pub_key = RSA.importKey(pub_key)
        cipher = PKCS1_cipher.new(pub_key)
        rsa_text = base64.b64encode(cipher.encrypt(bytes(message.encode("utf8"))))
        return rsa_text.decode('utf-8')


    def decrypt(self,rsa_text):
        with open(self.private_key,"r") as f:
            key = f.read()
            pri_key = RSA.importKey(key)
            cipher = PKCS1_cipher.new(pri_key)
            back_text = cipher.decrypt(base64.b64decode(rsa_text.encode('utf-8')), 0)
            return back_text.decode('utf-8')