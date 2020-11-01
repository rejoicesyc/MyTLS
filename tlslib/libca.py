from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature
import base64

class MyCa:
    def __init__(self):
        self.public_key='./ca/public_ca.rsa'
        self.private_key='./ca/private_ca.rsa'

        random_generator = Random.new().read
        rsa = RSA.generate(2048, random_generator)
        private_key = rsa.exportKey()
        public_key = rsa.publickey().exportKey()

        with open(self.private_key, 'wb') as f:
            f.write(private_key)
        
        with open(self.public_key, 'wb') as f:
            f.write(public_key)

    def signature(self,message):
        with open(self.private_key,"r") as f:
            key = f.read()
            pri_key = RSA.importKey(key)
            signer = PKCS1_signature.new(pri_key)
            digest = SHA.new()
            digest.update(message.encode("utf8"))
            sign = signer.sign(digest)
            signature_txt = base64.b64encode(sign)
            return signature_txt.decode('utf-8')

    def veritication(self,message,signature_txt):
        with open(self.public_key,"r") as f:
            key = f.read()
            pub_key = RSA.importKey(key)
            verifier = PKCS1_signature.new(pub_key)
            digest = SHA.new()
            digest.update(message.encode("utf8"))
            return verifier.verify(digest, base64.b64decode(signature_txt.encode('utf-8')))

