import tlslib.libca as ca  

def getCa(crt):
    crt["Issuer"]="GlobalSign CA"
    crt["Valid from"]="2020/1/1"
    crt["Valid to"]="2020/12/30"
    crt["Signature algorithm"]="SHA1"
    crt["Thumbprint algorithm"]="RSA"

    msg=""
    for key,value in crt.items():
        msg+=value
    crt["Thumbprint"]=myCa.signature(msg)

    return crt

def verify(crt):
    if crt["Signature algorithm"]=="SHA1" and crt["Thumbprint algorithm"]=="RSA":
        msg=""
        for key,value in crt.items():
            if key!="Thumbprint":
                msg+=value
        return myCa.veritication(msg,crt["Thumbprint"])
    else:
        return False

def getPublicKey(serverRsa):
    with open(serverRsa.public_key,"r") as f:
        return str(f.read())


myCa=ca.MyCa()
