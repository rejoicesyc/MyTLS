import tlslib.libssl as ssl

if __name__ == "__main__":
    myssl=ssl.MySSL("client",9999)
    myssl.handshake()
    flag=True

    while True:
        msg=input("client > ")
        if msg=="?>" and flag==True:
            print('\n[ client ]  exit\n')
            break
        else :
            myssl.sendMsg(msg)

        flag,data=myssl.recvMsg()
