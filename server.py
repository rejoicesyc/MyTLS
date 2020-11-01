import tlslib.libssl as ssl

if __name__=="__main__":
    myssl=ssl.MySSL("server",9999)
    myssl.handshake()

    while True:
        flag,data=myssl.recvMsg()

        msg=input("server > ")
        if msg=="?>" and flag==True:
            print('\n[ server ]  exit\n')
            break
        else:
            myssl.sendMsg(msg)

    