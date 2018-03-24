#!/usr/bin/env python3
'''
 OMEGA release 42 coded by TRIBELLION, estd. MMXV    --  modded by sigoa in 2018

 To generate keys, enter:        python omega.py   -g <key volume in MiB>
 To encrypt files, enter:        python omega.py   -e <file or directory>
 To decrypt files, enter:        python omega.py   -d <an encrypted file>


'''
import                 time
from os         import mkdir,path
from subprocess import call
from sys        import argv,version              #    ,exit
from zipfile    import is_zipfile,ZipFile


def xor(x,y):                     # xor function for Python 2/3
    if version[0]=="2":         z="".join(chr(ord(x)^ord(y)) for(x,y) in zip(x,y))
    else:                       z=bytes(x^y for x,y in zip(x,y))
    return z






def info(mib,sec):   # statistics
    print("Processed "+str("%.3f"%float(mib))+" MiB in " + str(round(sec,3))+" s ("+str("%.3f"%float(mib/sec)) + " MiB/s)")


print("OMEGA release 42 for Python 2/3, licensed under WTFPL version 2   ")
print("(O)ne-time-pad (M)essage (E)ncryption & (G)enerator (A)lgorithm   ")
print("hosted by Cyanbyte Digital Engineering (http://www.cyanbyte.de) \n")


if path.exists("./keys/"):                                                          # status info
    sfile=open( "./keys/sys.cfg","r"); local=sfile.read(1).lower(); sfile.close()                        # with
    if local!="a" and local!="b":     exit("ERROR: Invalid local system configuration (sys.cfg)")
    if local=="a":
        print("Local system is ALPHA and remote system must be BRAVO (sys.cfg)")
        ekey="./keys/a2b.key"; elog="./keys/a2b.log"
        dkey="./keys/b2a.key"; dlog="./keys/b2a.log"
    else:
        print("Local system is BRAVO and remote system must be ALPHA (sys.cfg)")
        ekey="./keys/b2a.key"; elog="./keys/b2a.log"
        dkey="./keys/a2b.key"; dlog="./keys/a2b.log"

    evolume=path.getsize(ekey)
    dvolume=path.getsize(dkey)

    sfile=open(elog,"r"); eindex=int(sfile.read()); sfile.close()
    sfile=open(dlog,"r"); dindex=int(sfile.read()); sfile.close()

    eavail=str("%10.3f"%float((evolume-eindex)/1024.0/1024.0))
    davail=str("%10.3f"%float((dvolume-dindex)/1024.0/1024.0))

    print("Total encryption key volume available: "           +eavail+" MiB ("+ekey[-7:]+")")
    print("Total decryption key volume available: "           +davail+" MiB ("+dkey[-7:]+")")
    print("\n")

if len(argv)!=3:  # help
    print("To generate keys, enter: python omega.py -g <key volume in MiB>")
    print("To encrypt files, enter: python omega.py -e <file or directory>")
    print("To decrypt files, enter: python omega.py -d <an encrypted file>")
    exit(0)

operation=argv[1]
parameter=argv[2]









if operation=="-g":  # key generator
    try:         size=int(parameter)
    except                   :    exit("ERROR: Invalid key volume, positive integer required")
    if size<=0               :    exit("ERROR: Invalid key volume, positive integer required")
    if path.exists("./keys/"):    exit("ERROR: Cannot generate keys, directory already exists")

    started=time.time()

    print("Key generation in progress...")
    mkdir("./keys/")

    call(["dd","if=/dev/urandom","of=./keys/a2b.key",           "bs=1M","count="+str(size),"status=none"])
    call(["dd","if=/dev/urandom","of=./keys/b2a.key",           "bs=1M","count="+str(size),"status=none"])

    stopped=time.time()
    info(size+size,stopped-started)

    sfile=open("./keys/a2b.log","w"); sfile.write("0"); sfile.close()
    sfile=open("./keys/b2a.log","w"); sfile.write("0"); sfile.close()
    sfile=open("./keys/sys.cfg","w"); sfile.write("a"); sfile.close()
    exit(0)

if not path.exists("./keys/"): exit("ERROR: No keys available")









if operation=="-e":  # encryption
    if not path.isdir(parameter) and not path.isfile(parameter):         exit("ERROR: File or directory not found")

    started=time.time()
    call(["rm","-rf" ,"./data/"])
    call(["mkdir"    ,"./data/"])
    call(["zip","-qr","./data/pack.zip",parameter])
    size=path.getsize("./data/pack.zip")
    if eindex+size>evolume:
        call(["rm","-rf","./data/"])
        exit("ERROR: Available encryption key volume not sufficient")

    print("Encryption in progress...")
    sfile=open("./data/data.log","w"); sfile.write(local+str(eindex))
    sfile.close()
    sfile=open("./data/pack.zip","rb"); message=sfile.read(); sfile.close()
    sfile=open(ekey,"rb"); sfile.seek(eindex); key=sfile.read(size); sfile.close()
    sfile=open("./data/data.bin","wb"); sfile.write(xor(message,key)); sfile.close()

    call(["rm","./data/pack.zip"])
    call(["zip","-qr0","./data.zip","./data/"])
    call(["rm","-rf","./data/"])
    eindex+=size

    sfile=open(elog,"w")
    sfile.write(str(eindex))
    sfile.close()
    stopped=time.time()

    info(size/1024.0/1024.0,stopped-started)
    print("Total encryption key volume remaining: " + str("%10.3f"%float((evolume-eindex)/1024.0/1024.0)) + " MiB ("+ekey[-7:]+")")
    exit(0)





if operation=="-d":  # decryption

    if not path.isfile(parameter)    : exit("ERROR: File not found")
    call(["rm","-rf","./data/"])
    error="ERROR: File not valid"
    zippo=ZipFile(parameter,"r")

    if not is_zipfile(parameter)     : exit(error)
    if len(zippo.namelist())!=3      : exit(error)
    if zippo.namelist()[0]!="data/"  : exit(error)

    started=time.time()
    call(["unzip","-q",parameter])

    sfile=open("./data/data.log","r")
    log=sfile.read( )
    ee =sfile.close()  #  )
    remote=log[0]; dindex=int(log[1:])

    if local==remote:                                                # deadlock  A and B must be separate, like sender & receiver machine
        call(["rm","-rf","./data/"])
        exit("ERROR: Identical configuration on local/remote system (sys.cfg)")

    print("Decryption in progress...")

    size=path.getsize("./data/data.bin")

    sfile=open(        "./data/data.bin","rb");     cipher=sfile.read();                 sfile.close()
    sfile=open(dkey,"rb"); sfile.seek(dindex);         key=sfile.read(size);             sfile.close()
    sfile=open(       "./data/pack.zip","wb");             sfile.write(xor(cipher,key)); sfile.close()

    call(["rm"         ,"./data/data.bin"])
    call(["unzip","-qo","./data/pack.zip"])
    call(["rm","-rf"   ,"./data/"])
    call(["rm",parameter])

    dindex+=size; sfile=open(dlog,"w"); sfile.write(str(dindex)); sfile.close()
    stopped=time.time()
    info(size/1024.0/1024.0,stopped-started)

    print("Total decryption key volume remaining: " +str("%10.3f"%float((dvolume-dindex)/1024.0/1024.0)) + " MiB ("+dkey[-7:]+")")
    exit(0) # fine

exit("no workie: unknown options given to OMEGA or trouble while imported or sth.")
