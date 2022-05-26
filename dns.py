# UDP max of 512 bytes messages
# DNS headers are 12 byte long

# +---------------------+
# |        Header       |
# +---------------------+
# |       Question      | the question for the name server
# +---------------------+
# |        Answer       | RRs answering the question
# +---------------------+
# |      Authority      | RRs pointing toward an authority
# +---------------------+
# |      Additional     | RRs holding additional information
# +---------------------+

# Header section format
#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      ID                       | Transaction ID
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
# |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   | FLAGS
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    QDCOUNT                    | 4-6
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ANCOUNT                    | 6-8
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+ 
# |                    NSCOUNT                    | 8-10
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                    ARCOUNT                    | 10-12
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


# Question section format (question)
#                                 1  1  1  1  1  1
#     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                                               |
# /                     QNAME                     /     
# /                                               /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QTYPE                     |     
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     QCLASS                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


# Resource record format 
#     0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                                               |
# /                                               /     
# /                      NAME                     /
# |                                               |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      TYPE                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                     CLASS                     |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                      TTL                      | 
# |                                               |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
# |                   RDLENGTH                    |
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
# /                     RDATA                     /
# /                                               /
# +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


import socket 
import sys #for sys arguments
import random #Inorder to generate a transactionID
import platform #To get infromation on the users OS
import subprocess #To ping a server for the RTT algo
import csv #To work with the cash
from datetime import datetime, timedelta #Calculate if answer are still valid
from ast import literal_eval #Data in cash is stored as a string, this lib helps us turn that string back to its orignal data type


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #Use UDP

PORT = 53
ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")

IP_LIST = []

def extractAnswer(data, domainName):
    resultWithTTL = []
    list = []

    headerSectionLenght = 12
    questionSectionLenght = len(domainName) + 2 + 4 # 2 comes from the 2 bytes expresing the data and label lenght google.com = 6google3com
    currentBytePointer = headerSectionLenght + questionSectionLenght

    ancount = int.from_bytes(data[6:8], "big")
    for i in range(ancount):
        currentBytePointer += 2 #skip name
        type = int.from_bytes(data[currentBytePointer: currentBytePointer + 2], "big")
        currentBytePointer += 4
        TTL = int.from_bytes(data[currentBytePointer: currentBytePointer + 4], "big")
        currentBytePointer += 4
        rdLenght = int.from_bytes(data[currentBytePointer: currentBytePointer + 2], "big")
        currentBytePointer += 2

        if(type == 1):
            b = data[currentBytePointer: currentBytePointer + rdLenght]
            ip = ""
            for byte in b:
                if byte == b[-1]:
                    ip += str(byte)
                    list = [ip, TTL]
                    resultWithTTL.append(list)
                else:
                    ip += str(byte) + "."

        if(type == 15):
            b = data[currentBytePointer: currentBytePointer + rdLenght]
            priority = int.from_bytes(b[ :2], "big")
            nameLenght = int.from_bytes(b[2:3], "big")
            mxCounter = 2

            # print(nameLenght)
            
            # print(b[mxCounter  : mxCounter + nameLenght])
            # print(b[mxCounter + nameLenght ])

            addr = ''
            while(nameLenght != 192):
                addr += b[mxCounter+1:mxCounter+1+nameLenght].decode("utf-8") + "."
                mxCounter += nameLenght+1
                nameLenght = b[mxCounter]

  
            completeDomainName = addr + domainName
            list = [str(priority) + " " + completeDomainName, TTL]
            resultWithTTL.append(list)

        currentBytePointer += rdLenght

    
    return resultWithTTL

def extractRR(data, domainName):
    headerSectionLenght = 12  
    questionSectionLenght = len(domainName) + 2 + 4 # 2 comes from the 2 bytes expresing the data and label lenght google.com = 6google3com
    currentBytePointer = headerSectionLenght + questionSectionLenght
    
    nsCount = int.from_bytes(data[8:10], "big")
    arCount = int.from_bytes(data[10:12], "big")
    for i in range(nsCount):
        currentBytePointer += 10 #10 is the size of name,type,class,rdlenght combined of the Resource record
        rdLenght = int.from_bytes(data[currentBytePointer: currentBytePointer + 2], "big")
        currentBytePointer += rdLenght + 2 #2 to skip rdatalenght itself
       
    for i in range(arCount):
        currentBytePointer += 2 #skip name
        type = int.from_bytes(data[currentBytePointer: currentBytePointer + 2], "big")
        currentBytePointer += 8 
        rdLenght = int.from_bytes(data[currentBytePointer: currentBytePointer + 2], "big")
        currentBytePointer += 2

        if(type == 1):
            b = data[currentBytePointer: currentBytePointer + rdLenght]
            result = ""
            for byte in b:
                if byte == b[-1]:
                    result += str(byte)
                    IP_LIST.append(result)
                else:
                    result += str(byte) + "."

        currentBytePointer += rdLenght
    
def nameToBytes(lenght, name):
    for letter in name:
        lenght += int(ord(letter)).to_bytes(1,"big")
    return lenght

def sendQuerry(querry, ip):
    addr = (ip,  PORT)
    try:
        sock.sendto(querry, addr)
        data, idk = sock.recvfrom(4096)
    except Exception as e:
        print("Error: ", e.__class__, " occurred.")
    return data

def constructQuerry(name_address, qType):
    #First two bytes are the TransactionI
    #Flags are split up over 2 bytes

    # The first byte stores 
    # QR - 1bit (Is this a query or response) 
    # OPCODE - 4 bits (Taken from ogirginal  query (What type of querry)) 
    # AA - 1 bit (Authoritative Answer, doesnt matter in this case since we dont serve) 
    # TC - 1 bit (Truncated, aka was it longer than 512 bytes) 
    # RD - 1 bit (Recursion Desired, are we ressposnible for finding an asnwer) 

    # The second byte stores 
    # RA - 1 bit (Recursion Available) 
    # Z - 3 bits (Always zero, reserved for future) 
    # RCODE - 4 bits (Response code, was there an error) 

    TID = transactionID.to_bytes(2, "big")
    QR = '0'  #query
    OPCODE = f'{0:04b}' #Standard query
    AA = '0' #We dont handle zones
    TC = '0' #No message of ours will be longer that 512bytes
    RD = '0' #We want to do the recursion ourself

    RA = '0'
    Z = f'{0:03b}'
    RCODE = f'{0:04b}'

    byte1 = int(int(QR + OPCODE + AA + TC + RD, 2)).to_bytes(1,"big")
    byte2 = int(int(RA+Z+RCODE, 2)).to_bytes(1,"big")
    flags = byte1 + byte2
    
    QDCOUNT = int(1).to_bytes(2,"big")
    ANCOUNR = int(0).to_bytes(2,"big")
    NSCOUNT = int(0).to_bytes(2,"big")
    ARCOUNT = int(0).to_bytes(2,"big")

    parsedDomainame = name_address.split('.')
    nameLenght = len(parsedDomainame[0]).to_bytes(1, "big")
    labelLenght = len(parsedDomainame[1]).to_bytes(1, "big")

    firstPart = nameToBytes(nameLenght, parsedDomainame[0])
    secondPart = nameToBytes(labelLenght, parsedDomainame[1]) + bytes(b'\x00')

    if(qType == "MX"):
        type = 15
    else:
        type = 1
    TYPE = int(type).to_bytes(2,"big") #A or #MX
    CLASS = int(1).to_bytes(2,"big") #in

    data = TID + flags + QDCOUNT + ANCOUNR + NSCOUNT + ARCOUNT + firstPart + secondPart + TYPE + CLASS
    return data

#https://stackoverflow.com/questions/29878003/python-ping-response-time
def roundTripTime(ipList):
    fastestServer = ""
    fastestTime = 0

    try:
        for ip in ipList:
            #ping a server
            parameter = '-n' if platform.system().lower()=='windows' else '-c'
            command = ['ping', parameter, '1', ip]
            result = subprocess.run(command, text=True,capture_output=True)

            #extraxt time
            start = result.stdout.find("time=") + len("time=")
            end = result.stdout.find(" ms")
            substring = result.stdout[start:end]

            #comapre to best time
            if(float(substring) > fastestTime):
                fastestTime = float(substring)
                fastestServer = ip

        return(fastestServer)
    except Exception as e:
        print("Error: ", e.__class__, " occurred.")

def resolver(domainName, qType):
    global transactionID
    transactionID = random.getrandbits(16) #random 12 bit number
    serverIP = roundTripTime(ROOT_SERVERS) #pick rootserver
    IP_LIST.append(serverIP)

    while (len(IP_LIST) > 0):
        ip = IP_LIST.pop()
        querry = constructQuerry(domainName, qType)
        response = sendQuerry(querry, ip)

        answerCount = int.from_bytes(response[6:8], "big")
        if(answerCount > 0):
            answerWithTTL = extractAnswer(response, domainName)
            return(answerWithTTL)    
        else:
            extractRR(response, domainName) #Get the next set of ips
    return False

def storeInCash(domainName,data, qType, dateCaptured):
    fieldname = ["hostName","type","data","dateCaptured"]
    row = {"hostName": domainName, "type": qType, "data":data, "dateCaptured": dateCaptured}
   
    with open('cash.csv','a',newline='') as csv_file:
        csv_writer = csv.DictWriter(csv_file, fieldnames=fieldname)
        csv_writer.writerow(row)
        csv_file.close()

def rewriteCash(list):
    fieldname = ["hostName","type","data","dateCaptured"]
    with open('cash.csv','w') as csv_file:
        csv_writer = csv.DictWriter(csv_file, fieldnames=fieldname)
        csv_writer.writeheader()
        for i in range(len(list)):
            row = {"hostName": list[i]["hostName"], "type": list[i]["type"], "data":list[i]["data"], "dateCaptured": list[i]["dateCaptured"]}
            csv_writer.writerow(row)
        csv_file.close()

def findInCash(domainName, qType):
    rewriteList = []
    result = []
    rewrite = False
    found = False

    with open('cash.csv','r') as csv_file:
        csv_reader = csv.DictReader(csv_file)
        
        for line in csv_reader:
            rewriteList.append(line)
            if(line['hostName'] == domainName and line['type'] == qType):              
                data = line['data']
                data = literal_eval(data) #convert string to list type
                dataLenght = int(len(data))
                for i in range(len(data)):
                    subdata = data[i]
                    TTL = subdata[1] #stands for time to live 
                    dateCaptured = datetime.strptime(line['dateCaptured'], '%Y-%m-%d %H:%M:%S')
                    discardDate = dateCaptured + timedelta(seconds = int(TTL))

                    if(datetime.now() < discardDate): #if IP still valid
                        result.append(subdata[0])
                        found = True
                    else:
                        rewriteList = rewriteList[:-1] #delete current line, since it contains outdated information
                        rewrite = True

        if(rewrite == True):
            rewriteCash(rewriteList)
            return False
        elif(found == False):
            return False
        else:
            if(len(result) > 1):
                return result[ :dataLenght]
            return result
        
if __name__ == '__main__':
    name = sys.argv[1]
    querryType = sys.argv[2]
    currentTime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    found = findInCash(name, querryType)
    if(found is not False):
        print("From cash: " + str(found))
    else:
        result = resolver(name, querryType)
        iplist = []
        if(result is False):
            print("Ip could not be found")
        else:
            for ip, tll in result: #remove ttl
                iplist.append(ip)

            print("From server: " + str(iplist))
            storeInCash(name,result,querryType,currentTime)
    