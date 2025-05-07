import os
import pyshark
import numpy as np

def main():
    print("This script will automatically perform the processing of a pcap file to encode it in a form suitable for multivariate HMM.")
    files = getFiles()
    encodeAndSave(files)

def getFiles():
    endloop = False;
    inputAndOutputFiles = {}

    while (endloop == False):
        endloopinput = getUserInput("Enter a file path to add a file, or enter Finish to finish adding files.")
        if endloopinput == "Finish":
            endloop = True
        else:
            inputfile = getInputFile(endloopinput)
            print("File saved")
            outputfile = getOutputFile()
            inputAndOutputFiles[inputfile] = outputfile
        for key in inputAndOutputFiles:
            print(key.name + " will be encoded and saved to " + inputAndOutputFiles[key])
    return inputAndOutputFiles

def getInputFile(filepath):
    if filepath == "none":
        filepath = getUserInput("Enter absolute filepath")
        checkfileexists(filepath)
        file = loadFile(filepath)
    else: 
        checkfileexists(filepath, "pcap")
        file = loadFile(filepath)
    return file

def getOutputFile():
    filepath = getUserInput("Where to save encoded data? Provide absolute path to .txt file (The file will be created if it does not yet exist)")
    checkfileexists(filepath, "txt")
    return filepath

def checkfileexists(filepath, type):
    if type == "pcap":
        if os.path.isfile(filepath):
            if filepath.lower().endswith(('.pcap', '.pcapng')):
                print("file exists")
        else:
            print("File does not exist, try again.")
            getFiles()
    else:
        if os.path.isfile(filepath):
            print("File found")
        else:
            createfileselection = getUserInput("File does not exist. Create file? Enter yes or no.", "yes", "no")
            if createfileselection == "yes":
                createfile(filepath)
            else:
                getOutputFile()            

def loadFile(filepath):
    file = open(filepath)
    return file

def getUserInput(message, *args):
    userResponse = input(message)
    if args:
        if userResponse in args:
            return userResponse
        else:
            return getUserInput("\n\nInvalid input. Answer with: " + ", ".join(args) + "\n", *args)
    return userResponse
 
def createfile(filepath):
    newfile = open(filepath, "x")
    print("File created")



def encodeAndSave(files):
    for key in files:
        packets = pyshark.FileCapture(key.name)

        lastEventTimestamps = {}

        with open(files[key], "w") as f:
            for packet in packets:
                basicData = getBasicData(packet)
                if basicData is not None:
                    Data = calcTimeDifference(basicData, lastEventTimestamps)

                    f.write(str(Data) + "\n")
                    print(Data)

def getBasicData(packet):
    try:
        timeStamp = packet.sniff_time.timestamp()
    except:
        timeStamp = np.nan

    if "HTTP" in packet:
        httpCode = np.nan
        httpLayer = np.nan
        try:
            if hasattr(packet.http, "request_method"):
                httpLayer = convertMethodToHmmFormat(packet.http.request_method)
            else: 
                httpLayer = np.nan

            if hasattr(packet.http, "response_code"):
                httpCode = convertCodeToHmmFormat(packet.http.response_code)

        except Exception as e:
            pass

        return [timeStamp, httpLayer, httpCode]

    elif "TCP" in packet:
        tcp_layer = packet.tcp
        if hasattr(tcp_layer, "flags"):
            tcpFlags = convertTcpFlagToHmmFormat(tcp_layer.flags)
            return [timeStamp, tcpFlags, packet.length]

    return None  

def convertMethodToHmmFormat(request_method):
    match request_method:
        case "GET":
            return 1  
        case "POST":
            return 2  
        case "PUT":
            return 3  
        case "DELETE":
            return 4  
        case "PATCH":
            return 5  
        case "OPTIONS":
            return 6  
        case "HEAD":
            return 7  
        case "CONNECT":
            return 8  
        case "TRACE":
            return 9  
        case _:
            return np.nan

def convertCodeToHmmFormat(http_code):
    httpCode = None  

    match http_code:
        case "200":
            httpCode = 1  
        case "201":
            httpCode = 2  
        case "202":
            httpCode = 3  
        case "204":
            httpCode = 4  
        case "301":
            httpCode = 5  
        case "302":
            httpCode = 6  
        case "304":
            httpCode = 7  
        case "400":
            httpCode = 8  
        case "401":
            httpCode = 9  
        case "403":
            httpCode = 10  
        case "404":
            httpCode = 11  
        case "405":
            httpCode = 12  
        case "408":
            httpCode = 13  
        case "500":
            httpCode = 14  
        case "501":
            httpCode = 15  
        case "502":
            httpCode = 16  
        case "503":
            httpCode = 17  
        case "504":
            httpCode = 18  
        case "505":
            httpCode = 19  
        case _:
            httpCode = np.nan

    return httpCode

def convertTcpFlagToHmmFormat(tcpFlags):
    match tcpFlags:
        case "0x00000010": 
            return 1 
        case "0x00000001": 
            return 2  
        case "0x00000100": 
            return 3  
        case "0x00010000": 
            return 4  
        case "0x00001000":
            return 5
        case "0x00100000":
            return 6
        case "0x00000011":
            return 7
        case _:
            return np.nan

def calcTimeDifference(data, last_timestamps):
    timestamp, event, length_or_code = data

    if event in last_timestamps:
        time_diff = timestamp - last_timestamps[event]
    else:
        time_diff = np.nan


    last_timestamps[event] = timestamp

    return [event, length_or_code, time_diff]

main()
