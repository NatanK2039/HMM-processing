import os
import pyshark
import numpy as np

#Main function, this will run the entire script
def main():
    print("This script will automatically perform the processing of a pcap file to encode it in a form suitable for multivariate HMM.")
    files = getFiles()
    encodeAndSave(files)

#This function is responsible for initiating the collection of files from the user. 
def getFiles():
    endloop = False;
    inputAndOutputFiles = {} # This dictionary will store the input to output file pairs

    #This loop will ensure that the user provides a vallid path
    while (endloop == False):
        endloopinput = getUserInput("Enter a file path to add a file, or enter Finish to finish adding files.")
        if endloopinput == "Finish":
            endloop = True
            break;
        else:
            inputfile = getInputFile(endloopinput) #This calls the function responsible for getting a specific input file
            print("File saved")
            outputfile = getOutputFile()#This calls the function responsible for getting a specific output file
            inputAndOutputFiles[inputfile] = outputfile 
        for key in inputAndOutputFiles: #For each key - value pair in the dictionary, print the pair with the message added
            print(key.name + " will be encoded and saved to " + inputAndOutputFiles[key])
    return inputAndOutputFiles

#This function is responsible for getting specific input files
def getInputFile(filepath):
    if filepath == "none":
        filepath = getUserInput("Enter absolute filepath")
        checkfileexists(filepath)
        file = loadFile(filepath)
    else: 
        checkfileexists(filepath, "pcap")
        file = loadFile(filepath)
    return file

#This function is responsible for getting specific output files. 
def getOutputFile():
    filepath = getUserInput("Where to save encoded data? Provide absolute path to .txt file (The file will be created if it does not yet exist)")
    newfilepath = checkfileexists(filepath, "txt")
    return newfilepath

#This function is responsible for ensuring that the files that the user provides actually exist. 
def checkfileexists(filepath, type):
    if type == "pcap":
        if os.path.isfile(filepath): #checks if the path points to a file
            if filepath.lower().endswith(('.pcap', '.pcapng')): #Ensures the file ends with .pcap or .pcapng - Cycle 3 hindsight: reduntant? if type =="pcap" should do this already. No changes will be made due to time constraints
                print("file exists")
                return filepath
        else:
            print("File does not exist, try again.")
            getFiles()
    else:
        if os.path.isfile(filepath):
            print("File found")
            return filepath
        else:
            createfileselection = getUserInput("File does not exist. Create file? Enter yes or no.", "yes", "no")
            if createfileselection == "yes":
                createfile(filepath)
                return filepath
            else:
                filepath = getOutputFile()    
                return filepath        

#This function is responsible for loading the file for use and handling errors that may arise. 
def loadFile(filepath):
    try:
        file = open(filepath)
        return file
    except Exception as e:
        print("Something went wrong. possibly caused by a previous spelling mistake or invalid file. Restarting.")
        main()

#This function is responsible for handling user inputs
def getUserInput(message, *args): #The second parameters allows an unknown number of parameters to be passed. 
    userResponse = input(message)
    if args:
        if userResponse in args:
            return userResponse
        else:
            return getUserInput("\n\nInvalid input. Answer with: " + ", ".join(args) + "\n", *args)
    return userResponse


#This function creates the file 
def createfile(filepath):
    newfile = open(filepath, "x")
    print("File created")


#This function initaets the process of encoding the data and saving it to a file
def encodeAndSave(files):
    for key in files:
        packets = pyshark.FileCapture(key.name) #pyshark used to properly read the contents of the file

        lastEventTimestamps = {} #dict prepared for the timestampts

        with open(files[key], "w") as f: 
            for packet in packets: #for each packet
                basicData = getBasicData(packet) #extract basic data
                if basicData is not None: #And if any data is available
                    Data = calcTimeDifference(basicData, lastEventTimestamps) #replace the timestamp with the time difference, which is usable to a hidden markov model
                    f.write(str(Data) + "\n") #write data to file
        print("Data written to file")

#This function is responsible for extracting data
def getBasicData(packet):
    try:
        timeStamp = packet.sniff_time.timestamp() #get timestamp
    except:
        timeStamp = np.nan #np.nan used as hmm models are incapable of reading strings like "None"

    if "HTTP" in packet: 
        httpCode = np.nan 
        httpLayer = np.nan
        try:
            if hasattr(packet.http, "request_method"): #If there is a request, extract it and convert to numeric format for model
                httpLayer = convertMethodToHmmFormat(packet.http.request_method)
             else: 
                httpLayer = np.nan

            if hasattr(packet.http, "response_code"): #If there is a response coce, extact it and convert to numeric format for model
                httpCode = convertCodeToHmmFormat(packet.http.response_code)

        except Exception as e:
            pass

        return [timeStamp, httpLayer, httpCode]

    elif "TCP" in packet: #if the packet is a TCP packet, return TCP data
        tcp_layer = packet.tcp
        if hasattr(tcp_layer, "flags"):
            tcpFlags = convertTcpFlagToHmmFormat(tcp_layer.flags)
            return [timeStamp, tcpFlags, packet.length]

    return None #If the packet is not HTTP or TCP, assign "None" to it, effectively dropping it. 

#This function is responsible for encoding the extractd data into a format suitable for use by a hidden markov model
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
        
#This function is responsible for encoding the extractd data into a format suitable for use by a hidden markov model
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

#This function is responsible for encoding the extractd data into a format suitable for use by a hidden markov model
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

#This function calculates the tiem difference between the timestamps 
def calcTimeDifference(data, last_timestamps):
    timestamp, event, length_or_code = data

    if event in last_timestamps:
        time_diff = timestamp - last_timestamps[event]
    else:
        time_diff = np.nan


    last_timestamps[event] = timestamp

    return [event, length_or_code, time_diff]

main()
