import os.path
from scapy.all import rdpcap

def main():
    print("This script will automatically perform the processing of a pcap file to encode it in a form suitable for multivariate HMM.")
    getFiles()

def getFiles():
    getFiles()

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
                createfile()
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
 




def createfile():
    print("stuff")



main()
#E:\ethical hacking examin\python assesme t\Mal.pcapng
#