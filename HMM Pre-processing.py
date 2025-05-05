import os.path

def main():
    print("This script will automatically perform the processing of a pcap file to encode it in a form suitable for multivariate HMM.")
    getFiles()

def getFiles():
    getInputFiles()

def getInputFiles():
    endloop = False;

    while (endloop == False):
        endloopinput = getUserInput("Enter a file path to add a file, or enter Finish to finish adding files.")
        if endloopinput == "Finish":
            endloop = True
        else:
            FileObject = getSingleFile(endloopinput)
            print("File succesfully added")



def getSingleFile(filepath):
    if filepath == "false":
        filepath = getUserInput("Enter absolute filepath")
        checkfileexists(filepath)
        
    else: 
        checkfileexists(filepath)






def checkfileexists(filepath):
    if os.path.isfile(filepath):
        if filepath.lower().endswith(('.pcap', '.pcapng')):
            print("file exists")
    else:
        print("File does not exist, try again.")
        getInputFiles()

def getUserInput(message):
    userResponse = input(message)
    return userResponse






def createfile():
    print("stuff")



main()