def main():
   getFiles()

def getFiles():
    endloop = False;
    print("This script will automatically perform the processing of a pcap file to encode it in a form suitable for multivariate HMM.")


    while (endloop == False):
        inputfile = getSingleFile()
        print("File succesfully added")
        endloopinput = input("Enter another file path to add another file, or enter Finish to finish adding files.")
        if endloopinput == "Finish":
            endloop = True
        else:
            getSingleFile()

def getSingleFile():
    filepath = input("Please provide the absolute path to the file.")

def checkfileexists():
    print("stuff")

def createfile():
    print("stuff")



main()