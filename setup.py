#!/usr/bin/python3

import os

if os.getuid() != 0:
  print("[!]YouMustExecute as Root!!!!!!!!!")
  sys.exit()
 
os.system("chmod +x shellbin.py")
os.system("cp shellbin.py /usr/local/bin/shellbin")

print("[+]SetUp Done.......")
