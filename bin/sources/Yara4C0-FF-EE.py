import os
import argparse
from time import sleep
import shlex
import subprocess
import crayons
import platform


b = crayons.blue
r = crayons.red
w = crayons.white

logo = [
"            ###########################        ) )       ",
"            ###########################       ( (        ",
"            #### Yara for C0-FF-EE ####        ) )       ",
"            ###########################      (----)-)    ",
"            ###########################       \__/-'     ",        
"                                                         ",
"  Crypt-0n Forensic Framework for Evidence Enumeration.  ",
"                                                         ",
"     Auteur: Julien LEQUEN - jlequen[AT]crypt-0n.fr      ",
"                                                         ",
"      GNU General Public License version 3 (GPLv3)       ",
" _______________________________________________________ ",
"\n\n"
]
logo = '\n'.join(logo)
logo += """
-------------------------------------------------------------------------------
-------------------------------------------------------------------------------

C0-FF-EE
Read more at: https://github.com/Crypt-0n/C0-FF-EE

"""

def is_os_64bit():
    return platform.machine().endswith('64')


print(logo)

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="Directory to scan", required=True, nargs='+')
parser.add_argument("-r", "--recursive", help="Scan files in directories recursively", action="store_true")
args = parser.parse_args()
target = ' '.join(args.target)
if target.endswith('\\') and not target.endswith('\\\\'):
    target += '\\'
target = '"' + target + '"'

if is_os_64bit():
    yara_cmd = ["bin/yara64.exe"]
else:
    yara_cmd = ["bin/yara32.exe"]

yara_cmd.extend(["--no-warnings", "--fast-scan", "-p", "24"])
if args.recursive:
    yara_cmd.append("-r")
yara_cmd.extend(["./rules.yar", target])

print("[+] Beginning YARA scan...")
print("[+] You may ignore file-specific errors")
os.system(" ".join(yara_cmd))
print("\n[+] Done!")


