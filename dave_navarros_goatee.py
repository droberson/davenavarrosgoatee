#!/usr/bin/env python

"""dave_navarros_goatee

This attempts to discover potential passwords leaked to the filesystem
via chat and program logs, shell histories, configuration files, and
anything else that is readable.

This is currently very terrible and shouldnt be used.
2/2017 -- Daniel Roberson

TODO:
- add more hash types
-- $id$salt$hash
-- ids: 1=md5 2a=blowfish 5=sha256 6=sha512
- convert getopt to argparse
- add left->right, right->left function
- LRU cache to minimize duplicate password attempts
- add charset to use with analyze()
- different pattern for open()
- flag to generate wordlist only
- check if -p exists
"""

"""
The MIT License

Copyright (c) 2017 Daniel Roberson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import os
import sys
import stat
import string
import getopt
import math
import crypt

# Globals
HASHLIST = {}
ENTROPY = 2.0 # minimum entropy
MINLENGTH = 6 # minimum password length

# Constants
ALPHAONLY = string.ascii_letters
ALPHANUM = ALPHAONLY + string.digits
ALLCHARS = ALPHANUM + string.punctuation


def is_binary(filename):
    """Determine if a file is a binary"""
    binary = open(filename, 'rb')
    chunk = ''
    try:
        while 1:
            try:
                chunk = binary.read(1024)
            except:
                return False
            if '\0' in chunk:
                return True
            if len(chunk) < 1024:
                break
    finally:
        binary.close()
    return False


def shannon_entropy(data, iterator):
    """Calculate entropy of a string using the Shannon Algorithm

    Claude Shannon looks like he could have commanded the Death Star.
    - Michael Roberson

    https://en.wikipedia.org/wiki/Claude_Shannon

    Jacked this function from:
    http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in (ord(c) for c in iterator):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def analyze(filename):
    """Try to find passwords in a file"""
    count = 0
    wordlist = []
    filep = open(filename, 'r')
    print "[-] Analyzing %s" % (os.path.abspath(filename))
    for line in filep:
        if len(HASHLIST.keys()) == 0:
            break
        if shannon_entropy(line.rstrip('\r\n'), ALLCHARS) < ENTROPY:
            continue
        wordlist = mutate(line.rstrip('\r\n'))
        for word in wordlist:
            if len(HASHLIST.keys()) == 0:
                break
            if len(word) < MINLENGTH:
                continue
            for user in HASHLIST.keys():
                crypted = crypt.crypt(word, HASHLIST[user])
                if crypted == HASHLIST[user]:
                    del HASHLIST[user]
                    print "[*] Found password for %s: %s in %s" % \
                        (user, word, os.path.abspath(filename))
                    continue
            count += 1
    print "[-] %s words attempted from %s" % \
        (str(count), os.path.abspath(filename))
    print
    filep.close()


def mutate(buf):
    """Generate a list of mutations from a buffer"""
    wordlist = []

    tmpstr = ''
    wordlist.append(buf) # add line itself
    for character in buf: # left to right
        tmpstr += character
        wordlist.append(tmpstr)

        tmpstr = ''
    for character in reversed(buf): # right to left
        tmpstr = character + tmpstr
        wordlist.append(tmpstr)
    tokens = ''.join(set(buf))

    for omit_token in ALPHANUM:
        tokens = tokens.replace(omit_token, '')

    for x in tokens:
        wordlist.extend(buf.split(x)) # add token itself
        for token in buf.split(x):
            tmpstr = ''
            for character in token: # left to right of token
                tmpstr += character
                wordlist.append(tmpstr)
            tmpstr = ''
            for character in reversed(token): # right to left of token
                tmpstr = character + tmpstr
                wordlist.append(tmpstr)

    # return unique list
    wordlist = list(set(wordlist))
    return wordlist


def should_analyze(filename):
    """Determine if filename is worth exploring"""
    try:
        filep = open(filename, 'r')
        filep.close()
    except:
        return False
    return os.access(filename, os.R_OK) \
        and stat.S_ISREG(os.stat(filename).st_mode) \
        and not os.path.islink(filename) \
        and not is_binary(filename)


def populate_hashes(hashfile):
    """Parse a hash file in user:hash format"""
    global HASHLIST
    HASHLIST = {}

    if hashfile == '':
        print "[-] Must specify a hash file with -f/--file"
        sys.exit(os.EX_USAGE)
    try:
        hashp = open(hashfile, 'r')
    except Exception, err:
        print "[-] Could not open hashfile: %s" % (str(err))
        sys.exit(os.EX_USAGE)

    print "[+] Populating hash list from %s" % (hashfile)

    for line in hashp:
        tmp = line.split(':')

        # remove carriage returns and newlines
        tmp[0] = tmp[0].rstrip('\r\n')
        tmp[1] = tmp[1].rstrip('\r\n')
        line = line.rstrip('\r\n')

        if len(tmp) < 2 or tmp[0] == '' or tmp[1] == '':
            print "[-] Skipping %s due to missing fields" % (line)
            continue

        if len(tmp[1]) < 12:
            print "[-] Skipping %s because its not a valid hash" % (line)
            continue

        HASHLIST[tmp[0]] = tmp[1]

    hashp.close()
    if HASHLIST == {}:
        print "[-] Empty hash list. Exiting"
        sys.exit(os.EX_USAGE)


def usage():
    """Print program usage"""
    print sys.argv[0], "[-h/--help] [-p/--path <path>] -f <hashfile>"
    print "\t-h/--help      -- prints this usage blurb"
    print "\t-p/--path      -- filesystem path to start the walk."
    print "\t-f/--file      -- file containing hashes in user:hash format"
    print "\t-e/--entropy   -- minimum entropy score. default:", ENTROPY
    print "\t-m/--minlength -- minimum password length. default:", MINLENGTH
    print
    print "example: ./dave_navarros_goatee.py -p /home -f hashes.txt"


def main():
    """dave_navarros_goatee.py entry point"""
    global ENTROPY
    global MINLENGTH
    ENTROPY = 2.0
    MINLENGTH = 6
    hashfile = ''
    path = "/"

    print "[+] dave_navarros_goatee.py -- by Daniel Roberson"
    print

    try:
        opts, args = getopt.getopt(sys.argv[1:], "-hp:f:e:m:", ["help", "path=", "file=", "entropy=", "minlength="])
    except getopt.GetoptError as err:
        print str(err)
        usage()
        sys.exit(os.EX_USAGE)
    for option, arg in opts:
        if option in ("-h", "--help"):
            usage()
            sys.exit(os.EX_USAGE)
        elif option in ("-p", "--path"):
            path = arg
        elif option in ("-f", "--file"):
            hashfile = arg
        elif option in ("-e", "--entropy"):
            ENTROPY = float(arg)
        elif option in ("-m", "--minlength"):
            MINLENGTH = int(arg)
        else:
            assert False, "Unhandled option"

    populate_hashes(hashfile)

    print
    print "[+] Walking filesystem starting at %s" % (path)
    print "[+] Press Control-C to stop the violence."
    print

    for root, dirs, files in os.walk(path):
        for filename in files:
            f = os.path.join(root, filename)
            if should_analyze(f) and len(HASHLIST):
                analyze(f)

    print
    print "[+] The last Metroid is in captivity. The galaxy is at peace."


if __name__ == "__main__":
    main()
