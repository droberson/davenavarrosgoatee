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
- LRU cache to minimize duplicate password attempts
- different pattern for open()
- flag to generate wordlist only
- check if -p exists
- flag to toggle whitespace in passwords
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
import argparse
import math
import crypt

# Globals
HASHLIST = {}

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


def shannon_entropy(data, charset):
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
    for x in (ord(c) for c in charset):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def analyze(filename, minlength, entropy, charset):
    """Try to find passwords in a file"""
    count = 0
    wordlist = []
    filep = open(filename, 'r')
    print "[-] Analyzing %s" % (os.path.abspath(filename))
    for line in filep:
        if len(HASHLIST.keys()) == 0:
            break
        if shannon_entropy(line.rstrip('\r\n'), charset) < entropy:
            continue
        wordlist = mutate(line.rstrip('\r\n'))
        for word in wordlist:
            if len(HASHLIST.keys()) == 0:
                break
            if len(word) < minlength:
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


def left_right_substrings(buf):
    """Return substrings containing leftmost and rightmost characters.

    For example, abc' returns:
    ['a', 'ab', 'abc', 'c', 'cb']

    Thanks to Michael Roberson for this function!
    """
    length = len(buf)
    left_right = [buf[0:i+1] for i in xrange(length)]
    right_left = [buf[-i:] for i in xrange(length)]
    return list(set(left_right + right_left))


def mutate(buf):
    """Generate a list of mutations from a buffer"""
    wordlist = [buf]
    wordlist += left_right_substrings(buf)

    tokens = ''.join(set(buf))

    for omit_token in ALPHANUM:
        tokens = tokens.replace(omit_token, '')

    for x in tokens:
        wordlist.extend(buf.split(x)) # add token itself
        for token in buf.split(x):
            wordlist += left_right_substrings(token)

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

        if len(tmp) <= 1:
            continue;
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


def main():
    """dave_navarros_goatee.py entry point"""

    print "[+] dave_navarros_goatee.py -- by Daniel Roberson"
    print

    # parse CLI arguments
    description = "example: ./dave_navarros_goatee.py -p /home -f hashes.txt"
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-p",
                        "--path",
                        default="/",
                        help="starting filesystem location")
    parser.add_argument("-f",
                        "--hashfile",
                        default="",
                        help="file containing hashes in user:hash format")
    parser.add_argument("-e",
                        "--entropy",
                        type=float,
                        default=2.0,
                        help="minimum Shannon entropy")
    parser.add_argument("-m",
                        "--minlength",
                        type=int,
                        default=6,
                        help="minimum password length")
    parser.add_argument("-c",
                        "--charset",
                        choices=["ALL", "ALPHA", "ALPHANUM"],
                        default="ALL",
                        help="character set to use for entropy check")
    args = parser.parse_args()

    charsets = {"ALL": ALLCHARS, "ALPHA": ALPHAONLY, "ALPHANUM": ALPHANUM}

    # parse hash file
    populate_hashes(args.hashfile)

    print
    print "[+] Walking filesystem starting at %s" % (args.path)
    print "[+] Press Control-C to stop the violence."
    print

    for root, dirs, files in os.walk(args.path):
        for filename in files:
            f = os.path.join(root, filename)
            if should_analyze(f) and len(HASHLIST):
                analyze(f, args.minlength, args.entropy, args.charset)

    print "[+] The last Metroid is in captivity. The galaxy is at peace."


if __name__ == "__main__":
    main()
