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
- flag to toggle whitespace in passwords
- threading


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
import argparse
import math
import crypt

# Globals
HASHLIST = {}

# Constants
ALPHAONLY = string.ascii_letters
ALPHANUM = ALPHAONLY + string.digits
ALLCHARS = ALPHANUM + string.punctuation

# Terminal colors
class Color(object):
    """ANSI color code constants and functions"""
    BOLD = '\033[1m'
    END = '\033[0m'

    @staticmethod
    def disable():
        """Disable color output"""
        Color.BOLD = ''
        Color.END = ''

    @staticmethod
    def bold_string(buf):
        """Return a string wrapped in bold ANSI codes"""
        return Color.BOLD + buf + Color.END


def is_binary(filename):
    """Determine if a file is a binary"""
    binary = open(filename, 'rb')
    chunk = ''
    try:
        while 1:
            try:
                chunk = binary.read(1024)
            except Exception:
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
    for byte in (ord(c) for c in charset):
        p_x = float(data.count(chr(byte))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def analyze(filename, minlength, entropy, charset):
    """Try to find passwords in a file"""
    word_list = []
    filep = open(filename, 'r')

    for line in filep:
        if len(HASHLIST.keys()) == 0:  # all hashes solved!
            filep.close()
            return
        line = line.rstrip('\r\n')
        if shannon_entropy(line, charset) < entropy:
            continue
        word_list += mutate(line)

    word_list = list(set(word_list))
    word_list = [s for s in word_list if len(s) >= minlength]

    print "[-] Trying %s possible password combinations from %s" % \
        (len(word_list), filename)

    for word in word_list:
        if len(HASHLIST.keys()) == 0:  # all hashes solved!
            filep.close()
            break
        for user in HASHLIST.keys():
            crypted = crypt.crypt(word, HASHLIST[user])
            if crypted == HASHLIST[user]:
                del HASHLIST[user]
                print "[*] Found password for %s: %s in %s" % \
                    (user, Color.bold_string(word), os.path.abspath(filename))
                continue


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
    word_list = [buf]
    word_list += left_right_substrings(buf)

    tokens = ''.join(set(buf))

    # don't use alphanumeric characters as tokens
    for omit_token in ALPHANUM:
        tokens = tokens.replace(omit_token, '')

    for token in tokens:
        word_list.extend(buf.split(token))  # add token itself
        for sub_token in buf.split(token):
            word_list += left_right_substrings(sub_token)

    # strip leading and tailing whitespace
    # TODO make this toggleable
    word_list = [s for s in word_list if s.strip() == s]

    # return unique list
    return list(set(word_list))


def should_analyze(filename):
    """Determine if filename is worth exploring"""
    try:
        filep = open(filename, 'r')
        filep.close()
    except Exception:
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
        hash_tokens = line.split(':')

        if len(hash_tokens) <= 1:
            continue
        # remove carriage returns and newlines
        hash_tokens[0] = hash_tokens[0].rstrip('\r\n')
        hash_tokens[1] = hash_tokens[1].rstrip('\r\n')
        line = line.rstrip('\r\n')

        if hash_tokens[0] == '' or hash_tokens[1] == '':
            print "[-] Skipping %s due to missing fields" % (line)
            continue

        if len(hash_tokens[1]) < 12:
            print "[-] Skipping %s because its not a valid hash" % (line)
            continue

        # HASHLIST[username] = hash
        HASHLIST[hash_tokens[0]] = hash_tokens[1]

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
    parser.add_argument("--nocolor",
                        action='store_true',
                        help="disable color output")
    args = parser.parse_args()

    charsets = {"ALL": ALLCHARS, "ALPHA": ALPHAONLY, "ALPHANUM": ALPHANUM}
    charset = charsets[args.charset]

    if args.nocolor:
        Color.disable()

    if not os.path.isdir(args.path):
        print "[-] %s is not a directory. exiting." % (args.path)
        sys.exit(os.EX_USAGE)

    # parse hash file
    populate_hashes(args.hashfile)

    print
    print "[+] Walking filesystem starting at %s" % (args.path)
    print "[+] Press Control-C to stop the violence."
    print

    # I don't care about directories here, therefore _
    for root, _, files in os.walk(args.path):
        for filename in files:
            try_file = os.path.join(root, filename)
            if should_analyze(try_file) and len(HASHLIST):
                analyze(try_file, args.minlength, args.entropy, charset)

    print
    print "[+] The last Metroid is in captivity. The galaxy is at peace."


if __name__ == "__main__":
    main()
