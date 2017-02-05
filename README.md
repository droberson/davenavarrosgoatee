# Dave Navarro's Goatee

This program attempts to crack hashes based on the contents of a
filesystem. It is currently pretty bad quality as I am just learning
Python.

In the future I plan on supporting more hash types besides ones supported
by crypt(), wordlist generation, and better efforts to eliminate duplicate
effort. This code actually works, but is slow. It takes roughly 3 minutes
to attempt to crack a single SHA-512 hash against a 5kb text file. This
should be used AFTER attempting to crack hashes using John the Ripper or
hashcat.

Some good paths to use this on are /home, /root, /var/www, /var/log, 
/var/spool/{cron,mail,...), and /etc. In this program's current state, it
would likely take several weeks/months to work against /.

If someone makes the mistake of mentioning their passwords in a chat program
that gets logged to the hard drive, mis-types their password into their
shell, types their password into the username field of a program that gets
logged to /var/log, or adds their password somewhere to a configuration
file in plain text, this program will eventually find it.

## How does this work?

It will recursively scan a directory for files that are not binaries
(contain no NULL characters), and read line by line, applying various
mutations to each line to generate a potential list of passwords. This uses
the entire line itself, a list of words reading character by character from
left to right, from right to left, every token combination of every
non-alphanumeric character, and each token broken down left to right, then
right to left.

To reduce CPU cost, you can specify minimum password lengths to try and
have the option to skip lines that do not score above a threshold met by
using Claude Shannon's entropy algorithm. I am currently exploring ways to
reduce duplicated combinations and to speed the process up.
