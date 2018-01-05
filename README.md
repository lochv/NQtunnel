# NQtunnel
```
  ________
< NQtunnel >
  ________
         \   ^__^ 
          \  (oo)\_______
             (__)\       )\/\
                 ||----w |
                 ||     ||
```
## Dependencies
+ python2.7
+ requests
+ socket
+ argparse


## Usage
```
$ NQSocksProxy.py [-h] [-l] [-p] [-r] -u  [-v]

Example: NQSocksProxy.py -u http://target.com/tunnel.php

optional arguments:
  -h, --help           show this help message and exit
  -l , --listen-on     the default listening address: 127.0.0.1
  -p , --listen-port   the default listening port: 8888
  -r , --read-buff     local read buffer, max data to be sent per POST
  -u , --url           the url containing the tunnel script
  -v , --verbose       Verbose output[INFO|DEBUG]
```
+ __Step 1.__ Obfucate with your way and upload NQtunnel.* to a webserver
+ __Step 2.__ Configure you tools to use a socks proxy, use the ip address and port you specified when you started the NQSocksProxy.py
+ __Step 3.__ Happy hacking!
- __Note: U only use tools, which based TCP/IP__


## New Features!
+ Upgrade from sensepost
+ Add ids/ips evasion techniques
+ Handle threads
+ Upcoming hidden features
