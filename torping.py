import os
import sys
import time
import array
import socket
import struct
import select
import tornado.iostream
import tornado.gen
import iopacket
import tornado.ioloop

def i2n(i):
    """ip to number """
    ip = [int(x) for x in i.split('.')]
    return ip[0] << 24 | ip[1] << 16 | ip[2] << 8 | ip[3]

try:
    from _thread import get_ident
except ImportError:
    def get_ident(): return 0

if sys.platform == "win32":
    # On Windows, the best timer is time.clock()
    default_timer = time.clock
else:
    # On most other platforms the best timer is time.time()
    default_timer = time.time

#=============================================================================#
# ICMP parameters

ICMP_ECHOREPLY = 0		# Echo reply (per RFC792)
ICMP_ECHO = 8			# Echo request (per RFC792)
ICMP_ECHO_IPV6 = 128		# Echo request (per RFC4443)
ICMP_ECHO_IPV6_REPLY = 129	# Echo request (per RFC4443)
ICMP_MAX_RECV = 2048		# Max size of incoming buffer


    
    
class Torping(object):

    def __init__(self):
        self.reset_stats()

    def reset_stats(self):
        self.thisIP = "0.0.0.0"
        self.pktsSent = 0
        self.pktsRcvd = 0
        self.minTime = 999999999
        self.maxTime = 0
        self.totTime = 0
        self.avrgTime = 0
        self.fracLoss = 1.0

    def checksum(self, source_string):
        """
        A port of the functionality of in_cksum() from ping.c
        Ideally this would act on the string as a series of 16-bit ints (host
        packed), but this works.
        Network data is big-endian, hosts are typically little-endian
        """
        if (len(source_string) % 2):
            source_string += "\x00"
        converted = array.array("H", source_string)
        if sys.byteorder == "big":
            converted.bytewap()
        val = sum(converted)
    
        val &= 0xffffffff # Truncate val to 32 bits (a variance from ping.c, which
                          # uses signed ints, but overflow is unlikely in ping)
    
        val = (val >> 16) + (val & 0xffff)    # Add high 16 bits to low 16 bits
        val += (val >> 16)                    # Add carry from above (if any)
        answer = ~val & 0xffff                # Invert and truncate to 16 bits
        answer = socket.htons(answer)
    
        return answer

    
    #=============================================================================#
    @tornado.gen.coroutine
    def send_one_ping(self, tsocket, destIP, myID, mySeqNumber, numDataBytes, ipv6=False):
        """
        Send one ping to the given >destIP<.
        """
        #destIP  =  socket.gethostbyname(destIP)
    
        # Header is type (8), code (8), checksum (16), id (16), sequence (16)
        # (numDataBytes - 8) - Remove header size from packet size
        myChecksum = 0
    
        # Make a dummy heder with a 0 checksum.
        if ipv6:
            header = struct.pack(
                "!BbHHh", ICMP_ECHO_IPV6, 0, myChecksum, myID, mySeqNumber
            )
        else:
            header = struct.pack(
                "!BBHHH", ICMP_ECHO, 0, myChecksum, myID, mySeqNumber
            )
    
        padBytes = []
        startVal = 0x42
        # 'cose of the string/byte changes in python 2/3 we have
        # to build the data differnely for different version
        # or it will make packets with unexpected size.
        if sys.version[:1] == '2':
            bytes = struct.calcsize("d")
            data = ((numDataBytes - 8) - bytes) * "Q"
            data = struct.pack("d", default_timer()) + data
        else:
            for i in range(startVal, startVal + (numDataBytes - 8)):
                padBytes += [(i & 0xff)]  # Keep chars in the 0-255 range
            #data = bytes(padBytes)
            data = bytearray(padBytes)
    
    
        # Calculate the checksum on the data and the dummy header.
        myChecksum = self.checksum(header + data) # Checksum is in network order
    
        # Now that we have the right checksum, we put that in. It's just easier
        # to make up a new header than to stuff it into the dummy.
        if ipv6:
            header = struct.pack(
                "!BbHHh", ICMP_ECHO_IPV6, 0, myChecksum, myID, mySeqNumber
            )
        else:
            header = struct.pack(
                "!BBHHH", ICMP_ECHO, 0, myChecksum, myID, mySeqNumber
            )
    
        packet = header + data
    
        sendTime = default_timer()
    
        #a = tsocket.socket.sendto(data, (tsocket.dest_ip, tsocket.port))
        yield tsocket.write(packet , (destIP,1))# Port number is irrelevant for ICMP

        return sendTime
    
    @tornado.gen.coroutine
    def receive_one_ping(self, tsocket, myID, timeout, ipv6 = False):
        """
        Receive the ping from the socket. Timeout = in ms
        """
        timeLeft = timeout/1000
        start_time = default_timer()
        tornado.ioloop.IOLoop.current().add_timeout(start_time + timeLeft , lambda : tsocket.close())

        while True: # Loop while waiting for packet or timeout
            try:
                try:
                    recPacket, address = yield tsocket.read()#ICMP_MAX_RECV)
                except iopacket.FdClosedError:
                    return None, 0, 0, 0, 0
                #print(recPacket)

                timeReceived = default_timer()
                ipHeader = recPacket[:20]
                iphVersion, iphTypeOfSvc, iphLength, \
                iphID, iphFlags, iphTTL, iphProtocol, \
                iphChecksum, iphSrcIP, iphDestIP = struct.unpack(
                    "!BBHHHBBHII", ipHeader
                )

                if ipv6:
                    icmpHeader = recPacket[0:8]
                else:
                    icmpHeader = recPacket[20:28]

                icmpType, icmpCode, icmpChecksum, \
                icmpPacketID, icmpSeqNumber = struct.unpack(
                    "!BBHHH", icmpHeader
                )

                # Match only the packets we care about
                if (icmpType == 0) and (icmpPacketID == myID):
                #if icmpPacketID == myID: # Our packet
                    dataSize = len(recPacket) - 28
                    #print (len(recPacket.encode()))
                    return timeReceived, (dataSize + 8), iphSrcIP, icmpSeqNumber, iphTTL
            except:
                continue


    def dump_stats(self):
        """
        Show stats when pings are done
        """
        print("\n----%s PYTHON PING Statistics----" % (self.thisIP))
    
        if self.pktsSent > 0:
            self.fracLoss = (self.pktsSent - self.pktsRcvd)/self.pktsSent
    
        print("%d packets transmitted, %d packets received, %0.1f%% packet loss" % (
            self.pktsSent, self.pktsRcvd, 100.0 * self.fracLoss
        ))
    
        if self.pktsRcvd > 0:
            print("round-trip (ms)  min/avg/max = %d/%0.1f/%d" % (
                self.minTime, self.totTime/self.pktsRcvd, self.maxTime
            ))
    
        print("")
        return

    @tornado.gen.coroutine
    def ping_once(self, destIP, hostname, timeout, mySeqNumber, numDataBytes, quiet = False, ipv6=False):
        """
        Returns either the delay (in ms) or None on timeout.
        """
        delay = None

        if ipv6:
            try: # One could use UDP here, but it's obscure
                mySocket = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname("ipv6-icmp"))
                mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            #except socket.error
            except OSError as e:
                #etype, evalue, etb = sys.exc_info()
                print("failed. (socket error: '%s')" % str(e))#evalue.args[1])
                print('Note that python-ping uses RAW sockets'
                        'and requiers root rights.')
                raise # raise the original error
        else:

            try: # One could use UDP here, but it's obscure
                mySocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
                mySocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            #except socket.error:
            except OSError as e:
                #etype, evalue, etb = sys.exc_info()
                print("failed. (socket error: '%s')" % str(e))#evalue.args[1])
                print('Note that python-ping uses RAW sockets'
                        'and requires root rights.')
                raise # raise the original error

        #my_ID = os.getpid() & 0xFFFF
        my_ID = (os.getpid() ^ get_ident() + i2n(destIP)) & 0xFFFF
        tsocket = iopacket.IOPacket(mySocket, max_packet_size=ICMP_MAX_RECV)
        sentTime = yield self.send_one_ping(tsocket, destIP, my_ID, mySeqNumber, numDataBytes, ipv6)
        if sentTime == None:
            tsocket.close()
            return delay

        self.pktsSent += 1

        recvTime, dataSize, iphSrcIP, icmpSeqNumber, iphTTL = yield self.receive_one_ping(tsocket, my_ID, timeout, ipv6)

        tsocket.close()

        if recvTime:
            delay = (recvTime-sentTime)*1000
            if not quiet:
                if ipv6:
                    host_addr = hostname
                else:
                    try:
                        host_addr = socket.inet_ntop(socket.AF_INET, struct.pack("!I", iphSrcIP))
                    except AttributeError:
                        # Python on windows dosn't have inet_ntop.
                        host_addr = hostname

                print("%d bytes from %s: icmp_seq=%d ttl=%d time=%d ms" % ( dataSize, host_addr, icmpSeqNumber, iphTTL, delay))
            self.pktsRcvd += 1
            self.totTime += delay
            if self.minTime > delay:
                self.minTime = delay
            if self.maxTime < delay:
                self.maxTime = delay
        else:
            delay = None
            if not quiet:
                print("Request timed out.")
                pass

        return delay

    @tornado.gen.coroutine
    def ping(self, hostname, timeout = 3000, count = 3, interval = 1000, numDataBytes = 64, ipv6=False):
        self.reset_stats()
        mySeqNumber = 0 # Starting value

        try:
            if ipv6:
                info = socket.getaddrinfo(hostname, None)[0]
                destIP = info[4][0]
            else:
                destIP = socket.gethostbyname(hostname)
            print("\nPYTHON PING %s (%s): %d data bytes" % (hostname, destIP, numDataBytes))
        except socket.gaierror as e:
            #etype, evalue, etb = sys.exc_info()
            print("\nPYTHON PING: Unknown host: %s (%s)" % (hostname, str(e))) #(hostname, evalue.args[1]))
            return

        self.thisIP = destIP

        for i in range(count):
            delay = yield self.ping_once(destIP, hostname, timeout,mySeqNumber, numDataBytes, ipv6=ipv6)
            if delay is None:
                delay = 0

            mySeqNumber += 1

            if interval > delay:
                pass
                yield tornado.gen.sleep((interval - delay)/1000)
        self.dump_stats()
        #print(self.pktsRcvd / self.pktsSent)
        return bool(self.pktsRcvd)

if __name__ == '__main__':
    torping = Torping()
    tornado.ioloop.IOLoop.current().run_sync(lambda:torping.ping("www.google.com"))
