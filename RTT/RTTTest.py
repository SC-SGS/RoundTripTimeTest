#!/usr/bin/python3
import numpy as np
import os
import sys
import socket
import time
import subprocess
import errno
import signal
try:
    from icecream import ic
    icecreamPresent=True
except:
    def ic(*dummyArgument):
        pass

    icecreamPresent=False
import json

helpstr = (
        "                                                                                          \n"
        "TCP Round Trip Time Test:                                                                 \n"
        "                                                                                          \n"
        "Measures the time needed to transfer TCP messages between this and a given remote host.   \n"
        "For each given message size, the application will perform 8 repetitive PingPong tests.    \n"
        "The measured duration of each test is divided by two, which in a symmetric routing        \n"
        "scenario represents the average time of a single transfer. For each given size, average   \n"
        "and standard deviation of the repetitions are determined and presented.                   \n"
        "                                                                                          \n"
        "Usage:                                                                                    \n"
        "  ./latencyTest -r [[user@]remotehost] [-s messagesizes] [-t] [-o filename] [-p port] [-v]\n"
        "                                                                                          \n"
        "Options:                                                                                  \n"
        "  -o filename                                                                             \n"
        "    The results will be plotted to screen (only if possible) and are saved to the given   \n"
        "    destination. Supported file endings are .png (default), .pdf and .svg. Additionally a \n"
        "    .txt file is created containing the raw measurement data.                             \n"
        "  -p port                                                                                 \n"
        "    Specifies the port on which either the receiver listens or the sender connects to.    \n"
        "    Default is port 9999                                                                  \n"
        "  -r [[user@]remotehost]                                                                  \n"
        "    Specifies the remote host to which messages are sent. If additionally a username      \n"
        "    is given, the program will automatically start the receiving counterpart on the       \n"
        "    remote host via SSH, as long as logging in without entering a password is possible. If\n"
        "    no argument is given, the program runs in receiver mode and waits for requests on port\n"
        "    9999 or a given alternative.                                                          \n"
        "  -s messagesizes                                                                         \n"
        "    Size of messages in form Bytes1,Bytes2,...,BytesN which are sent and received during  \n"
        "    the test. If no size is given, the default is 100Bytes. For each size 8 repeats of the\n"
        "    PingPong test are performed                                                           \n"
        "  -t                                                                                      \n"
        "    An SSH-Tunnel is used for transmission. This requires username and remotehost to      \n"
        "    be set.                                                                               \n"
        "  -v                                                                                      \n"
        "    Enables verbose output.                                                               \n"
        "                                                                                          \n"
        )


remotehost = ""
user       = ""
port       = 9999
mesgsizes  = [ int(100) ]
useTunnel  = False
outfile    = ""
mode       = "receive"
verbose    = False
repeats    = 8
sock       = None
tunnel     = None
maxInt     = int(2**31 - 1)

class memorySavingDummyMessage:
    __mesg = []
    size = 0
    limit = maxInt

    def __init__(self, size):
        self.size = size
        self.__createMesg(size)

    def __createMesg(self, random=False):
        """
        Creates buffer of limited size.
        """
        createBuffStart = time.time()
        if self.size >= self.limit:
            if random:
                self.__mesg = bytearray(os.urandom(self.limit))
            else:
                self.__mesg = bytearray(self.limit)
        else:
            if random:
                self.__mesg = bytearray(os.urandom(self.size))
            else:
                self.__mesg = bytearray(self.size)
        createBuffStop = time.time()
        write("Creating Buffer took: {}\n".format(createBuffStop - createBuffStart), False)


    def sendall(self, sock):
        """
        Sends the message repeatedly, until size Bytes are send.
        """
        try:
            for i in range(self.size//len(self.__mesg)):
                ic("send", i)
                sendall(sock, self.__mesg)
            if (self.size%len(self.__mesg)) > 0:
                ic("send mini")
                ic(self.size%len(self.__mesg))
                sendall(sock, self.__mesg[:(self.size%len(self.__mesg))])
        except socket.error as v:
            errorcode = v[0]
            write("ERROR: sendallAndRepeatWhenTooBig failed Errno [{}]\n".format(errorcode))
            sock.close()
            exit(0)
        ic("sent")


def main(argv):
    global sock
    checkArgs(argv)

    if mode == "auto":
        write("Checking if remote port is in use...\n")
        checkRemotePort()

        write("Starting receiving counterpart...\n")
        receiver = runReceiver()

        write("Waiting for receiver...\n")
        waitForReceiver()

    if mode == "auto" and useTunnel:
        write("Creating tunnel...\n")
        createTunnel()

        write("Connecting to tunnel...\n")
        sock = connectToReceiver()

    if mode == "send" or (mode == "auto" and not useTunnel):
        write("Connecting to receiver...\n")
        sock = connectToReceiver()

    if mode == "send" or mode == "auto":
        write("Running tests...\n")
        measuredLatencys = senderTest(sock)

        if outfile:
            writeRawFile(measuredLatencys)
            plotLatencyResults(measuredLatencys)

    if mode == "auto":
        receiver.wait()

    if mode == "receive":
        write("Listening for incoming connection...\n", False)
        sock = connectToSender()
        write("Sender accepted\n", False)

        write("Running tests...\n", False)
        receiverTest(sock)

    exit(0)


def senderTest(sock):
    """
    Runs sender's part of the latency test; including time measurement for each
    data size.
    """
    head = (
            "                                   \n"
            "Size (Byte)   Avg (sec)      SD    \n"
            "-----------  ----------  ----------\n"
            )
    write(head)

    # tell receiver about size of each message
    mesgsizesstr = ( str(list(mesgsizes))[1:-1] ).replace(" ", "")
    sendallPrefixed(sock, mesgsizesstr)
    maxSize = int(maxInt)
    times   = []
    avgs    = []
    stds    = []
    ic(mesgsizes)
    for size in list(mesgsizes):
        repTimes = []
        mesg = memorySavingDummyMessage(size)
        for rep in range(repeats):
            ic(size, rep)
            start = time.time()
            mesg.sendall(sock)
            recvall(sock, size)
            ic("Received", size)
            stop = time.time()
            repTimes.append( (stop - start) / 2. )

        ic("Receive finished")
        avg = np.mean(repTimes)
        std = np.std(repTimes)
        times.append(np.array(repTimes))
        avgs.append(avg)
        stds.append(std)

        printLatencyMeasurement(size, avg, std)

    write("\n")

    times = np.array(times)
    avgs  = np.array(avgs)
    stds  = np.array(stds)
    return (times, avgs, stds)


def sendall(sock, mesg):
    """
    Sends the given message over the given socket.
    """
    size = len(mesg)
    maxSize = int(maxInt)
    #maxSize = smallerLimit
    ic("sendall", mesg)
    try:
        if size >= maxSize:
            for i in range(size // maxSize):
                sock.sendall(mesg[(i*maxSize):(i+1)*maxSize])
            if (size%maxSize) > 0:
                sock.sendall(mesg[:(size%maxSize)])
        else:
            sock.sendall(mesg)
    except socket.error as v:
        sock.close()
        raise


def receiverTest(sock):
    """
    Receivers part of the latency test.
    """
    global mesgsizes

    mesgsizesstr = recvall(sock, recvLen(sock)).decode('ascii')
    mesgsizes    = np.array(mesgsizesstr.split(","), dtype=int)
    assert(len(mesgsizes) > 0 )
    ic(mesgsizes)
    for size in mesgsizes:
        for rep in range(repeats):
            ic(size, rep)
            ic(" waiting to receive ")
            mesg = recvall(sock, size)
            ic("received")
            sendall(sock, mesg)
            ic("sent")



def runReceiver():
    """
    Runs the receiver on the remote side via ssh.
    """
    prgname = sys.argv[0]
    if prgname == "-":
        write("ERROR: Program name at argv[0] not valid\n")
        exit(0)
    command = 'ssh {}@{} python3 < {} - -r -p {}'.format(user, remotehost, prgname,
            port)
    receiver = execute(command)
    return receiver


def createTunnel():
    """
    Creates an ssh tunnel that forwards the port on local side to the same
    one at the remote host.
    """
    global tunnel
    checkLocalPort()
    command = "ssh -L {}:localhost:{} {}@{} -nNT".format(port, port, user,
            remotehost)
    tunnel = execute(command)
    time.sleep(2)
    return tunnel


def connectToReceiver():
    """
    Connects the sender to the receiver and chooses the right host based on
    if an ssh tunnel is used. If the receiver does not respond within 30
    seconds, the program will exit and an error message is displayed.
    """
    sock      = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    trys      = 1
    maxTrys   = 30
    connected = False
    while not connected and trys < maxTrys:
        try:
            start = time.time()
            if useTunnel and mode == "auto":
                sock.connect(("localhost", port))
            elif mode == "send" or mode == "auto":
                sock.connect((remotehost, port))
            stop = time.time()
            connected = True
            write("  Connect took: {:-.3} seconds\n".format(stop-start))
        except socket.error as v:
            errorcode = v[0]
            if errorcode == errno.ECONNREFUSED:
                write("  Cannot reach receiver: {:>2}. try\n".format(trys),
                        False)
                trys += 1
                time.sleep(1)
                connected = False
            elif errorcode == errno.ETIMEDOUT:
                write("ERROR: Connection attempt timed out. errno [{}]\n".format(errorcode))
                write("The firewall might not allow TCP connections to the receiver on port {}\n".format(port))
                exit(0)
            else:
                write("ERROR: Connect to receiver failed: errno [{}]\n".format(
                    errorcode))
                exit(0)
    if trys == maxTrys:
        write("ERROR: Cannot not reach receiver: Timeout expired.\n")
        exit(0)
    return sock


def connectToSender():
    """
    Receiver listens on port and accepts the sender.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.settimeout(300000)
    try:
        server.bind(('', port))
        server.listen(5)
        (client, address) = server.accept()
    except socket.timeout:
        write("ERROR: Cannot reach sender: Timeout expired.\n")
        server.close()
        exit(0)
    except socket.error as v:
        errorcode = v[0]
        if errorcode == errno.EADDRINUSE:
            write("ERROR: Receiver cannot bind to localhost at port {}\n".format(port))
            write('Try "lsof -P -i tcp:{}" to find out which process is using the port.\n'.format(port))
            server.close()
            exit(0)
    server.close()
    return client


def recvall(sock, length):
    """
    Helper function to receive all data of given length
    """
    maxRecvLen = 2147483647
    recvdSoFar = 0
    mesg       = bytearray()
    while recvdSoFar < length:
        try:
            chunk = sock.recv(min(length - recvdSoFar, maxRecvLen))
        except socket.error as v:
            errorcode = v[0]
            write("ERROR: recvall failed Errno [{}]\n".format(errorcode))
            exit(0)
        #chunk = chunk.decode('ascii')
        recvdSoFar += len(chunk)
        mesg += chunk
    ic("recvall",mesg)
    return mesg


def recvLen(sock):
    """
    Receives the '#' suffixed length of the subsequent message.
    """
    length = ""
    char   = sock.recv(1).decode('ascii')
    while char != "#":
        length += char
        char = sock.recv(1).decode('ascii')
    try:
        length = int(length)
    except ValueError:
        write("ERROR: Received length has no valid value\n")
        exit(0)
    except socket.error as v:
        errorcode = v[0]
        write("ERROR: recvLen failed Errno [{}]\n".format(errorcode))
        exit(0)
    return length


def sendallPrefixed(sock, mesg):
    """
    Sends the message with its length prefixed
    """
    try:
        mesg = bytes(mesg, 'ascii')
        prefix = bytes(str(len(mesg)) + "#", 'ascii')
        sock.sendall(prefix)
        sock.sendall(mesg)
    except socket.error as v:
        errorcode = v[0]
        write("ERROR: sendallPrefixed failed Errno [{}]\n".format(errorcode))
        exit(0)


def checkArgs(argv):
    """
    Checks and sets the arguments given to the program.
    If no or a wrong argument is given, help is printed.
    """
    argv = argv[1:]
    global remotehost
    global port
    global user
    global mesgsizes
    global useTunnel
    global outfile
    global mode
    global verbose

    i = 0
    required = 0
    while i < len(argv):
        option = argv[i]

        if option == "-r":
            required += 1
            try:
                arg = argv[i+1]

                if '@' in arg:
                    temp = arg.split('@')
                    user = temp[0]
                    remotehost = temp[1]
                    mode = "auto"
                    i += 2
                elif not isOption(arg):
                    remotehost = arg
                    mode = "send"
                    i += 2
                else:
                    mode = "receive"
                    i += 1
            except IndexError:
                mode = "receive"
                i += 1

        elif option == "-p":
            try:
                port = int(argv[i+1])
                i += 2
            except ValueError:
                write("ERROR: Port must be an number\n")
                exit(0)
            except IndexError:
                write("ERROR: Port must be given\n")
                exit(0)

        elif option == "-s":
            try:
                mesgsizes = map(int, argv[i+1].split(','))
                filter(lambda a: a != 0, mesgsizes)
                mesgsizes = list(mesgsizes)
                i += 2
            except IndexError:
                write("ERROR: Messagesizes not given.\n")
                exit(0)
            except ValueError:
                write("ERROR: Given sizes have wrong format\n")
                exit(0)

        elif (option == "-o"):
            try:
                outfile = argv[i+1]
                i += 2
            except IndexError:
                write("ERROR: Filename not given\n")
                exit(0)

        elif (option == "-t"):
            useTunnel = True
            i += 1

        elif (option == "-v"):
            verbose = True
            i += 1

        else:
            write(helpstr)
            exit(0)

    if verbose == False and icecreamPresent:
        ic.disable()

    if (required != 1):
        write(helpstr)
        exit(0)
    return


def waitForReceiver():
    """
    If an ssh tunnel is used, calling connect will just create a TCP connection
    to the ssh process on local side. We won't get notified when ssh connects to
    the receiver, thus calling receive before a connection is established ends
    up crashing the application.
    The function provides the receiver a maximum of 30 seconds to setup and
    listen on the remote port.
    """
    trys    = 1
    maxTrys = 30
    ready   = False
    command = 'ssh {}@{} "lsof -P -i tcp:{}"'.format(user,
                remotehost, port)
    write("  executing: " + command + "\n", False)

    while not ready and trys < maxTrys:
        returncode = executeAndWait(command)
        if returncode == 1:
            write("  receiver not ready {}. try\n".format(trys))
            trys += 1
            time.sleep(1)
        else:
            ready = True
            time.sleep(1)

    if not ready:
        write("ERROR: Timeout expired while waiting for receiver.\n")
        exit(0)


def checkRemotePort():
    """
    If the remote port is in use before the application starts, this will print
    an error message.
    """
    command = 'ssh {}@{} "netstat -n | grep localhost:{}"'.format(user,
            remotehost, port)
    returncode = executeAndWait(command)
    if returncode == 0:
        write('ERROR: Remote Port {} is in use.\n'.format(port))
        exit(0)

    command = 'ssh {}@{} "lsof -P -i tcp:{}"'.format(user, remotehost,
            port)
    returncode = executeAndWait(command)
    if returncode == 0:
        write('ERROR: Remote Port {} is in use.\n'.format(port))
        write('Try "lsof -P -i tcp:{}" to find out which process is using the port\n'.format(port))
        exit(0)


def checkLocalPort():
    """
    If the port is in use, this will print an error message.
    """
    command = '(netstat -n | grep localhost:{})'.format(port)
    returncode = executeAndWait(command)
    if returncode == 0:
        write('ERROR: Port {} is in use.\n'.format(port))
        exit(0)

    command = '(lsof -P -i tcp:{})'.format(port)
    returncode = executeAndWait(command)
    if returncode == 0:
        write('ERROR: Port {} is in use.\n'.format(port))
        write('Try "lsof -P -i tcp:{}" to find out which process is using the port.\n'.format(port))
        exit(0)


def printLatencyMeasurement(size, avg, std):
    """
    Prints a latency measurement with the corresponding size
    to console.
    """
    line = "{:>11}  {:>10.5f}  {:>10.5f}\n".format(size, avg, std)
    write(line)


def plotLatencyResults(measuredLatencys):
    """
    Plots the results of the latency test to file and if possible to screen.
    """
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
    except ImportError:
        write("WARNING: Could not import matplotlib. No plots are created.\n")
        return

    x = mesgsizes
    y = measuredLatencys[1]
    e = measuredLatencys[2]

    fig, ax = plt.subplots()
    ax.errorbar(x, y, e, fmt='--o', ecolor='r', capthick=2)
    ax.set_title("Measured Latency")
    ax.set_xlabel("Datasize in Bytes")
    ax.set_ylabel("Time in Seconds")
    ax.set_xscale("log")
    plt.savefig(outfile)

    if "DISPLAY" in os.environ:
        plt.show()


def writeRawFile(measuredLatencys):
    """
    Writes the raw measurements into json file.
    """
    rawFileName = outfile.split('.')[0] + "RAW.json"
    with open(rawFileName, 'w') as f:
        json.dump({'Repeats' : measuredLatencys[0].tolist(),
                   'AVG'     : measuredLatencys[1].tolist(),
                   'SD'      : measuredLatencys[2].tolist()
                  }, f)


def signalHandler(sig, frame):
    exit(0)


def exit(code):
    write("\nClosing Application\n", False)
    if type(sock) is socket.socket:
        sock.close()
    if type(tunnel) is subprocess.Popen:
        tunnel.terminate()
    sys.exit(code)


def executeAndWait(command, suppress=True):
    """
    Executes the given command in /bin/sh  as a child process, waits for
    termination and returns the returncode. The suppress parameter decides
    on weather stdout is printed or not.
    """
    proc = execute(command, suppress)
    proc.wait()
    return proc.returncode


def execute(command, suppress=True):
    """
    Executes the given command in /bin/sh  as a child process, and returns the
    subprocess handle. The suppress parameter decides on weather stdout is
    printed or not.
    """
    write("  executing: " + command + "\n", False)
    if suppress:
        devnull = open(os.devnull, 'w')
        sp = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE,
                stdout=devnull, close_fds=True)
    else:
        sp = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)
    return sp


def isOption(arg):
    options = ['-r', '-s', '-t', '-o', '-p', '-v']
    return arg in options


def write(s, essential=True):
    if verbose or essential:
        sys.stdout.write(s)
        sys.stdout.flush()


signal.signal(signal.SIGINT, signalHandler)
main(sys.argv)
