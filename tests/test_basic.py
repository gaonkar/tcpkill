# -*- coding: utf-8 -*-

import traceback
import time
import socket
import threading
import socketserver
import unittest
import subprocess

COUNT = 1000

def run_tcpkill(cmd):
    time.sleep(5)
    process = subprocess.Popen(cmd.split(' '))
    try:
        print('Running in process', process.pid)
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        print('Timed out - killing', process.pid)
        subprocess.Popen(['sudo', 'killall', 'tcpkill'])
        print("Done")

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        i = 0
        try:
            while i < COUNT:
                data = "Echo " + str(self.request.recv(1024), 'ascii')
                cur_thread = threading.current_thread()
                response = bytes("{}: {}".format(cur_thread.name, data), 'ascii')
                self.request.send(response)
                i = i + 1
        except:
            print("TCP Reset as server succeeded")
            return

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

def client(ip, port, message, count):
    sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout( 5.0)
    sock.setsockopt( socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    with sock:
        sock.connect((ip, port))
        with sock:
            i = 0
            cmd = "sudo ./tcpkill -i lo -s "+ip+ " -d " + ip
            cmd = cmd + " -p " + str(port) + " -q " + str(sock.getsockname()[1])
            print(cmd)
            x = threading.Thread(target=run_tcpkill,args=(cmd,))
            x.start()
            while i < count:
                try:
                    msg = message + " " + str(i)
                    sock.send(bytes(msg, 'ascii'))
                    response = str(sock.recv(1024), 'ascii')
                    print("Received: {}".format(response))
                    time.sleep(10)
                    i = i + 1
                except:
                    print("TCP Reset at client succeeded")
                    x.join()
                    return


class BasicTestSuite(unittest.TestCase):
    """Basic test cases."""

    def test_absolute_truth_and_meaning(self):
        # Port 0 means to select an arbitrary unused port
        HOST = "localhost"
        PORT = 10000

        server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
        with server:
            ip, port = server.server_address

            # Start a thread with the server -- that thread will then start one
            # more thread for each request
            server_thread = threading.Thread(target=server.serve_forever)
            # Exit the server thread when the main thread terminates
            server_thread.daemon = True
            server_thread.start()
            print("Server loop running in thread:", server_thread.name)

            client(ip, port, "Hello World", COUNT)
            server.shutdown()
        assert True


if __name__ == '__main__':
    unittest.main()
