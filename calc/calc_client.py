#!/usr/bin/python
import socket
import sys

HOST = '127.0.0.1'
PORT = 8001
my_socket = socket.socket()
my_socket.connect((HOST, PORT))

print 'Welcome to simple calculator\nUsage directions:'
print '-- A legal input should be in the format: first number, one space, operation, one space, second number'
print '-- In order to quit, enter ''EXIT'''
print 'Notes:\nA. Only +-*/ are supported\nB. Only positive numbers allowed'
print 'Example: 55 * 4'

user_input = raw_input('Enter TARGIL\n')
while user_input != 'EXIT':
    my_socket.send(user_input + '\n')
    server_reply = my_socket.recv(1024)
    print 'Server reply: ' + server_reply
    user_input = raw_input('Enter TARGIL\n')

my_socket.send(user_input + '\n')
my_socket.close()
