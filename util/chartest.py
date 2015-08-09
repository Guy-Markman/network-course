#!/usr/bin/python


import util


with util.Char() as char:
    while True:
        c = char.getchar()
        if c:
            print('!%s!' % c)
