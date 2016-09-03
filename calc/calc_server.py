#!/usr/bin/python
# -*- coding: utf-8 -*-

import contextlib
import socket


BIND_ADDRESS = '0.0.0.0'
BIND_PORT = 8001
MAX_LINE = len('99999 * 99999\n')
LF_BIN = '\n'.encode('utf-8')
TOKEN_EXIT = 'EXIT'
MAX_TIMEOUT = 60


# ===================================================================
# COMMUNICATION FUNCTIONS
# ===================================================================


def send_all(s, string):
    """Send entire string"""

    #
    # First understand why we need to loop.
    #
    #buf = string.encode('utf-8')
    #while buf:
    #    buf = buf[s.send(buf):]

    #
    # Then you can use the python shortcut
    #
    s.sendall(string.encode('utf-8'))


def recv_line_simple(s, max_length=1024):
    """Receive line byte by byte"""

    buf = bytearray()
    while True:
        if len(buf) > max_length:
            raise RuntimeError('Exceeded maximum line length %s' % max_length)

        t = s.recv(1)
        if not t:
            raise RuntimeError('Disconnect')
        if t == LF_BIN:
            break
        buf += t
    return buf.decode('utf-8')


def recv_line_block(
    s,
    buf,
    max_length=1024,
    block_size=1024,
):
    """Receive line by block and tail"""

    while True:
        if len(buf) > max_length:
            raise RuntimeError('Exceeded maximum line length %s' % max_length)

        n = buf.find(LF_BIN)
        if n != -1:
            break

        t = s.recv(block_size)
        if not t:
            raise RuntimeError('Disconnect')
        buf += t

    return buf[:n].decode('utf-8'), buf[n + len(LF_BIN):]


# ===================================================================
# OPERATORS
# ===================================================================


#
# Operators in python are functions
#
# Guy figured this out!
#
import operator
OPS_operator = {
    '+': operator.add,
    '-': operator.sub,
    '*': operator.mul,
    '/': operator.floordiv,
}


#
# We can write our own functions...
#
OPS_lambda = {
    '+': lambda a, b: a + b,
    '-': lambda a, b: a - b,
    '*': lambda a, b: a * b,
    '/': lambda a, b: a / b,
}


#
# Or if we do not know lambda we can
# define actual functions...
#
# Ron figured this out!
#
def add(a, b):
    return a + b
def sub(a, b):
    return a - b
def mul(a, b):
    return a * b
def div(a, b):
    return b // b
OPS_funcs = {
    '+': add,
    '-': sub,
    '*': mul,
    '/': div,
}


# Let's select one
OPS = OPS_operator
#OPS = OPS_lambda
#OPS = OPS_funcs


# ===================================================================
# INTEGER VALIDATION FUNCTIONS
# ===================================================================


def int_range(n, minimum=0, maximum=65535):
    """Check range"""
    if n < minimum:
        raise RuntimeError("Integer '%s' smaller than '%s'" % (n, minimum))
    if n > maximum:
        raise RuntimeError("Integer '%s' larger than '%s'" % (n, maximum))
    return n


def to_int_safe(s, maximum=65535):
    """Convert to integer without triggering exceptions"""

    if not set(s) <= set('0123456789'):
        raise RuntimeError("'%s' is not a positive integer" % s)

    # avoid issues with very large numbers
    if len(s) > len(str(maximum)):
        raise RuntimeError("'%s' is bigger than '%s'" % (s, maximum))

    return int_range(int(s), 0, maximum)


def to_int_exc(s, minimum=0, maximum=65535):
    """Basic integer conversion"""
    try:
        return int_range(int(s), minimum, maximum)
    except ValueError:
        raise RuntimeError("'%s' is not an integer" % s)


# Let's select one
to_int = to_int_safe
#to_int = to_int_exc


# ===================================================================
# EXPRESSION VALIDATION FUNCTIONS
# ===================================================================


import re


# Number with 5 digits, space, operator, number with 5 digits
EXP_PATTERN = re.compile(
    flags=re.VERBOSE,
    pattern=r'''
        ^
        (?P<num1>\d{1,5})
        \s
        (?P<op>[+-/*])
        \s
        (?P<num2>\d{1,5})
        $
    ''',
)


def calculate_expr_pattern(line):
    """Pattern parsing"""
    m = EXP_PATTERN.match(line)
    if not m:
        raise RuntimeError('Invalid expression')
    return OPS[m.group('op')](
        int_range(int(m.group('num1'))),
        int_range(int(m.group('num2'))),
    )


def calculate_expr_simple(line):
    """Manual parsing"""
    comps = line.split(' ')
    if len(comps) != 3:
        raise RuntimeError('Invalid expression')
    num1, op, num2 = comps
    if op not in OPS:
        raise RuntimeError('Invalid operator %s' % op)
    return OPS[op](to_int(num1), to_int(num2))


# Let's select one
calculate_expr = calculate_expr_pattern
#calculate_expr = calculate_expr_simple


# ===================================================================
# MAIN
# ===================================================================


def main():
    with contextlib.closing(
        socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )
    ) as sl:
        sl.bind((BIND_ADDRESS, BIND_PORT))
        sl.listen(1)
        while True:
            try:
                s, addr = sl.accept()
                with contextlib.closing(s):
                    # Disconnect client if it is idle too long
                    s.settimeout(MAX_TIMEOUT)

                    rest = bytearray()
                    try:
                        while True:
                            # one of these two
                            #line = recv_line_simple(s, max_length=MAX_LINE)
                            line, rest = recv_line_block(
                                s,
                                rest,
                                max_length=MAX_LINE,
                            )

                            #
                            # Disconnect if we got exit
                            #
                            if line == TOKEN_EXIT:
                                break

                            #
                            # Non critial errors, we can recover from these
                            #
                            try:
                                send_all(s, '%s\n' % calculate_expr(line))
                            except Exception as e:
                                send_all(s, 'Error: %s\n' % e)

                    except Exception as e:
                        print('Error: %s' % e)
                        send_all(s, 'Error: %s\n' % e)
            except Exception:
                print('Error: %s' % e)


if __name__ == '__main__':
    main()


# vim: expandtab tabstop=4 shiftwidth=4
