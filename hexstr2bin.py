#!/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
import binascii

def convert(f_in, f_out):
    with open(f_in) as fd_in, open(f_out, "wb") as fd_out:
        for line in fd_in:
            chunk = binascii.unhexlify(line.rstrip())
            fd_out.write(chunk)


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_file> <output_file>")
        sys.exit(1)

    f_in = sys.argv[1]
    f_out = sys.argv[2]
    convert(f_in, f_out)
