#!/usr/bin/python

'''
Copyright 2016 Aaron Stephens <aaron@icebrg.io>, ICEBRG

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''


import sys
import data
import codecs
import logging
import traceback

from glob import glob
from parser import Parser
from packer import Packer
from handler import Handler
from json import dump, dumps
from exceptions import Exception
from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter


# Encoding
reload(sys)  
sys.setdefaultencoding('utf-8')

# Functions
def parse(path, f=None):
    p = Parser(path=path)
    p.parse_file()
    j = Packer(parser=p)
    if f is None:
        return j.pack()
    else:
        j.pack(f=f)

def output_file(path):
    return codecs.open(path, 'w', encoding='utf-8')

# Beginning of Script
if __name__ == '__main__':
    parser = ArgumentParser(description='MachoLibre: Mach-O & Universal Binary Parser\
        \n  aaron@icebrg.io',
        formatter_class=RawDescriptionHelpFormatter,
        epilog='examples:\n  python macholibre.py macho\
            \n  python macholibre.py -o output.json macho\
            \n  python macholibre.py -o output.json "machos/*"')
    parser.add_argument('input', type=glob,
        help='input mach-o file (or glob in quotes) to parse')
    parser.add_argument('-o', '--output', type=output_file, help='output JSON file')

    args = parser.parse_args()

    if len(args.input) == 1:
        try:
            if (args.output) is not None:
                parse(args.input[0], f=args.output)
            else:
                print parse(args.input[0])
        except:
            print('Could not parse file: %s' % args.input[0])
            logging.error(traceback.format_exc())
    else:
        # handle json array manually so we don't hold all the results in memory
        if args.output is not None:
            args.output.write('[')
        count = 1
        for i in args.input:
            print ('Processing file #%d: %s' % (count, i))
            try:
                if args.output is not None:
                    parse(i, f=args.output)
                    if count < len(args.input):
                        args.output.write(',')
                else:
                    print parse(i)
                    if count < len(args.input):
                        print ('\n')
            except Exception as e:
                print ('Could not parse file: %s' % i)
                logging.error(traceback.format_exc())
            count += 1
        if args.output is not None:
            args.output.write(']')

