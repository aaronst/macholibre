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
from analyzer import Analyzer
from exceptions import Exception


# Encoding
reload(sys)  
sys.setdefaultencoding('utf-8')

# Functions
def processFile(path, f=None):
    p = Parser(path=path)
    p.parseFile()
    a = Analyzer(parser=p)
    a.analyze()
    j = Packer(analyzer=a)
    if f is None:
        return j.pack()
    else:
        j.pack(f=f)

# Beginning of Script
if __name__ == '__main__':
    h = Handler()
    h.digest(sys.argv)

    if data.o is not None:
        f = codecs.open(data.o, 'w', encoding='utf-8')
    else:
	f = None

    if data.r is None:
        try:
            processFile(sys.argv[1], f=f)
        except Exception as e:
            print ('Bad file: ' + sys.argv[1])
            logging.error(traceback.format_exc())
    else:
        f.write('[')
        count = 1
        for i in glob(data.r):
            try:
                print ('Processing file #' + str(count) + ': ' + i)
                processFile(i, f=f)
                if count < len(glob(data.r)):
                    f.write(',')
            except Exception as e:
                print ('Bad file: ' + i)
                logging.error(traceback.format_exc())

            if count == len(glob(data.r)):
                f.write(']')
            count += 1

    if data.o is not None:
        f.close()

