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


import data


class Handler(object):

    # Constructor
    def __init__(self): pass

    # Functions
    def help(self):
        print ('MachoLibre - Universal & Mach-O Binary Parser')
        print ('Usage: python macholibre.py (-r <directory|glob> | <file>) [' \
              'options]')
        print ('Options:')
        print ('-h         -        Show this help stuff')
        print ('-o     <output>     Specify output file')
        print ('-r <directory|glob> Parse directory or glob')

        print ('\nFor single files, make sure you put the filename first ' \
              'before any options.\nAlso, globs need to be in quotes')

        print ('\nExamples:\n')
        print ('(Single File)')
        print ('python macholibre.py otool -o otool.json')
        print ('\n(Glob)')
        print ('python macholibre.py -r \"machos/*\" -o machos.json')

        exit(0)

    def parseOptions(self, args):
        i = 0
        while i < len(args):
            if args[i] == '-h':
                data.h = True
            elif args[i] == '-o':
                data.o = args[i + 1]
                i += 1
            elif args[i] == '-r':
                data.r = args[i + 1]
                i += 1

            i += 1

    def digest(self, args):
        if len(args) < 2:
            self.help()
        else:
            self.parseOptions(args)
            if data.h:
                self.help()
