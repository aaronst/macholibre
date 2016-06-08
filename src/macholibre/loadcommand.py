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


class LoadCommand(object):

    # Constructor
    def __init__(self, cmd=None, size=None):
        # Fields
        self._cmd = cmd
        self._size = size
        self._data = {}

    # Getters
    def getCmd(self): return self._cmd

    def getSize(self): return self._size

    def getData(self): return self._data

    # Setters
    def setCmd(self, cmd): self._cmd = cmd

    def setSize(self, size): self._size = size

    def setData(self, data): self._data = data

    # Generators
    def genData(self):
        for i in self._data.iteritems():
            yield i

    # Functions
    def addData(self, key, value): self._data[key] = value

    def isSegment(self):
        return self._cmd == 'SEGMENT' or self._cmd == 'SEGMENT_64'
