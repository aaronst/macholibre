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


class StringTable(object):

    # Constructor
    def __init__(self, offset=None, size=None):
        # Fields
        self._offset = offset
        self._size = size
        self._strings = []

    # Getters
    def getOffset(self): return self._offset

    def getSize(self): return self._size

    def getStrings(self): return self._strings

    # Setters
    def setOffset(self, offset): self._offset = offset

    def setSize(self, size): self._size = size

    def setStrings(self, strings): self._strings = strings

    # Generators
    def genStrings(self):
        for i in self._strings:
            yield i

    # Functions
    def addString(self, string): self._strings.append(string)
