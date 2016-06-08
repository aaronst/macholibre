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


class Section(object):

    # Constructor
    def __init__(self, name=None, segname=None, addr=None, offset=None,
                 align=None, reloff=None, nreloc=None, size=None):
        # Fields
        self._name = name
        self._segname = segname
        self._addr = addr
        self._offset = offset
        self._align = align
        self._reloff = reloff
        self._nreloc = nreloc
        self._size = size
        self._type = None
        self._attrs = []

    # Getters
    def getName(self): return self._name

    def getSegName(self): return self._segname

    def getAddr(self): return self._addr

    def getOffset(self): return self._offset

    def getAlign(self): return self._align

    def getRelOff(self): return self._reloff

    def getNReloc(self): return self._nreloc

    def getSize(self): return self._size

    def getType(self): return self._type

    def getAttrs(self): return self._attrs

    # Setters
    def setName(self, name): self._name = name

    def setSegName(self, segname): self._segname = segname

    def setAddr(self, addr): self._addr = addr

    def setOffset(self, offset): self._offset = offset

    def setAlign(self, align): self._align = align

    def setRelOff(self, reloff): self._reloff = reloff

    def setNReloc(self, nreloc): self._nreloc = nreloc

    def setSize(self, size): self._size = size

    def setType(self, section_type): self._type = section_type

    def setAttrs(self, attrs): self._attrs = attrs

    # Generators
    def genAttrs(self):
        for i in self._attrs:
            yield i

    # Functions
    def addAttr(self, attr): self._attrs.append(attr)
