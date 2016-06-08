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


import loadcommand


class Segment(loadcommand.LoadCommand):

    # Constructor
    def __init__(self, cmd=None, vmaddr=None, vmsize=None, size=None,
                 name=None, offset=None, segsize=None, maxprot=None,
                 initprot=None, nsects=None):
        # Fields
        self._name = name
        self._vmaddr = vmaddr
        self._vmsize = vmsize
        self._offset = offset
        self._segsize = segsize
        self._maxprot = maxprot
        self._initprot = initprot
        self._nsects = nsects
        self._sects = []
        self._flags = []
        super(Segment, self).__init__(cmd, size)

    # Getters
    def getName(self): return self._name

    def getVMAddr(self): return self._vmaddr

    def getVMSize(self): return self._vmsize

    def getOffset(self): return self._offset

    def getSegSize(self): return self._segsize

    def getMaxProt(self): return self._maxprot

    def getInitProt(self): return self._initprot

    def getNSects(self): return self._nsects

    def getSects(self): return self._sects

    def getFlags(self): return self._flags

    # Setters
    def setName(self, name): self._name = name

    def setVMAddr(self, vmaddr): self._vmaddr = vmaddr

    def setVMSize(self, vmsize): self._vmsize = vmsize

    def setOffset(self, offset): self._offset = offset

    def setSegSize(self, segsize): self._segsize = segsize

    def setMaxProt(self, maxprot): self._maxprot = maxprot

    def setInitProt(self, initprot): self._initprot = initprot

    def setNSects(self, nsects): self._nsects = nsects

    def setSects(self, sects): self._sects = sects

    def setFlags(self, flags): self._flags = flags

    # Generators
    def genSects(self):
        for i in self._sects:
            yield i

    def genFlags(self):
        for i in self._flags:
            yield i

    # Functions
    def addSect(self, sect): self._sects.append(sect)

    def addFlag(self, flag): self._flags.append(flag)
