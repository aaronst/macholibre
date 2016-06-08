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


class MachO(object):

    # Constructor
    def __init__(self, archive=None, offset=None, arch=None,
                 endi=None, size=None, cputype=None, subtype=None,
                 filetype=None, nlcs=None, slcs=None, symtab=None,
                 strtab=None, signature=None):
        # Fields
        self._archive = archive
        self._offset = offset
        self._arch = arch
        self._endi = endi
        self._size = size
        self._cputype = cputype
        self._subtype = subtype
        self._filetype = filetype
        self._nlcs = nlcs
        self._slcs = slcs
        self._flags = []
        self._lcs = []
        self._dylibs = []
        self._symtab = symtab
        self._strtab = strtab
        self._imports = []
        self._signature = signature
        self._minos = None
        self._analytics = {}

    # Getters
    def getArchive(self): return self._archive

    def getOffset(self): return self._offset

    def getArch(self): return self._arch

    def getEndi(self): return self._endi

    def getSize(self): return self._size

    def getCPUType(self): return self._cputype

    def getSubType(self): return self._subtype

    def getFileType(self): return self._filetype

    def getNLCs(self): return self._nlcs

    def getSLCs(self): return self._slcs

    def getFlags(self): return self._flags

    def getLCs(self): return self._lcs

    def getDylibs(self): return self._dylibs

    def getSymTab(self): return self._symtab

    def getStrTab(self): return self._strtab

    def getImports(self): return self._imports

    def getSignature(self): return self._signature

    def getMinOS(self): return self._minos

    def getAnalytics(self): return self._analytics

    # Setters
    def setArchive(self, archive): self._archive = archive

    def setOffset(self, offset): self._offset = offset

    def setArch(self, arch): self._arch = arch

    def setEndi(self, endi): self._endi = endi

    def setSize(self, size): self._size = size

    def setCPUType(self, cputype): self._cputype = cputype

    def setSubType(self, subtype): self._subtype = subtype

    def setFileType(self, filetype): self._filetype = filetype

    def setNLCs(self, nlcs): self._nlcs = nlcs

    def setSLCs(self, slcs): self._slcs = slcs

    def setFlags(self, flags): self._flags = flags

    def setLCs(self, lcs): self._lcs = lcs

    def setDylibs(self, dylibs): self._dylibs = dylibs

    def setSymTab(self, symtab): self._symtab = symtab

    def setStrTab(self, strtab): self._strtab = strtab

    def setImports(self, imports): self._imports = imports

    def setSignature(self, signature): self._signature = signature

    def setMinOS(self, minos): self._minos = minos

    def setAnalytics(self, analytics): self._analytics = analytics

    # Generators
    def genFlags(self):
        for i in self._flags:
            yield i

    def genLCs(self):
        for i in self._lcs:
            yield i

    def genDylibs(self):
        for i in self._dylibs:
            yield i

    def genImports(self):
        for i in self._imports:
            yield i

    # Functions
    def isArchive(self): return self._archive

    def is32Bit(self): return self._arch == 32

    def is64Bit(self): return self._arch == 64

    def isBig(self): return self._endi == 'big'

    def isLittle(self): return self._endi == 'little'

    def addFlag(self, flag): self._flags.append(flag)

    def hasFlag(self, flag): return flag in self._flags

    def addLC(self, lc): self._lcs.append(lc)

    def hasLC(self, lc):
        for i in self.genLCs():
            if lc == i.getCmd():
                return True
        return False

    def getLC(self, lc):
        for i in self.genLCs():
            if lc == i.getCmd():
                return i
        return None

    def addDylib(self, dylib): self._dylibs.append(dylib)

    def addImport(self, imp): self._imports.append(imp)

    def addAnalytic(self, key, value): self._analytics[key] = value
