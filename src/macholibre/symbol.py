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


class Symbol(object):

    # Constructor
    def __init__(self, index=None, stab=None, pext=None, sym_type=None,
                 ext=None, sect=None, dylib=None, ref=None, value=None):
        # Fields
        self._index = index
        self._stab = stab
        self._pext = pext
        self._type = sym_type
        self._ext = ext
        self._sect = sect
        self._dylib = dylib
        self._ref = ref
        self._value = value

    # Getters
    def getIndex(self): return self._index

    def getStab(self): return self._stab

    def getPext(self): return self._pext

    def getType(self): return self._type

    def getExt(self): return self._ext

    def getSect(self): return self._sect

    def getDylib(self): return self._dylib

    def getRef(self): return self._ref

    def getValue(self): return self._value

    # Setters
    def setIndex(self, index): self._index = index

    def setStab(self, stab): self._stab = stab

    def setPext(self, pext): self._pext = pext

    def setType(self, sym_type): self._type = sym_type

    def setExt(self, ext): self._ext = ext

    def setSect(self, sect): self._sect = sect

    def setDylib(self, dylib): self._dylib = dylib

    def setRef(self, ref): self._ref = ref

    def setValue(self, value): self._value = value

    # Functions
    def isStab(self): return self._stab is not None

    def isType(self, type): return self._type == type

    # I am defining an imported symbol as an undefined,
    # non-private, external symbol.  See below url for
    # a more in depth explanation of symbols.
    # http://math-atlas.sourceforge.net/devel/assembly/MachORuntime.pdf
    def isImp(self):
        return (self._pext == 0 and self._ext == 1 and
                (self._type == 'UNDF' or self._type == 'PBUD') and
                ((self._ref & 0xf == 0) or (self._ref & 0xf == 1)))

