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


class SymbolTable(object):

    # Constructor
    def __init__(self, offset=None, nsyms=None):
        # Fields
        self._offset = offset
        self._nsyms = nsyms
        self._il = None
        self._nl = None
        self._ie = None
        self._ne = None
        self._iu = None
        self._nu = None
        self._syms = []

    # Getters
    def getOffset(self): return self._offset

    def getNSyms(self): return self._nsyms

    def getIL(self): return self._il

    def getNL(self): return self._nl

    def getIE(self): return self._ie

    def getNE(self): return self._ne

    def getIU(self): return self._iu

    def getNU(self): return self._nu

    def getSyms(self): return self._syms

    # Setters
    def setOffset(self, offset): self._offset = offset

    def setNSyms(self, nsyms): self._nsyms = nsyms

    def setIL(self, il): self._il = il

    def setNL(self, nl): self._nl = nl

    def setIE(self, ie): self._ie = ie

    def setNE(self, ne): self._ne = ne

    def setIU(self, iu): self._iu = iu

    def setNU(self, nu): self._nu = nu

    def setSyms(self, syms): self._syms = syms

    # Generators
    def genSyms(self):
        for i in self._syms:
            yield i

    # Functions
    def addSym(self, sym): self._syms.append(sym)
