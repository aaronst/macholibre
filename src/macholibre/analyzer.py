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


import math


class Analyzer(object):

    # Constructor
    def __init__(self, parser=None):
        self._parser = parser

    # Getters
    def getParser(self): return self._parser

    # Setters
    def setParser(self, parser): self._parser = parser

    # Functions
    def calcNImps(self, macho):
        macho.addAnalytic('nimps', len(macho.getImports()))

    def calcNDylibs(self, macho):
        macho.addAnalytic('ndylibs', len(macho.getDylibs()))

    def calcSNLCR(self, macho):
        slcs = 1.0 * macho.getSLCs()
        nlcs = 1.0 * macho.getNLCs()
        macho.addAnalytic('snlcr', slcs / nlcs)

    def calcEntropy(self, macho):
        byteCounts = {}
        f = self._parser.getF()
        f.seek(macho.getOffset())
        for i in range(256):
            byteCounts[i] = 0
        for i in bytearray(f.read(macho.getSize())):
            byteCounts[i] += 1

        total = float(sum(byteCounts.values()))
        entropy = 0
        for count in byteCounts.itervalues():
            if count == 0:
                continue
            p = float(count) / total
            entropy -= p * math.log(p, 256)

        macho.addAnalytic('entropy', entropy)

    def populateAnalytics(self, macho):
        self.calcNImps(macho)
        self.calcNDylibs(macho)
        # self.calcSNLCR(macho)
        self.calcEntropy(macho)

    def analyze(self):
        if self._parser.getFile().isUniversal():
            for i in self._parser.getFile().getContent().getMachOs():
                self.populateAnalytics(i)
        else:
            self.populateAnalytics(self._parser.getFile().getContent())
