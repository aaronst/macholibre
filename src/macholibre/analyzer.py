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
        self.parser = parser

    # Functions
    def calc_n_imps(self, macho):
        macho.add_analytic('nimps', len(macho.imports))

    def calc_n_dylibs(self, macho):
        macho.add_analytic('ndylibs', len(macho.dylibs))

    # Currently not included in JSON output (see packer.py)
    def calc_snlcr(self, macho):
        slcs = float(macho.slcs)
        nlcs = float(macho.nlcs)
        macho.add_analytic('snlcr', slcs / nlcs)

    # Need to extend this to segment/section granularity
    def calc_entropy(self, macho):
        byte_counts = {}
        f = self.parser.f
        f.seek(macho.offset)
        for i in range(256):
            byte_counts[i] = 0
        for i in bytearray(f.read(macho.size)):
            byte_counts[i] += 1

        total = float(sum(byte_counts.values()))
        entropy = 0
        for count in byte_counts.itervalues():
            if count == 0:
                continue
            p = float(count) / total
            entropy -= p * math.log(p, 256)

        macho.add_analytic('entropy', entropy)

    def populate_analytics(self, macho):
        self.calc_n_imps(macho)
        self.calc_n_dylibs(macho)
        # self.calc_snlcr(macho)
        self.calc_entropy(macho)

    def analyze(self):
        if self.parser.file.is_universal():
            for i in self.parser.file.content.machos:
                self.populate_analytics(i)
        else:
            self.populate_analytics(self.parser.file.content)

