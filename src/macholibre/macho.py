#!/usr/bin/env python2

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
        self.archive = archive
        self.offset = offset
        self.arch = arch
        self.endi = endi
        self.size = size
        self.cputype = cputype
        self.subtype = subtype
        self.filetype = filetype
        self.nlcs = nlcs
        self.slcs = slcs
        self.flags = []
        self.lcs = []
        self.dylibs = []
        self.symtab = symtab
        self.strtab = strtab
        self.imports = []
        self.signature = signature
        self.minos = None
        self.analytics = {}

    # Generators
    def gen_flags(self):
        for i in self.flags:
            yield i

    def gen_lcs(self):
        for i in self.lcs:
            yield i

    def gen_dylibs(self):
        for i in self.dylibs:
            yield i

    def gen_imports(self):
        for i in self.imports:
            yield i

    # Functions
    def is_archive(self): return self.archive

    def is_32_bit(self): return self.arch == 32

    def is_64_bit(self): return self.arch == 64

    def is_big(self): return self.endi == 'big'

    def is_little(self): return self.endi == 'little'

    def add_flag(self, flag): self.flags.append(flag)

    def has_flag(self, flag): return flag in self.flags

    def add_lc(self, lc): self.lcs.append(lc)

    def has_lc(self, lc):
        for i in self.gen_lcs():
            if lc == i.cmd:
                return True
        return False

    def get_lc(self, lc):
        for i in self.gen_lcs():
            if lc == i.cmd:
                return i
        return None

    def add_dylib(self, dylib): self.dylibs.append(dylib)

    def add_import(self, imp): self.imports.append(imp)

    def add_analytic(self, key, value): self.analytics[key] = value

