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


class Symbol(object):

    # Constructor
    def __init__(self, index=None, stab=None, pext=None, sym_type=None,
                 ext=None, sect=None, dylib=None, ref=None, value=None):
        # Fields
        self.index = index
        self.stab = stab
        self.pext = pext
        self.type = sym_type
        self.ext = ext
        self.sect = sect
        self.dylib = dylib
        self.ref = ref
        self.value = value

    # Functions
    def is_stab(self): return self.stab is not None

    def is_type(self, type): return self.type == type

    # I am defining an imported symbol as an undefined,
    # non-private, external symbol.  See below url for
    # a more in depth explanation of symbols.
    # http://math-atlas.sourceforge.net/devel/assembly/MachORuntime.pdf
    def is_imp(self):
        return (self.pext == 0 and self.ext == 1 and
                (self.type == 'UNDF' or self.type == 'PBUD') and
                ((self.ref & 0xf == 0) or (self.ref & 0xf == 1)))

