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
                 initprot=None, nsects=None, entropy=None):
        # Fields
        self.name = name
        self.vmaddr = vmaddr
        self.vmsize = vmsize
        self.offset = offset
        self.segsize = segsize
        self.maxprot = maxprot
        self.initprot = initprot
        self.nsects = nsects
        self.entropy = entropy
        self.sects = []
        self.flags = []
        super(Segment, self).__init__(cmd, size)

    # Generators
    def gen_sects(self):
        for i in self.sects:
            yield i

    def gen_flags(self):
        for i in self.flags:
            yield i

    # Functions
    def add_sect(self, sect): self.sects.append(sect)

    def add_flag(self, flag): self.flags.append(flag)

