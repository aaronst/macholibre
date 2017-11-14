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


from macho import MachO
from universal import Universal


class File(object):

    # Constructor
    def __init__(self, name=None, size=None, content=None):
        self.name = name
        self.size = size
        self.hashes = {}
        self.content = content

    # Functions
    def add_hash(self, key, value): self.hashes[key] = value

    def is_macho(self): return type(self.content) is MachO

    def is_universal(self): return type(self.content) is Universal

