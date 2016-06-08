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


from macho import MachO
from universal import Universal


class File(object):

    # Constructor
    def __init__(self, name=None, size=None, content=None):
        self._name = name
        self._size = size
        self._hashes = {}
        self._content = content

    # Getters
    def getName(self): return self._name

    def getSize(self): return self._size

    def getHashes(self): return self._hashes

    def getContent(self): return self._content

    # Setters
    def setName(self, name): self._name = name

    def setSize(self, size): self._size = size

    def setHashes(self, hashes): self._hashes = hashes

    def setContent(self, content): self._content = content

    # Functions
    def addHash(self, key, value): self._hashes[key] = value

    def isMachO(self): return type(self._content) is MachO

    def isUniversal(self): return type(self._content) is Universal
