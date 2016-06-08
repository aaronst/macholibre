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


class Universal(object):

    # Fields
    _nmachos = None
    _machos = []

    # Constructor
    def __init__(self, nmachos=None):
        self._nmachos = nmachos
        self._machos = []

    # Getters
    def getNMachOs(self): return self._nmachos

    def getMachOs(self): return self._machos

    # Setters
    def setNMachOs(self, nmachos): self._nmachos = nmachos

    def setMachOs(self, machos): self._machos = machos

    # Generators
    def genMachOs(self):
        for i in self._machos:
            yield i

    # Functions
    def addMachO(self, macho): self._machos.append(macho)
