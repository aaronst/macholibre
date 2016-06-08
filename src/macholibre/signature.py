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


class Signature(object):

    # Constructor
    def __init__(self, offset=None, size=None, count=None):
        self._offset = offset
        self._size = size
        self._count = count
        self._codedirectory = None
        self._entitlements = []
        self._requirements = []
        self._certs = []

    # Getters
    def getOffset(self): return self._offset

    def getSize(self): return self._size

    def getCount(self): return self._count

    def getCodeDirectory(self): return self._codedirectory

    # Setters
    def setOffset(self, offset): self._offset = offset

    def setSize(self, size): self._size = size

    def setCount(self, count): self._count = count

    def setCodeDirectory(self, codedirectory):
        self._codedirectory = codedirectory

    # Generators
    def genEntitlements(self):
        for i in self._entitlements:
            yield i

    def genRequirements(self):
        for i in self._requirements:
            yield i

    def genCerts(self):
        for i in self._certs:
            yield i

    # Functions
    def addEntitlement(self, entitlement):
        self._entitlements.append(entitlement)

    def addRequirement(self, requirement):
        self._requirements.append(requirement)

    def addCert(self, cert):
        self._certs.append(cert)
