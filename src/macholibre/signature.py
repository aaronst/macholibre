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
        self.offset = offset
        self.size = size
        self.count = count
        self.codedirectory = None
        self.entitlements = []
        self.requirements = []
        self.certs = []

    # Generators
    def gen_entitlements(self):
        for i in self.entitlements:
            yield i

    def gen_requirements(self):
        for i in self.requirements:
            yield i

    def gen_certs(self):
        for i in self.certs:
            yield i

    # Functions
    def add_entitlement(self, entitlement):
        self.entitlements.append(entitlement)

    def add_requirement(self, requirement):
        self.requirements.append(requirement)

    def add_cert(self, cert):
        self.certs.append(cert)

