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


class StringTable(object):

    # Constructor
    def __init__(self, offset=None, size=None):
        # Fields
        self.offset = offset
        self.size = size
        self.strings = []

    # Generators
    def gen_strings(self):
        for i in self.strings:
            yield i

    # Functions
    def add_string(self, string): self.strings.append(string)

