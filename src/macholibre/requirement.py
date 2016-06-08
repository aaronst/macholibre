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


class Requirement(object):

    # Constructor
    def __init__(self, req_type=None, offset=None):
        self._type = req_type
        self._offset = offset
        self._expression = None

    # Getters
    def getType(self): return self._type

    def getOffset(self): return self._offset

    def getExpression(self): return self._expression

    # Setters
    def setType(self, req_type): self._type = req_type

    def setOffset(self, offset): self._offset = offset

    def setExpression(self, expression): self._expression = expression
