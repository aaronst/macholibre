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


class Expression(object):

    # Constructor
    def __init__(self, operator=None):
        self._operator = operator
        self._operands = []

    # Getters
    def getOperator(self): return self._operator

    # Setters
    def setOperator(self, operator): self._operator = operator

    def setOperands(self, operands): self._operands = operands

    # Generators
    def genOperands(self):
        for i in self._operands:
            yield i

    # Functions
    def addOperand(self, operand): self._operands.append(operand)
