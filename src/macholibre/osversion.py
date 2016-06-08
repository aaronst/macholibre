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


class OSVersion(object):

    # Constructor
    def __init__(self, vx=None, vy=None, vz=None):
        self._vx = vx
        self._vy = vy
        self._vz = vz
        self._version = str(vx) + '.' + str(vy) + '.' + str(vz)

    # Getters
    def getVX(self): return self._vx

    def getVY(self): return self._vy

    def getVZ(self): return self._vz

    def getVersion(self): return self._version

    # Setters
    def setVX(self, vx): self._vx = vx

    def setVY(self, vy): self._vy = vy

    def setVZ(self, vz): self._vz = vz

    def setVersion(self, version): self._version = version

    # Functions
    def compareTo(self, version):
        if self._vx < version.getVX():
            return -1
        elif self._vx > version.getVX():
            return 1
        elif self._vy < version.getVY():
            return -1
        elif self._vy > version.getVY():
            return 1
        elif self._vz < version.getVZ():
            return -1
        elif self._vz > version.getVZ():
            return 1
        else:
            return 0