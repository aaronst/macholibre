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
        self.vx = vx
        self.vy = vy
        self.vz = vz
        self.version = str(vx) + '.' + str(vy) + '.' + str(vz)

    # Functions
    def compare_to(self, version):
        if self.vx < version.vx:
            return -1
        elif self.vx > version.vx:
            return 1
        elif self.vy < version.vy:
            return -1
        elif self.vy > version.vy:
            return 1
        elif self.vz < version.vz:
            return -1
        elif self.vz > version.vz:
            return 1
        else:
            return 0

