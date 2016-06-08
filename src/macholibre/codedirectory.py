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


class CodeDirectory(object):

    # Constructor
    def __init__(self, version=None, flags=None, hash_offset=None,
                 ident_offset=None, n_special_slots=None, n_code_slots=None,
                 code_limit=None, hash_size=None, hash_type=None,
                 platform=None, page_size=None, scatter_offset=None,
                 team_id_offset=None, identity=None, team_id=None):
        self._version = version
        self._flags = flags
        self._hash_offset = hash_offset
        self._ident_offset = ident_offset
        self._n_special_slots = n_special_slots
        self._n_code_slots = n_code_slots
        self._code_limit = code_limit
        self._hash_size = hash_size
        self._hash_type = hash_type
        self._platform = platform
        self._page_size = page_size
        self._scatter_offset = scatter_offset
        self._team_id_offset = team_id_offset
        self._identity = identity
        self._team_id = team_id
        self._hashes = []

    # Getters
    def getSize(self): return self._size

    def getVersion(self): return self._version

    def getFlags(self): return self._flags

    def getHashOffset(self): return self._hash_offset

    def getIdentOffset(self): return self._ident_offset

    def getNSpecialSlots(self): return self._n_special_slots

    def getNCodeSlots(self): return self._n_code_slots

    def getCodeLimit(self): return self._code_limit

    def getHashSize(self): return self._hash_size

    def getHashType(self): return self._hash_type

    def getPlatform(self):
        if self._version >= 0x20200:
            return self._platform
        return None

    def getPageSize(self): return self._page_size

    def getScatterOffset(self):
        if self._version >= 0x20100:
            return self._scatter_offset
        return None

    def getTeamIDOffset(self):
        if self._version >= 0x20200:
            return self._team_id_offset

    def getIdentity(self): return self._identity

    def getTeamID(self):
        if self._version >= 0x20200 and self._team_id_offset != 0:
            return self._team_id
        return None

    # Setters
    def setSize(self, size): self._size = size

    def setVersion(self, version): self._version = version

    def setFlags(self, flags): self._flags = flags

    def setHashOffset(self, hash_offset): self._hash_offset = hash_offset

    def setIdentOffset(self, ident_offset): self._ident_offset = ident_offset

    def setNSpecialSlots(self, n_special_slots):
        self._n_special_slots = n_special_slots

    def setNCodeSlots(self, n_code_slots): self._n_code_slots = n_code_slots

    def setCodeLimit(self, code_limit): self._code_limit = code_limit

    def setHashSize(self, hash_size): self._hash_size = hash_size

    def setHashType(self, hash_type): self._hash_type = hash_type

    def setPlatform(self, platform): self._platform = platform

    def setPageSize(self, page_size): self._page_size = page_size

    def setScatterOffset(self, scatter_offset):
        self._scatter_offset = scatter_offset

    def setTeamIDOffset(self, team_id_offset):
        self._team_id_offset = team_id_offset

    def setIdentity(self, identity): self._identity = identity

    def setTeamID(self, team_id): self._team_id = team_id

    # Generators
    def genHashes(self):
        for i in self._hashes:
            yield i

    # Functions
    def addHash(self, hash): self._hashes.append(hash)
