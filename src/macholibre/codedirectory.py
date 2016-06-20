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
        self.version = version
        self.flags = flags
        self.hash_offset = hash_offset
        self.ident_offset = ident_offset
        self.n_special_slots = n_special_slots
        self.n_code_slots = n_code_slots
        self.code_limit = code_limit
        self.hash_size = hash_size
        self.hash_type = hash_type
        self._platform = platform
        self.page_size = page_size
        self._scatter_offset = scatter_offset
        self._team_id_offset = team_id_offset
        self.identity = identity
        self._team_id = team_id
        self.hashes = []

    # Properties
    @property
    def platform(self):
        if self.version >= 0x20200:
            return self._platform
        return None

    @platform.setter
    def platform(self, platform):
        self._platform = platform

    @property
    def scatter_offset(self):
        if self.version >= 0x20100:
            return self._scatter_offset
        return None

    @scatter_offset.setter
    def scatter_offset(self, scatter_offset):
        self._scatter_offset = scatter_offset

    @property
    def team_id_offset(self):
        if self.version >= 0x20200:
            return self._team_id_offset

    @team_id_offset.setter
    def team_id_offset(self, team_id_offset):
        self._team_id_offset = team_id_offset

    @property
    def team_id(self):
        if self.version >= 0x20200 and self.team_id_offset != 0:
            return self._team_id
        return None

    @team_id.setter
    def team_id(self, team_id):
        self._team_id = team_id

    # Generators
    def gen_hashes(self):
        for i in self.hashes:
            yield i

    # Functions
    def add_hash(self, hash): self.hashes.append(hash)

