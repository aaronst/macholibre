#!/usr/bin/env python2

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


# An abonormality is the object that wraps parsing error
# information for inclusion into JSON output.
class Abnormality(object):

    # Constructor
    def __init__(self, title=None, data=None):
        self.title = title
        self.data = data

    # Functions
    def add_data(self, key, value): self.data[key] = value


def bad_content(thing, offset):
    a_type = 'BAD_CONTENT: '
    message = 'Could not parse data in {0} at offset {1}.'
    return a_type + message.format(thing, offset)


def bad_magic(expected, actual, offset):
    a_type = 'BAD_MAGIC: '
    message = 'Expected {0} magic, {1} instead at offset {2}.'
    return a_type + message.format(expected, actual, offset)


def out_of_bounds(child, size, offset, parent, parent_size, parent_offset):
    a_type = 'OUT_OF_BOUNDS: '
    message = ('{0} of {1} bytes at offset {2} is out of bounds for {3} ' +
               ' of {4} bytes at offset {5}.')
    return a_type + message.format(child, size, offset, parent,
                                   parent_size, parent_offset)

