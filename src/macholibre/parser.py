"""
Copyright 2016 Aaron Stephens <aaronjst93@gmail.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""


import hashlib

from collections import Counter
from datetime import datetime
from json import dump
from math import exp, log
from os import SEEK_END
from re import split
from struct import unpack
from uuid import UUID

from asn1crypto.cms import ContentInfo
from plistlib import loads

import macholibre.dictionary as dictionary


class Parser():
    """Main object containing all the necessary functions to parse
    a mach-o binary.
    """

    def __init__(self, path):
        """Initialize instance variables and flags."""

        self.__file = open(path, 'rb')
        self.__is_64_bit = True         # default place-holder
        self.__is_little_endian = True  # ^^
        self.__macho = {}
        self.__output = {
            'name': split(r'\\|/', path)[-1]
        }

    def add_abnormality(self, abnormality):
        """Add abnormality to output."""

        if 'abnormalities' not in self.__output:
            self.__output['abnormalities'] = []

        self.__output['abnormalities'].append(abnormality)

    def calc_entropy(self, b):
        """Calculate byte entropy for given bytes."""

        byte_counts = Counter()

        entropy = 0

        for i in b:
            byte_counts[i] += 1

        total = float(sum(byte_counts.values()))

        for count in byte_counts.values():
            p = float(count) / total
            entropy -= p * log(p, 256)

        return entropy

    def get_string(self):
        """Read a null-terminated string from macho."""

        string = bytearray()

        c = self.__file.read(1)

        while c not in (b'\x00', ''):
            string += c
            c = self.__file.read(1)

        return string.decode('utf-8', errors='replace')

    def get_int(self, ignore_endian=False):
        """Read a 4-byte integer from macho, account for endian-ness."""

        integer = self.__file.read(4)

        if self.__is_little_endian and not ignore_endian:
            return int.from_bytes(integer, byteorder='little')

        return int.from_bytes(integer, byteorder='big')

    def get_ll(self):
        """Read an 8-byte long long from macho, account for endian-ness."""

        longlong = self.__file.read(8)

        if self.__is_little_endian:
            return int.from_bytes(longlong, byteorder='little')

        return int.from_bytes(longlong, byteorder='big')

    def make_version(self, version):
        """Construct a version number from given bytes."""

        vx = version >> 16
        vy = (version >> 8) & 0xff
        vz = version & 0xff

        return '{}.{}.{}'.format(vx, vy, vz)

    def identify_file(self):
        """Identify if the given file is a single Mach-O or a
        Universal binary."""

        magic = self.get_int(ignore_endian=True)

        if magic in dictionary.machos:
            return dictionary.machos[magic]
        else:
            raise ValueError('Provided file has unrecognized magic: {}'.format(
                magic))

    def parse_macho_flags(self, flags):
        """Parse ``flags`` into list of readable flags."""

        output = []

        i = 0

        while i < 28:
            if (0x1 & (flags >> i)) == 0x1:
                if 2 ** i in dictionary.flags:
                    output.append(dictionary.flags[2 ** i])
                else:
                    self.add_abnormality('Unknown mach-o flag "{}".'.format(
                        2 ** i))

            i += 1

        return output

    def get_segment_entropy(self, m_offset, offset, size):
        """Determine byte-entropy for this segment."""

        old = self.__file.tell()

        self.__file.seek(m_offset + offset)

        entropy = self.calc_entropy(self.__file.read(size))

        self.__file.seek(old)

        return entropy

    def parse_section_attrs(self, attrs):
        """Parse section attributes."""

        output = []

        for a in dictionary.section_attrs:
            if attrs & a == a:
                output.append(dictionary.section_attrs[a])

        return output

    def parse_section_flags(self, output, flags):
        """Parse section flags into section type and attributes."""

        output['type'] = dictionary.section_types[flags & 0xff]

        attrs = flags & 0xffffff00

        output['attrs'] = self.parse_section_attrs(attrs)

    def parse_section(self):
        """Parse section."""

        name = self.__file.read(16).decode().rstrip('\u0000')
        segname = self.__file.read(16).decode().rstrip('\u0000')
        addr = self.get_ll() if self.__is_64_bit else self.get_int()
        size = self.get_ll() if self.__is_64_bit else self.get_int()
        offset = self.get_int()
        align = self.get_int()
        reloff = self.get_int()
        nreloc = self.get_int()
        flags = self.get_int()

        self.__file.read(12) if self.__is_64_bit else self.__file.read(8)

        output = {
            'name': name,
            'segname': segname,
            'addr': addr,
            'offset': offset,
            'align': align,
            'reloff': reloff,
            'nreloc': nreloc,
            'size': size
        }

        self.parse_section_flags(output, flags)

        return output

    def parse_segment_flags(self, flags):
        """Parse segment flags into readable list."""

        output = []

        i = 1

        while i < 9:
            if flags & i == i:
                output.append(dictionary.segment_flags[i])
            i <<= 1

        return output

    def parse_segment(self, m_offset, m_size, cmd, cmd_size):
        """Parse segment command."""

        name = self.__file.read(16).decode().rstrip('\u0000')
        vmaddr = self.get_ll() if self.__is_64_bit else self.get_int()
        vmsize = self.get_ll() if self.__is_64_bit else self.get_int()
        offset = self.get_ll() if self.__is_64_bit else self.get_int()
        segsize = self.get_ll() if self.__is_64_bit else self.get_int()
        maxprot = self.get_int()
        initprot = self.get_int()
        nsects = self.get_int()
        flags = self.get_int()

        maxprot = dictionary.protections[maxprot & 0b111]
        initprot = dictionary.protections[initprot & 0b111]

        entropy = self.get_segment_entropy(m_offset, offset, segsize)

        output = {
            'cmd': cmd,
            'size': cmd_size,
            'name': name,
            'vmaddr': vmaddr,
            'vmsize': vmsize,
            'offset': offset,
            'segsize': segsize,
            'maxprot': maxprot,
            'initprot': initprot,
            'nsects': nsects,
            'entropy': entropy,
            'sects': []
        }

        sect_size = 80 if self.__is_64_bit else 68

        for _ in range(nsects):
            if self.__file.tell() + sect_size > m_offset + m_size:
                self.add_abnormality('Section at offset "{}" with size "{}" '
                                     'greater than mach-o size.'.format(
                                         self.__file.tell(), sect_size))

                break

            output['sects'].append(self.parse_section())

        output['flags'] = self.parse_segment_flags(flags)

        return output

    def parse_symtab(self, cmd, cmd_size):
        """Parse symbol table load command."""

        symoff = self.get_int()
        nsyms = self.get_int()
        stroff = self.get_int()
        strsize = self.get_int()

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'symoff': symoff,
            'nsyms': nsyms,
            'stroff': stroff,
            'strsize': strsize
        }

        return output

    def parse_symseg(self, cmd, cmd_size):
        """Parse link-edit gdb symbol table info (obsolete)."""

        offset = self.get_int()
        size = self.get_int()

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'offset': offset,
            'size': size
        }

        return output

    def parse_thread(self, cmd, cmd_size):
        """Parse thread load command."""

        state = self.get_int()
        count = self.get_int()

        self.__file.read(cmd_size - 16)  # skip thread_state objects.
        # TODO: parse them, definitions in <machine/thread_status.h>

        if state in dictionary.thread_states:
            state = dictionary.thread_states[state]
        else:
            self.add_abnormality('Invalid THREAD STATE FLAVOR "{}" at offset '
                                 '"{}".'.format(state, self.__file.tell() - 8))

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'state': state,
            'count': count
        }

        return output

    def parse_fvmlib(self, cmd, cmd_size):
        """Parse fvmlib load command."""

        offset = self.__file.tell() - 8

        self.__file.read(4)  # skip name offset

        minor_version = self.get_int()
        header_addr = self.get_int()
        name = self.get_string()

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'name': name,
            'minor_version': self.make_version(minor_version),
            'header_addr': header_addr
        }

        self.__file.read(cmd_size - (self.__file.tell() - offset))

        return output

    def parse_ident(self, cmd, cmd_size):
        """Parse object identification info (obsolete)."""

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'strings': []
        }

        end = self.__file.tell() - 8 + cmd_size

        while self.__file.tell() < end:
            string = self.get_string()

            if string != '':
                output['strings'].append(string)

        return output

    def parse_fvmfile(self, cmd, cmd_size):
        """Parse fixed VM file inclusion (internal use)."""

        name = self.get_string()
        header_addr = self.get_int()

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'name': name,
            'header_addr': header_addr
        }

        return output

    def parse_prepage(self, cmd, cmd_size):
        """Parse prepage command (internal use). Load command structure not
        found.
        """

        self.__file.read(cmd_size - 8)

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size
        }

        return output

    def parse_dysymtab(self, cmd, cmd_size):
        """Parse dynamic link-edit symbol table info."""

        ilocalsym = self.get_int()       # index to local symbols
        nlocalsym = self.get_int()       # number of local symbols
        iextdefsym = self.get_int()      # index to externally defined sybmols
        nextdefsym = self.get_int()      # number of externally defined symbols
        iundefsym = self.get_int()       # index to undefined symbols
        nundefsym = self.get_int()       # number of externally defined symbols
        tocoff = self.get_int()          # file offset to table of contents
        ntoc = self.get_int()            # number of module table entries
        modtaboff = self.get_int()       # file offset to module table
        nmodtab = self.get_int()         # number of module table entries
        extrefsymoff = self.get_int()    # offset to referenced symbol table
        nextrefsyms = self.get_int()     # number of referenced symbol table entries
        indirectsymoff = self.get_int()  # file offset to the indirect symbol table
        nindirectsyms = self.get_int()   # number of indirect symbol table entries
        extreloff = self.get_int()       # offset to external relocation entries
        nextrel = self.get_int()         # number of external relocation entries
        locreloff = self.get_int()       # offset to local relocation entries
        nlocrel = self.get_int()         # number of local relocation entries

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'ilocalsym': ilocalsym,
            'nlocalsym': nlocalsym,
            'iextdefsym': iextdefsym,
            'nextdefsym': nextdefsym,
            'iundefsym': iundefsym,
            'nundefsym': nundefsym,
            'tocoff': tocoff,
            'ntoc': ntoc,
            'modtaboff': modtaboff,
            'nmodtab': nmodtab,
            'extrefsymoff': extrefsymoff,
            'nextrefsyms': nextrefsyms,
            'indirectsymoff': indirectsymoff,
            'nindirectsyms': nindirectsyms,
            'extreloff': extreloff,
            'nextrel': nextrel,
            'locreloff': locreloff,
            'nlocrel': nlocrel
        }

        return output

    def parse_load_dylib(self, cmd, cmd_size):
        """Parse dylib load command."""

        offset = self.__file.tell() - 8

        self.__file.read(4)  # skip name offset

        timestamp = self.get_int()
        current_version = self.get_int()
        compatibility_version = self.get_int()
        name = self.get_string()

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'name': name,
            'timestamp': datetime.fromtimestamp(timestamp).strftime(
                '%Y-%m-%d %H:%M:%S'),
            'current_version': self.make_version(current_version),
            'compatability_version': self.make_version(compatibility_version)
        }

        # skip padding
        self.__file.read(cmd_size - (self.__file.tell() - offset))

        return output

    def parse_load_dylinker(self, cmd, cmd_size):
        """Parse dylinker load command."""

        offset = self.__file.tell() - 8

        self.__file.read(4)  # skip name offset

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'name': self.get_string()
        }

        # skip padding
        self.__file.read(cmd_size - (self.__file.tell() - offset))

        return output

    def parse_prebound_dylib(self, cmd, cmd_size):
        """Parse prebound dylib load command.  An executable that is prebound to
        its dynamic libraries will have one of these for each library that the
        static linker used in prebinding.
        """

        name = self.get_string()
        nmodules = self.get_int()
        linked_modules = self.get_string()

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'name': name,
            'nmodules': nmodules,
            'linked_modules': linked_modules
        }

        return output

    def parse_routines(self, cmd, cmd_size):
        """Parse routines load command. The routines command contains the
        address of the dynamic shared library initialization routine and an
        index into the module table for the module that defines the routine.
        """

        init_address = self.get_ll() if self.__is_64_bit else self.get_int()
        init_module = self.get_ll() if self.__is_64_bit else self.get_int()

        self.__file.read(48) if self.__is_64_bit else self.__file.read(24)

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'init_address': init_address,
            'init_module': init_module
        }

        return output

    def parse_sub_stuff(self, cmd, cmd_size):
        """Parse sub_* load command."""

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'name': self.get_string()
        }

        return output

    def parse_twolevel_hints(self, cmd, cmd_size):
        """Parse two-level hints load command."""

        offset = self.get_int()
        nhints = self.get_int()

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'offset': offset,
            'nhints': nhints
        }

        return output

    def parse_prebind_cksum(self, cmd, cmd_size):
        """Parse prebind checksum load command."""

        cksum = self.get_int()

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'cksum': cksum
        }

        return output

    def parse_uuid(self, cmd, cmd_size):
        """Parse UUID load command."""

        uuid = self.__file.read(16)

        if self.__is_little_endian:
            uuid = unpack('<16s', uuid)[0]

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'uuid': UUID(bytes=uuid).hex
        }

        return output

    def parse_linkedit_data(self, cmd, cmd_size):
        """Parse link-edit data load command."""

        dataoff = self.get_int()   # file offset of data in __LINKEDIT segment
        datasize = self.get_int()  # file size of data in __LINKEDIT segment

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'dataoff': dataoff,
            'datasize': datasize
        }

        return output

    def parse_encryption_info(self, cmd, cmd_size):
        """Parse encryption info load command. Contains the file offset and size
        of an encrypted segment.
        """

        cryptoff = self.get_int()
        cryptsize = self.get_int()
        cryptid = self.get_int()

        if cmd.endswith('64'):
            self.__file.read(4)  # skip padding

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'cryptoff': cryptoff,
            'cryptsize': cryptsize,
            'cryptid': cryptid
        }

        return output

    def parse_dyld_info(self, cmd, cmd_size):
        """Parse dyld info load command. contains the file offsets and sizes of
        the new compressed form of the information dyld needs to load the
        image. This information is used by dyld on Mac OS X 10.6 and later. All
        information pointed to by this command is encoded using byte streams,
        so no endian swapping is needed to interpret it.
        """

        rebase_off = self.get_int()      # file offset to rebase info
        rebase_size = self.get_int()     # size of rebase info
        bind_off = self.get_int()        # file offset to binding info
        bind_size = self.get_int()       # size of binding info
        weak_bind_off = self.get_int()   # file offset to weak binding info
        weak_bind_size = self.get_int()  # size of weak binding info
        lazy_bind_off = self.get_int()   # file offset to lazy binding info
        lazy_bind_size = self.get_int()  # size of lazy binding info
        export_off = self.get_int()      # file offset to export info
        export_size = self.get_int()     # size of offset info

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'rebase_off': rebase_off,
            'rebase_size': rebase_size,
            'bind_off': bind_off,
            'bind_size': bind_size,
            'weak_bind_off': weak_bind_off,
            'weak_bind_size': weak_bind_size,
            'lazy_bind_off': lazy_bind_off,
            'lazy_bind_size': lazy_bind_size,
            'export_off': export_off,
            'export_size': export_size
        }

        return output

    def parse_version_min_os(self, cmd, cmd_size):
        """Parse minimum OS version load command."""

        version = self.get_int()
        sdk = self.get_int()

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'version': self.make_version(version),
            'sdk': self.make_version(sdk)
        }

        return output

    def parse_source_version(self, cmd, cmd_size):
        """Parse source version load command."""

        version = self.get_ll()  # A.B.C.D.E packed as a24.b10.c10.d10.e10

        mask = 0b1111111111  # 10 bit mask for B, C, D, and E

        a = version >> 40
        b = (version >> 30) & mask
        c = (version >> 20) & mask
        d = (version >> 10) & mask
        e = version & mask

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'version': '{}.{}.{}.{}.{}'.format(a, b, c, d, e)
        }

        return output

    def parse_linker_option(self, cmd, cmd_size):
        """Parse linker options load command."""

        start = self.__file.tell() - 8

        count = self.get_int()

        linker_options = []

        for _ in range(count):
            linker_options.append(self.get_string())

        self.__file.read(cmd_size - (self.__file.tell() - start))

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'count': count,
            'linker_options': linker_options
        }

        return output

    def parse_rpath(self, cmd, cmd_size):
        """Parse rpath load command."""

        offset = self.__file.tell() - 8

        self.__file.read(4)  # skip path offset

        path = self.get_string()

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'path': path
        }

        self.__file.read(cmd_size - (self.__file.tell() - offset))

        return output

    def parse_main(self, cmd, cmd_size):
        """Parse main load command."""

        entryoff = self.get_ll()   # file (__TEXT) offset of main()
        stacksize = self.get_ll()  # if not zero, initialize stack size

        output = {
            'cmd': cmd,
            'cmd_size': cmd_size,
            'entryoff': entryoff,
            'stacksize': stacksize
        }

        return output

    def parse_lcs(self, offset, size, nlcs, slcs):
        """Determine which load commands are present and parse each one
        accordingly. Return as a list.

        Load command structures found in '/usr/include/mach-o/loader.h'.
        """

        self.__macho['lcs'] = []

        for _ in range(nlcs):
            cmd = self.get_int()       # Load command type
            cmd_size = self.get_int()  # Size of load command

            if self.__is_64_bit and cmd_size % 8 != 0:
                raise ValueError('Load command size "{}" for 64-bit mach-o at '
                                 'offset "{}" is not divisible by 8.'.format(
                                    cmd_size, self.__file.tell() - 4))
            elif cmd_size % 4 != 0:
                raise ValueError('Load command size "{}" for 32-bit mach-o at '
                                 'offset "{}" is not divisible by 4.'.format(
                                    cmd_size, self.__file.tell() - 4))

            if cmd in dictionary.loadcommands:
                cmd = dictionary.loadcommands[cmd]
            else:
                self.add_abnormality('Unknown load command "{}" at offset '
                                     '"{}".'.format(
                                         cmd, self.__file.tell() - 8))

                self.__file.read(cmd_size - 8)  # skip load command

            if cmd == 'SEGMENT' or cmd == 'SEGMENT_64':
                self.__macho['lcs'].append(
                    self.parse_segment(offset, size, cmd, cmd_size))
            elif cmd == 'SYMTAB':
                self.__macho['lcs'].append(self.parse_symtab(cmd, cmd_size))
            elif cmd == 'SYMSEG':
                self.__macho['lcs'].append(self.parse_symseg(cmd, cmd_size))
            elif cmd in ('THREAD', 'UNIXTHREAD'):
                self.__macho['lcs'].append(self.parse_thread(cmd, cmd_size))
            elif cmd in ('LOADFVMLIB', 'IDFVMLIB'):
                self.__macho['lcs'].append(self.parse_fvmlib(cmd, cmd_size))
            elif cmd == 'IDENT':
                self.__macho['lcs'].append(self.parse_ident(cmd, cmd_size))
            elif cmd == 'FVMFILE':
                self.__macho['lcs'].append(self.parse_fvmfile(cmd, cmd_size))
            elif cmd == 'PREPAGE':
                self.__macho['lcs'].append(self.parse_prepage(cmd, cmd_size))
            elif cmd == 'DYSYMTAB':
                self.__macho['lcs'].append(self.parse_dysymtab(cmd, cmd_size))
            elif cmd in ('LOAD_DYLIB', 'ID_DYLIB', 'LAZY_LOAD_DYLIB',
                         'LOAD_WEAK_DYLIB', 'REEXPORT_DYLIB',
                         'LOAD_UPWARD_DYLIB'):
                self.__macho['lcs'].append(
                    self.parse_load_dylib(cmd, cmd_size))
            elif cmd in ('LOAD_DYLINKER', 'ID_DYLINKER', 'DYLD_ENVIRONMENT'):
                self.__macho['lcs'].append(
                    self.parse_load_dylinker(cmd, cmd_size))
            elif cmd == 'PREBOUND_DYLIB':
                self.__macho['lcs'].append(
                    self.parse_prebound_dylib(cmd, cmd_size))
            elif cmd in ('ROUTINES', 'ROUTINES_64'):
                self.__macho['lcs'].append(self.parse_routines(cmd, cmd_size))
            elif cmd in ('SUB_FRAMEWORK', 'SUB_UMBRELLA', 'SUB_CLIENT',
                         'SUB_LIBRARY'):
                self.__macho['lcs'].append(self.parse_sub_stuff(cmd, cmd_size))
            elif cmd == 'TWOLEVEL_HINTS':
                self.__macho['lcs'].append(
                    self.parse_twolevel_hints(cmd, cmd_size))
            elif cmd == 'PREBIND_CKSUM':
                self.__macho['lcs'].append(
                    self.parse_prebind_cksum(cmd, cmd_size))
            elif cmd == 'UUID':
                self.__macho['lcs'].append(self.parse_uuid(cmd, cmd_size))
            elif cmd in ('CODE_SIGNATURE', 'SEGMENT_SPLIT_INFO',
                         'FUNCTION_STARTS', 'DATA_IN_CODE',
                         'DYLIB_CODE_SIGN_DRS', 'LINKER_OPTIMIZATION_HINT'):
                self.__macho['lcs'].append(
                    self.parse_linkedit_data(cmd, cmd_size))
            elif cmd in ('ENCRYPTION_INFO', 'ENCRYPTION_INFO_64'):
                self.__macho['lcs'].append(
                    self.parse_encryption_info(cmd, cmd_size))
            elif cmd in ('DYLD_INFO', 'DYLD_INFO_ONLY'):
                self.__macho['lcs'].append(self.parse_dyld_info(cmd, cmd_size))
            elif cmd in ('VERSION_MIN_MACOSX', 'VERSION_MIN_IPHONEOS',
                         'VERSION_MIN_WATCHOS', 'VERSION_MIN_TVOS'):
                self.__macho['lcs'].append(
                    self.parse_version_min_os(cmd, cmd_size))
            elif cmd == 'SOURCE_VERSION':
                self.__macho['lcs'].append(
                    self.parse_source_version(cmd, cmd_size))
            elif cmd == 'LINKER_OPTION':
                self.__macho['lcs'].append(
                    self.parse_linker_option(cmd, cmd_size))
            elif cmd == 'RPATH':
                self.__macho['lcs'].append(self.parse_rpath(cmd, cmd_size))
            elif cmd == 'MAIN':
                self.__macho['lcs'].append(self.parse_main(cmd, cmd_size))

    def parse_syms(self, offset, size, lc_symtab):
        """Parse symbol and string tables.

        Symbol table format found in:
        /usr/include/mach-o/nlist.h
        /usr/include/mach-o/stab.h
        """

        # Check if symbol table offset is within mach-o
        if lc_symtab['symoff'] > size:
            self.add_abnormality('Symbol table at offset "{}" out of '
                                 'bounds.'.format(
                                     offset + lc_symtab['symoff']))

            return

        true_offset = offset + lc_symtab['symoff']  # beginning of symbol table

        symbol_size = 16 if self.__is_64_bit else 12

        self.__file.seek(true_offset)

        entropy = self.calc_entropy(self.__file.read(
            lc_symtab['nsyms'] * symbol_size))

        if entropy >= 0.8:
            self.add_abnormality('Symbol table with entropy of "{}" is '
                                 'probably packed. Not attempting to '
                                 'parse.'.format(entropy))

            return

        if lc_symtab['symoff'] + lc_symtab['nsyms'] * symbol_size > size:
            self.add_abnormality('Symbol table at offset "{}" partially out '
                                 'of bounds. Attempting to parse as many '
                                 'symbols as possible.'.format(true_offset))

        self.__file.seek(true_offset)  # jump to beginning of symbol table

        self.__macho['symtab'] = []

        for _ in range(lc_symtab['nsyms']):
            if self.__file.tell() + symbol_size > offset + size:
                break

            n_strx = self.get_int()
            n_type = int(self.__file.read(1).hex(), 16)
            n_sect = int(self.__file.read(1).hex(), 16)
            n_desc = int(self.__file.read(2).hex(), 16)

            n_value = self.get_ll() if self.__is_64_bit else self.get_int()

            symbol = {
                'n_strx': n_strx,
                'n_sect': n_sect,
                'n_desc': n_desc,
                'n_value': n_value
            }

            if n_type >= 32:
                if n_type in dictionary.stabs:
                    symbol['stab'] = dictionary.stabs[n_type]
                else:
                    self.add_abnormality(
                        'Unknown stab type "{}" at offset "{}".'.format(
                            n_type, self.__file.tell() - symbol_size + 4))
            else:
                n_pext = n_type & 0x10  # private external symbol flag
                n_ext = n_type & 0x01   # external symbol flag
                n_type = n_type & 0x0e  # symbol type

                if n_type in dictionary.n_types:
                    n_type = dictionary.n_types[n_type]
                else:
                    self.add_abnormality(
                        'Unknown N_TYPE "{}" at offset "{}".'.format(
                            n_type, self.__file.tell() - symbol_size + 4))

                if self.__is_little_endian:
                    dylib = n_desc & 0x0f
                    ref = (n_desc >> 8) & 0xff
                else:
                    dylib = (n_desc >> 8) & 0xff
                    ref = n_desc & 0x0f

                symbol['pext'] = n_pext
                symbol['n_type'] = n_type
                symbol['ext'] = n_ext
                symbol['dylib'] = dylib
                symbol['ref'] = ref

            self.__macho['symtab'].append(symbol)

    def parse_strings(self, offset, size, lc_symtab):
        """Parse string table."""

        # Check is string table offset is within mach-o
        if lc_symtab['stroff'] > size:
            self.add_abnormality(
                'String table at offset "{}" greater than mach-o size.'.format(
                    offset + lc_symtab['stroff']))

            return

        true_offset = offset + lc_symtab['stroff']

        self.__file.seek(true_offset)

        entropy = self.calc_entropy(self.__file.read(lc_symtab['strsize']))

        if entropy >= 0.8:
            self.add_abnormality('String table with entropy of "{}" is '
                                 'probably packed. Not attempting to '
                                 'parse.'.format(entropy))

            return

        if true_offset + lc_symtab['strsize'] > offset + size:
            self.add_abnormality('String Table at offset "{}" partially out '
                                 'of bounds. Attempting to parse as many '
                                 'strings as possible.'.format(true_offset))

        self.__macho['strtab'] = []

        self.__file.seek(true_offset)

        while self.__file.tell() < true_offset + lc_symtab['strsize']:
            try:
                string = self.get_string()

                if string != '':
                    self.__macho['strtab'].append(string)
            except:
                break

    def parse_imports(self, offset, size, lc_symtab, lc_dysymtab=None,
                      lc_dylibs=None):
        """Parse undefined external symbols (imports) out of the symbol and
        string tables.
        """

        self.__macho['imports'] = []

        true_offset = offset + lc_symtab['stroff']

        undef_syms = None

        if lc_dysymtab is not None:  # Use symtab layout info from DYSYMTAB
            i_undef = lc_dysymtab['nlocalsym'] + lc_dysymtab['nextdefsym'] - 1
            j_undef = i_undef + lc_dysymtab['nundefsym']

            undef_syms = self.__macho['symtab'][i_undef:j_undef]
        else:  # Find undefined symbols manually by checking n_type
            undef_syms = filter(lambda sym: sym['n_type'] in ('UNDF', 'PBUD'),
                                self.__macho['symtab'])

        for sym in undef_syms:
            self.__file.seek(true_offset + sym['n_strx'])

            value = self.get_string()

            if lc_dylibs is not None:  # If created with two-level namespace
                dylib = sym['dylib']

                if dylib == 0:
                    dylib = 'SELF_LIBRARY'
                elif dylib == 254:
                    dylib = 'DYNAMIC_LOOKUP'
                elif dylib == 255:
                    dylib = 'EXECUTABLE'
                else:
                    dylib = lc_dylibs[dylib - 1]['name']

                self.__macho['imports'].append((value, dylib))
            else:
                self.__macho['imports'].append(value)

    def parse_certs(self, sig_offset, index_offset):
        """Parse X509 certificates out of code signature."""

        prev = self.__file.tell()

        true_offset = sig_offset + index_offset

        self.__file.seek(true_offset)

        magic = self.get_int(ignore_endian=True)

        if magic != dictionary.signatures['BLOBWRAPPER']:
            self.add_abnormality('Bad magic "{}" for certificate blob wrapper '
                                 'at offset "{}".'.format(magic, true_offset))

            return []

        # subtract 8 to ignore magic and size fields
        size = self.get_int(ignore_endian=True) - 8

        if size <= 0:
            self.add_abnormality('Non-positive CMS size "{}" at offset '
                                 '"{}".'.format(size, self.__file.tell() - 4))

            return []

        signed_data = ContentInfo.load(self.__file.read(size))['content']

        self.__macho['code_signature']['certs'] = []

        for cert in signed_data['certificates']:
            cert = cert.chosen

            subject = {}

            for rdn in cert.subject.chosen:
                name = rdn[0]['type'].human_friendly
                value = rdn[0]['value']

                if name == 'Country':
                    subject['country'] = str(value.chosen)
                elif name == 'Organization':
                    subject['org'] = str(value.chosen)
                elif name == 'Organizational Unit':
                    subject['org_unit'] = str(value.chosen)
                elif name == 'Common Name':
                    subject['common_name'] = str(value.chosen)
                else:
                    subject[name] = str(value.parsed)

            issuer = {}

            for rdn in cert.issuer.chosen:
                name = rdn[0]['type'].human_friendly
                value = rdn[0]['value']

                if name == 'Country':
                    issuer['country'] = str(value.chosen)
                elif name == 'Organization':
                    issuer['org'] = str(value.chosen)
                elif name == 'Organizational Unit':
                    issuer['org_unit'] = str(value.chosen)
                elif name == 'Common Name':
                    issuer['common_name'] = str(value.chosen)
                else:
                    issuer[name] = str(value.parsed)

            certificate = {
                'subject': subject,
                'issuer': issuer,
                'serial': cert.serial_number,
                'is_ca': cert.ca
            }

            self.__macho['code_signature']['certs'].append(certificate)

        self.__file.seek(prev)

    def parse_codedirectory(self, sig_offset, index_offset):
        """Parse code directory from code signature."""

        prev = self.__file.tell()

        true_offset = sig_offset + index_offset

        self.__file.seek(true_offset)

        magic = self.get_int(ignore_endian=True)

        if magic != dictionary.signatures['CODEDIRECTORY']:
            self.add_abnormality('Bad magic "{}" for code directory at offset '
                                 '"{}".'.format(magic, self.__file.tell() - 4))

            return

        size = self.get_int(ignore_endian=True)
        version = self.get_int(ignore_endian=True)
        # TODO: not sure how to parse flags yet...
        flags = self.get_int(ignore_endian=True)
        hash_offset = self.get_int(ignore_endian=True)
        ident_offset = self.get_int(ignore_endian=True)
        n_special_slots = self.get_int(ignore_endian=True)
        n_code_slots = self.get_int(ignore_endian=True)
        code_limit = self.get_int(ignore_endian=True)
        hash_size = int(self.__file.read(1).hex(), 16)
        hash_type = dictionary.hashes[int(self.__file.read(1).hex(), 16)]

        if version >= 0x20200:
            platform = int(self.__file.read(1).hex(), 16)
        else:
            self.__file.read(1)  # skip spare1

        page_size = int(round(exp(
            int(self.__file.read(1).hex(), 16) * log(2))))

        self.__file.read(4)  # skip spare2

        if version >= 0x20100:
            scatter_offset = self.get_int(ignore_endian=True)
        if version >= 0x20200:
            team_id_offset = self.get_int(ignore_endian=True)
            self.__file.seek(true_offset + team_id_offset)
            team_id = self.get_string()

        self.__file.seek(true_offset + ident_offset)

        identity = self.get_string()

        self.__macho['code_signature']['codedirectory'] = {
            'size': size,
            'version': version,
            'flags': flags,
            'hash_offset': hash_offset,
            'n_special_slots': n_special_slots,
            'n_code_slots': n_code_slots,
            'code_limit': code_limit,
            'hash_size': hash_size,
            'hash_type': hash_type,
            'page_size': page_size,
            'identity': identity,
            'hashes': []
        }

        if version >= 0x20100:
            self.__macho['code_signature']['codedirectory']['scatter_offset'] = scatter_offset
        if version >= 0x20200:
            self.__macho['code_signature']['codedirectory']['platform'] = platform
            self.__macho['code_signature']['codedirectory']['team_id_offset'] = team_id_offset
            self.__macho['code_signature']['codedirectory']['team_id'] = team_id

        self.__file.seek(
            true_offset + hash_offset - n_special_slots * hash_size)

        count = n_special_slots + n_code_slots

        for _ in range(count):
            self.__macho['code_signature']['codedirectory']['hashes'].append(
                self.__file.read(hash_size).hex())

        self.__file.seek(prev)

    def get_oid(self, db, p):
        """OID parser implementation from:

        http://opensource.apple.com/source/Security/Security-57337.20.44/
        OSX/libsecurity_cdsa_utilities/lib/cssmdata.cpp
        """

        q = 0

        while True:
            q = q * 128 + (db[p] & ~0x80)

            if p < len(db) and db[p] & 0x80:
                p += 1
            else:
                p += 1
                break

        return q, p

    def to_oid(self, length):
        """Convert bytes to correct OID."""

        if length == 0:
            return ''

        data_bytes = [
            int(self.__file.read(1).hex(), 16) for i in range(length)
        ]

        p = 0

        # first byte is composite (q1, q2)
        oid1, p = self.get_oid(data_bytes, p)

        q1 = min(oid1 / 40, 2)

        data = str(q1) + '.' + str(oid1 - q1 * 40)

        while p < len(data_bytes):
            d, p = self.get_oid(data_bytes, p)
            data += '.' + str(d)

        self.__file.read(-length & 3)

        return data

    def parse_entitlement(self, sig_offset, index_offset):
        """Parse entitlement from code signature."""

        prev = self.__file.tell()

        true_offset = sig_offset + index_offset

        self.__file.seek(true_offset)

        magic = self.get_int(ignore_endian=True)

        if magic != dictionary.signatures['ENTITLEMENT']:
            self.add_abnormality('Bad magic "{}" for entitlement at offset '
                                 '"{}".'.format(magic, self.__file.tell() - 4))

            return

        # size of plist minus magic and size values
        size = self.get_int(ignore_endian=True) - 8

        try:
            plist = loads(self.__file.read(size))
        except Exception as exc:
            plist = {}
            self.add_abnormality('Unable to parse plist at offset "{}". '
                                 '{}.'.format(self.__file.tell() - size, exc))

        if 'entitlements' not in self.__macho['code_signature']:
            self.__macho['code_signature']['entitlements'] = []

        self.__macho['code_signature']['entitlements'].append({
            'size': size,
            'plist': plist
        })

        self.__file.seek(prev)

    def parse_data(self):
        """Parse data for requirement expression."""

        length = self.get_int(ignore_endian=True)

        data = self.__file.read(length)

        self.__file.read(-length & 3)  # skip padding

        return data

    def parse_match(self):
        """Parse match for requirement expression."""

        match_type = self.get_int(ignore_endian=True)

        if match_type in dictionary.matches:
            match_type = dictionary.matches[match_type]

        if match_type == 'matchExists':
            return ' /* exists */'
        elif match_type == 'matchEqual':
            return ' = "{}"'.format(self.parse_data().decode())
        elif match_type == 'matchContains':
            return ' ~ "{}"'.format(self.parse_data().decode())
        elif match_type == 'matchBeginsWith':
            return ' = "{}*"'.format(self.parse_data().decode())
        elif match_type == 'matchEndsWith':
            return ' = "*{}"'.format(self.parse_data().decode())
        elif match_type == 'matchLessThan':
            return ' < {}'.format(int(self.parse_data(), 16))
        elif match_type == 'matchGreaterThan':
            return ' > {}'.format(int(self.parse_data(), 16))
        elif match_type == 'matchLessEqual':
            return ' <= {}'.format(int(self.parse_data(), 16))
        elif match_type == 'matchGreaterEqual':
            return ' >= {}'.format(int(self.parse_data(), 16))
        else:
            return ' UNKNOWN MATCH TYPE "{}"'.format(match_type)

    def parse_expression(self, in_or=False):
        """Parse requirement expression. Recurse if necessary"""

        # Zero out flags in high byte (TODO: Look into flags field)
        operator = self.get_int(ignore_endian=True)
        operator = dictionary.operators[operator & 0xfff]

        expression = ''

        if operator == 'False':
            expression += 'never'
        elif operator == 'True':
            expression += 'always'
        elif operator == 'Ident':
            expression += 'identity "{}"'.format(self.parse_data().decode())
        elif operator == 'AppleAnchor':
            expression += 'anchor apple'
        elif operator == 'AppleGenericAnchor':
            expression += 'anchor apple generic'
        elif operator == 'AnchorHash':
            cert_slot = self.get_int(ignore_endian=True)

            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]

            expression += 'certificate {} = {}'.format(
                cert_slot, self.parse_data().decode())
        elif operator == 'InfoKeyValue':
            expression += 'info[{}] = "{}"'.format(
                self.parse_data().decode(), self.parse_data().decode())
        elif operator == 'And':
            if in_or:
                expression += '({} and {})'.format(
                    self.parse_expression(), self.parse_expression())
            else:
                expression += '{} and {}'.format(
                    self.parse_expression(), self.parse_expression())
        elif operator == 'Or':
            if in_or:
                expression += '({} or {})'.format(
                    self.parse_expression(in_or=True),
                    self.parse_expression(in_or=True))
            else:
                expression += '{} or {}'.format(
                    self.parse_expression(in_or=True),
                    self.parse_expression(in_or=True))
        elif operator == 'Not':
            expression += '! {}'.format(self.parse_expression())
        elif operator == 'CDHash':
            expression += 'cdhash {}'.format(self.parse_data().decode())
        elif operator == 'InfoKeyField':
            expression += 'info[{}]{}'.format(
                self.parse_data().decode(), self.parse_match())
        elif operator == 'EntitlementField':
            expression += 'entitlement[{}]{}'.format(
                self.parse_data().decode(), self.parse_match())
        elif operator == 'CertField':
            cert_slot = self.get_int(ignore_endian=True)

            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]

            expression += 'certificate {}[{}]{}'.format(
                cert_slot, self.parse_data().decode(), self.parse_match())
        elif operator == 'CertGeneric':
            cert_slot = self.get_int(ignore_endian=True)

            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]

            length = self.get_int(ignore_endian=True)

            expression += 'certificate {}[field.{}]{}'.format(
                cert_slot, self.to_oid(length), self.parse_match())
        elif operator == 'CertPolicy':
            cert_slot = self.get_int(ignore_endian=True)

            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]

            expression += 'certificate {}[policy.{}]{}'.format(
                cert_slot, self.parse_data().decode(), self.parse_match())
        elif operator == 'TrustedCert':
            cert_slot = self.get_int(ignore_endian=True)

            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]

            expression += 'certificate {} trusted'.format(cert_slot)
        elif operator == 'TrustedCerts':
            expression += 'anchor trusted'
        elif operator == 'NamedAnchor':
            expression += 'anchor apple {}'.format(self.parse_data().decode())
        elif operator == 'NamedCode':
            expression += '({})'.format(self.parse_data().decode())
        elif operator == 'Platform':
            platform = self.get_int(ignore_endian=True)
            expression += 'platform = {}'.format(platform)

        return expression

    def parse_requirement(self, reqs_offset, req_type, req_offset):
        """Parse single requirement from code signature."""

        prev = self.__file.tell()

        true_offset = reqs_offset + req_offset

        self.__file.seek(true_offset)

        magic = self.get_int(ignore_endian=True)

        if magic != dictionary.signatures['REQUIREMENT']:
            self.add_abnormality('Bad magic "{}" for requirement at offset '
                                 '"{}".'.format(magic, self.__file.tell() - 4))

            return

        self.__file.read(8)  # skip size and kind fields
        # (TODO: look into ``kind`` field)

        self.__macho['code_signature']['requirements'].append({
            'req_type': req_type,
            'req_offset': req_offset,
            'expression': self.parse_expression()
        })

        self.__file.seek(prev)

    def parse_requirements(self, sig_offset, index_offset):
        """Parse requirements from code signature."""

        prev = self.__file.tell()

        true_offset = sig_offset + index_offset

        self.__file.seek(true_offset)

        magic = self.get_int(ignore_endian=True)

        if magic != dictionary.signatures['REQUIREMENTS']:
            self.add_abnormality('Bad magic "{}" for requirements at offset '
                                 '"{}".'.format(magic, self.__file.tell() - 4))

            return

        self.__file.read(4)  # skip size field

        count = self.get_int(ignore_endian=True)

        self.__macho['code_signature']['requirements'] = []

        for _ in range(count):
            req_type = self.get_int(ignore_endian=True)
            req_type = dictionary.requirements[req_type]

            req_offset = self.get_int(ignore_endian=True)

            self.parse_requirement(true_offset, req_type, req_offset)

        self.__file.seek(prev)

    def parse_sig(self, offset, size, lc_codesig):
        """Parse code signature in its entirety."""

        if lc_codesig['dataoff'] + lc_codesig['datasize'] > size:
            self.add_abnormality('CODE_SIGNATURE at offset "{}" with size '
                                 '"{}" greater than mach-o size.'.format(
                                     offset + lc_codesig['dataoff'],
                                     lc_codesig['datasize']))

            return

        true_offset = offset + lc_codesig['dataoff']

        self.__file.seek(true_offset)

        magic = self.get_int(ignore_endian=True)

        if magic != dictionary.signatures['EMBEDDED_SIGNATURE']:
            self.add_abnormality('Bad magic "{}" for embedded signature at '
                                 'offset "{}".'.format(magic, true_offset))

            return

        self.__macho['code_signature'] = {}

        size = self.get_int(ignore_endian=True)
        count = self.get_int(ignore_endian=True)

        for _ in range(count):
            index_type = self.get_int(ignore_endian=True)

            if index_type in dictionary.indeces:
                index_type = dictionary.indeces[index_type]
            else:
                self.add_abnormality('Unknown code signature index type "{}" '
                                     'at offset "{}".'.format(
                                         index_type, self.__file.tell() - 4))

                self.__file.read(4)  # skip offset
                continue

            index_offset = self.get_int(ignore_endian=True)

            if index_type == 'SignatureSlot':
                self.parse_certs(true_offset, index_offset)
            elif index_type == 'CodeDirectorySlot':
                self.parse_codedirectory(true_offset, index_offset)
            elif index_type == 'EntitlementSlot':
                self.parse_entitlement(true_offset, index_offset)
            elif index_type == 'RequirementsSlot':
                self.parse_requirements(true_offset, index_offset)

    def parse_macho(self, offset, size):
        """Parse mach-o binary, possibly contained within a
        universal binary.
        """

        if size is None:
            self.__file.seek(0, SEEK_END)  # find the end of the file
            size = self.__file.tell()

        # jump to the location of this mach-o within the file
        self.__file.seek(offset)

        identity = self.identify_file()
        self.__is_64_bit = identity[0]
        self.__is_little_endian = identity[1]

        cputype = self.get_int()   # CPU type
        subtype = self.get_int()   # CPU sub-type
        filetype = self.get_int()  # Mach-o file type
        nlcs = self.get_int()      # Number of load commands
        slcs = self.get_int()      # Size of load commands
        flags = self.get_int()     # Mach-o flags

        if self.__is_64_bit:
            self.__file.read(4)  # skip padding

        if cputype in dictionary.cputypes:
            if subtype in dictionary.cputypes[cputype]:
                subtype = dictionary.cputypes[cputype][subtype]
            else:
                self.add_abnormality('Unknown SUBTYPE "{}" for CPUTYPE "{}" '
                                     'at offset "{}".'.format(
                                         subtype, cputype, offset + 8))

            cputype = dictionary.cputypes[cputype][-2]
        else:
            raise ValueError('Unknown or unsupported CPUTYPE "{}" at offset '
                             '"{}".'.format(cputype, offset + 4))

        if filetype in dictionary.filetypes:
            filetype = dictionary.filetypes[filetype]
        else:
            self.add_abnormality('Unknown FILETYPE "{}" at offset '
                                 '"{}".'.format(filetype, offset + 12))

        flags = self.parse_macho_flags(flags)

        self.__macho['cputype'] = cputype
        self.__macho['subtype'] = subtype
        self.__macho['filetype'] = filetype
        self.__macho['nlcs'] = nlcs
        self.__macho['slcs'] = slcs
        self.__macho['flags'] = flags

        # Parse load commands
        self.parse_lcs(offset, size, nlcs, slcs)

        lcs = list(map(lambda x: x['cmd'], self.__macho['lcs']))

        # Check for symbol and strings tables and parse if present
        if 'SYMTAB' in lcs:
            lc_symtab = self.__macho['lcs'][lcs.index('SYMTAB')]

            self.parse_syms(offset, size, lc_symtab)
            self.parse_strings(offset, size, lc_symtab)

        # If symbol and strings tables were parsed, parse imports
        if 'symtab' in self.__macho and 'strtab' in self.__macho:
            lc_dysymtab = None
            lc_dylibs = None

            # Check for presence of DYSYMTAB load command and, if present, use
            # it to parse undefined external symbols (imports). Otherwise, find
            # imports manually.
            if 'DYSYMTAB' in lcs:
                lc_dysymtab = self.__macho['lcs'][lcs.index('DYSYMTAB')]

            # Check if the static linker used the two-level namespace feature.
            # If so, pass in the list of dynamic libraries (dylibs) given in
            # the 'DYLIB' load commands.
            if 'TWOLEVEL' in self.__macho['flags']:
                lc_dylibs = list(filter(lambda x: x['cmd'].endswith('DYLIB'),
                                        self.__macho['lcs']))

            self.parse_imports(offset, size, lc_symtab,
                               lc_dysymtab=lc_dysymtab, lc_dylibs=lc_dylibs)

        # Check for a code signature and parse if present
        if 'CODE_SIGNATURE' in lcs:
            lc_codesig = self.__macho['lcs'][lcs.index('CODE_SIGNATURE')]

            self.parse_sig(offset, size, lc_codesig)

    def parse_universal(self):
        """Parses universal binary."""

        self.__output['universal'] = {
            'machos': []
        }

        # number of mach-o's contained in this binary
        n_machos = self.get_int(ignore_endian=True)

        for _ in range(n_machos):
            self.__file.read(8)  # skip cputype and subtype fields

            offset = self.get_int(ignore_endian=True)
            size = self.get_int(ignore_endian=True)

            self.__file.read(4)  # skip align field

            prev = self.__file.tell()
            self.parse_macho(offset, size)
            self.__file.seek(prev)

            self.__output['universal']['machos'].append(self.__macho.copy())
            self.__macho.clear()

    def parse_file(self):
        """Determines characteristics about the entire file and begins
        to parse.
        """

        contents = self.__file.read()

        self.__output['size'] = len(contents)

        self.__output['hashes'] = {
            'md5': hashlib.md5(contents).hexdigest(),
            'sha1': hashlib.sha1(contents).hexdigest(),
            'sha256': hashlib.sha256(contents).hexdigest()
        }

        self.__file.seek(0)  # return to beginning of file

        if self.__file.read(4) == b'\xca\xfe\xba\xbe':
            self.parse_universal()
        else:
            self.parse_macho(0, self.__output['size'])

            self.__output['macho'] = self.__macho

    def parse(self, out=None):
        """Parse Mach-O file at given path, and either return a dict
        or write output to provided file.
        """

        self.parse_file()

        if out is None:
            return self.__output

        dump(self.__output, out)
