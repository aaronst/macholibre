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


import dictionary
import logging
import traceback

from uuid import UUID
from utilities import calc_entropy, little, get_int, get_ll, readstring, strip
from segment import Segment
from section import Section
from version import Version
from datetime import datetime
from symboltable import SymbolTable
from stringtable import StringTable
from loadcommand import LoadCommand
from abnormality import Abnormality


class LoadCommander(object):

    # Constructor
    def __init__(self, f=None, macho=None, file_size=None):
        # Fields
        self.f = f
        self.macho = macho
        self.file_size = file_size
        self.abnormalities = []

    # Functions
    def add_abnormality(self, abnormality): self.abnormalities.append(abnormality)

    def get_segment_entropy(self, offset, size):
        old = self.f.tell()
        self.f.seek(self.macho.offset + offset)
        entropy = calc_entropy(self.f.read(size))
        self.f.seek(old)
        return entropy

    def parse_section_attrs(self, section, attrs):
        for a in dictionary.section_attrs:
            if attrs & a == a:
                section.add_attr(dictionary.section_attrs[a])

    def parse_section_flags(self, section, flags):
        section.type = dictionary.section_types[flags & 0xff]
        attrs = flags & 0xffffff00
        self.parse_section_attrs(section, attrs)

    def parse_section(self):
        name = strip(self.f.read(16))
        segname = strip(self.f.read(16))
        addr = get_int(self.f) if self.macho.is_32_bit() else get_ll(self.f)
        size = get_int(self.f) if self.macho.is_32_bit() else get_ll(self.f)
        offset = get_int(self.f)
        align = get_int(self.f)
        reloff = get_int(self.f)
        nreloc = get_int(self.f)
        flags = get_int(self.f)
        self.f.read(8) if self.macho.is_32_bit() else self.f.read(12)

        if self.macho.is_little():
            addr = little(addr, 'I') if self.macho.is_32_bit() \
                else little(addr, 'Q')
            size = little(size, 'I') if self.macho.is_32_bit() \
                else little(size, 'Q')
            offset = little(offset, 'I')
            align = little(align, 'I')
            reloff = little(reloff, 'I')
            nreloc = little(nreloc, 'I')
            flags = little(flags, 'I')

        section = Section(name=name, segname=segname, addr=addr, offset=offset,
                          align=align, reloff=reloff, nreloc=nreloc, size=size)
        self.parse_section_flags(section, flags)

        return section

    def parse_segment_flags(self, segment, flags):
        j = 1
        while j < 9:
            if flags & j == j:
                segment.add_flag(dictionary.segment_flags[j])
            j <<= 1

    def parse_segment(self, lc):
        name = strip(self.f.read(16))
        vmaddr = get_int(self.f) if self.macho.is_32_bit() else get_ll(self.f)
        vmsize = get_int(self.f) if self.macho.is_32_bit() else get_ll(self.f)
        offset = get_int(self.f) if self.macho.is_32_bit() else get_ll(self.f)
        segsize = get_int(self.f) if self.macho.is_32_bit() else get_ll(self.f)
        maxprot = get_int(self.f)
        initprot = get_int(self.f)
        nsects = get_int(self.f)
        flags = get_int(self.f)

        if self.macho.is_little():
            vmaddr = little(vmaddr, 'I') if self.macho.is_32_bit() \
                else little(vmaddr, 'Q')
            vmsize = little(vmsize, 'I') if self.macho.is_32_bit() \
                else little(vmsize, 'Q')
            offset = little(offset, 'I') if self.macho.is_32_bit() \
                else little(offset, 'Q')
            segsize = little(segsize, 'I') if self.macho.is_32_bit() \
                else little(segsize, 'Q')
            maxprot = little(maxprot, 'I')
            initprot = little(initprot, 'I') 
            nsects = little(nsects, 'I')
            flags = little(flags, 'I')

        maxprot = dictionary.protections[maxprot & 0b111]
        initprot = dictionary.protections[initprot & 0b111]        

        entropy = self.get_segment_entropy(offset, segsize)

        segment = Segment(cmd=lc.cmd, size=lc.size, name=name,
                          vmaddr=vmaddr, vmsize=vmsize, offset=offset,
                          segsize=segsize, maxprot=maxprot, initprot=initprot,
                          nsects=nsects, entropy=entropy)

        if self.macho.is_32_bit():
            sect_size = 68
        else:
            sect_size = 80
        for i in range(segment.nsects):
            if self.f.tell() + sect_size > self.file_size:
                data = {
                    'offset': self.f.tell(),
                    'file_size': self.file_size
                }
                a = Abnormality(title='SECTION OUT OF BOUNDS', data=data)
                break
            sect = self.parse_section()
            segment.add_sect(sect)

        self.parse_segment_flags(segment, flags)
        self.macho.add_lc(segment)

    def parse_symtab(self, lc):
        symoff = get_int(self.f)
        nsyms = get_int(self.f)
        stroff = get_int(self.f)
        strsize = get_int(self.f)

        if self.macho.is_little():
            symoff = little(symoff, 'I')
            nsyms = little(nsyms, 'I')
            stroff = little(stroff, 'I')
            strsize = little(strsize, 'I')

        self.macho.symtab = SymbolTable(offset=symoff, nsyms=nsyms)
        self.macho.strtab = StringTable(offset=stroff, size=strsize)

        lc.add_data('symoff', symoff)
        lc.add_data('nsyms', nsyms)
        lc.add_data('stroff', stroff)
        lc.add_data('strsize', strsize)

        self.macho.add_lc(lc)

    def parse_sym_seg(self, lc):
        offset = get_int(self.f)
        size = get_int(self.f)

        if self.macho.is_little():
            offset = little(offset, 'I')
            size = little(size, 'I')

        lc.add_data('offset', offset)
        lc.add_data('size', size)

        self.macho.add_lc(lc)

    def parse_thread(self, lc):
        state = get_int(self.f)
        count = get_int(self.f)
        self.f.read(lc.size - 16)

        if self.macho.is_little():
            state = little(state, 'I')
            count = little(count, 'I')

        try:
            state = dictionary.thread_states[state]
        except:
            data = {
                'offset': self.f.tell() - lc.size,
                'state': state
            }
            a = Abnormality(title='INVALID THREAD STATE FLAVOR', data=data)
            self.add_abnormality(a)

        lc.add_data('state', state)
        lc.add_data('count', count)

        self.macho.add_lc(lc)

    def parse_fvmlib(self, lc):
        self.f.read(lc.size - 8)
        lc.add_data('msg', 'OBSOLETE')
        self.macho.add_lc(lc)

    def parse_ident(self, lc):
        self.f.read(lc.size - 8)
        lc.add_data('msg', 'OBSOLETE')
        self.macho.add_lc(lc)

    def parse_fvmfile(self, lc):
        self.f.read(lc.size - 8)
        lc.add_data('msg', 'INTERNAL ONLY')
        self.macho.add_lc(lc)

    def parse_prepage(self, lc):
        self.f.read(lc.size - 8)
        lc.add_data('msg', 'INTERNAL ONLY')
        self.macho.add_lc(lc)

    def parse_dysymtab(self, lc):
        il = get_int(self.f)
        nl = get_int(self.f)
        ie = get_int(self.f)
        ne = get_int(self.f)
        iu = get_int(self.f)
        nu = get_int(self.f)
        self.f.read(lc.size - 32)

        if self.macho.is_little():
            self.macho.symtab.il = little(il, 'I')
            self.macho.symtab.nl = little(nl, 'I')
            self.macho.symtab.ie = little(ie, 'I')
            self.macho.symtab.ne = little(ne, 'I')
            self.macho.symtab.iu = little(iu, 'I')
            self.macho.symtab.nu = little(nu, 'I')

        lc.add_data('il', il)
        lc.add_data('nl', nl)
        lc.add_data('ie', ie)
        lc.add_data('ne', ne)
        lc.add_data('iu', iu)
        lc.add_data('nu', nu)

        self.macho.add_lc(lc)

    def parse_load_dylib(self, lc):
        offset = get_int(self.f)
        timestamp = get_int(self.f)
        current_version = get_int(self.f)
        compatibility_version = get_int(self.f)

        if self.macho.is_little():
            offset = little(offset, 'I')
            timestamp = little(timestamp, 'I')
            current_version = little(current_version, 'I')
            compatibility_version = little(compatibility_version, 'I')

        timestamp = datetime.fromtimestamp(timestamp)
        current_version = Version(version=current_version)
        compatibility_version = Version(version=compatibility_version)

        dylib = strip(self.f.read(lc.size - 24))
        self.macho.add_dylib(dylib)

        lc.add_data('timestamp', str(timestamp))
        lc.add_data('current_version', current_version.version)
        lc.add_data('compatibility_version', compatibility_version.version)
        lc.add_data('dylib', dylib)

        self.macho.add_lc(lc)

    def parse_load_dylinker(self, lc):
        # first char is \n
        name = strip(self.f.read(lc.size - 8)[1:])
        lc.add_data('name', name)

        self.macho.add_lc(lc)

    def parse_prebound_dylib(self, lc):
        dylib = readstring(self.f)
        nmodules = get_int(self.f)
        linked_modules = readstring(self.f)
        
        if self.macho.is_little():
            nmodules = little(nmodules, 'I')

        lc.add_data('dylib', dylib)
        lc.add_data('nmodules', nmodules)
        lc.add_data('linked_modules', linked_modules)

        self.macho.add_lc(lc)

    def parse_routines(self, lc):
        if lc.cmd == 'ROUTINES':
            init_address = get_int(self.f)
            init_module = get_int(self.f)
            if self.macho.is_little():
                init_address = little(init_address, 'I')
                init_module = little(init_module, 'I')
            self.f.read(24)
        else:
            init_address = get_ll(self.f)
            init_module = get_ll(self.f)
            if self.macho.is_little():
                init_address = little(init_address, 'Q')
                init_module = little(init_module, 'Q')
            self.f.read(48)

        lc.add_data('init_address', init_address)
        lc.add_data('init_module', init_module)

        self.macho.add_lc(lc)

    def parse_sub_stuff(self, lc):
        name = strip(self.f.read(lc.size - 8))
        lc.add_data('name', name)

        self.macho.add_lc(lc)

    def parse_twolevel_hints(self, lc):
        offset = get_int(self.f)
        nhints = get_int(self.f)

        if self.macho.is_little():
            offset = little(offset, 'I')
            nhints = little(nhints, 'I')

        lc.add_data('offset', offset)
        lc.add_data('nhints', nhints)

        self.macho.add_lc(lc)

    def parse_prebind_cksum(self, lc):
        cksum = get_int(self.f)

        if self.macho.is_little():
            cksum = little(cksum, 'I')

        lc.add_data('cksum', cksum)

        self.macho.add_lc(lc)

    def parse_uuid(self, lc):
        uuid = self.f.read(16)

        if self.macho.is_little():
            uuid = UUID(bytes=little(uuid, '16s'))
        else:
            uuid = UUID(bytes=uuid)

        lc.add_data('uuid', uuid.hex)

        self.macho.add_lc(lc)

    def parse_linkedit_data(self, lc):
        offset = get_int(self.f)
        size = get_int(self.f)

        if self.macho.is_little():
            offset = little(offset, 'I')
            size = little(size, 'I')

        lc.add_data('offset', offset)
        lc.add_data('size', size)

        self.macho.add_lc(lc)

    def parse_encryption_info(self, lc):
        offset = get_int(self.f)
        size = get_int(self.f)
        id = get_int(self.f)

        if self.macho.is_little():
            offset = little(offset, 'I')
            size = little(size, 'I')
            id = little(id, 'I')

        lc.add_data('offset', offset)
        lc.add_data('size', size)
        lc.add_data('id', id)

        if lc.cmd == 'ENCRYPTION_INFO_64':
            # Skip padding
            self.f.read(4)

        self.macho.add_lc(lc)

    def parse_dyld_info(self, lc):
        rebase_off = get_int(self.f)
        rebase_size = get_int(self.f)
        bind_off = get_int(self.f)
        bind_size = get_int(self.f)
        weak_bind_off = get_int(self.f)
        weak_bind_size = get_int(self.f)
        lazy_bind_off = get_int(self.f)
        lazy_bind_size = get_int(self.f)
        export_off = get_int(self.f)
        export_size = get_int(self.f)

        if self.macho.is_little():
            rebase_off = little(rebase_off, 'I')
            rebase_size = little(rebase_size, 'I')
            bind_off = little(bind_off, 'I')
            bind_size = little(bind_size, 'I')
            weak_bind_off = little(weak_bind_off, 'I')
            weak_bind_size = little(weak_bind_size, 'I')
            lazy_bind_off = little(lazy_bind_off, 'I')
            lazy_bind_size = little(lazy_bind_size, 'I')
            export_off = little(export_off, 'I')
            export_size = little(export_size, 'I')

        lc.add_data('rebase_off', rebase_off)
        lc.add_data('rebase_size', rebase_size)
        lc.add_data('bind_off', bind_off)
        lc.add_data('bind_size', bind_size)
        lc.add_data('weak_bind_off', weak_bind_off)
        lc.add_data('weak_bind_size', weak_bind_size)
        lc.add_data('lazy_bind_off', lazy_bind_off)
        lc.add_data('lazy_bind_size', lazy_bind_size)
        lc.add_data('export_off', export_off)
        lc.add_data('export_size', export_size)

        self.macho.add_lc(lc)

    def parse_version_min_os(self, lc):
        version = get_int(self.f)
        sdk = get_int(self.f)

        if self.macho.is_little():
            version = little(version, 'I')
            sdk = little(sdk, 'I')

        version = Version(version=version)
        sdk = Version(version=sdk)

        lc.add_data('version', version.version)
        lc.add_data('sdk', sdk.version)

        self.macho.minos = version
        self.macho.add_lc(lc)

    def parse_source_version(self, lc):
        version = get_ll(self.f)
        if self.macho.is_little():
            version = little(version, 'Q')

        a = str((version >> 40) & 0xffffff)
        b = str((version >> 30) & 0x3ff)
        c = str((version >> 20) & 0x3ff)
        d = str((version >> 10) & 0x3ff)
        e = str(version & 0x3ff)

        # TODO: fix source version.
        version = a + '.' + b + '.' + c + '.' + d + '.' + e

        lc.add_data('version', version)

        self.macho.add_lc(lc)

    def parse_linker_option(self, lc):
        count = get_int(self.f)
        if self.macho.is_little():
            count = little(count, 'I')
        linker_options = []
        start = self.f.tell()
        for i in range(count):
            linker_option = readstring(self.f)
            linker_options.append(linker_option)

        length = self.f.tell() - start
        self.f.read(lc.size - length - 12)

        lc.add_data('count', count)
        lc.add_data('linker_options', linker_options)

        self.macho.add_lc(lc)

    def parse_rpath(self, lc):
        # first char is \n
        path = strip(self.f.read(lc.size - 8)[1:])
        lc.add_data('path', path)

        self.macho.add_lc(lc)

    def parse_main(self, lc):
        offset = get_ll(self.f)
        size = get_ll(self.f)

        if self.macho.is_little():
            offset = little(offset, 'Q')
            size = little(size, 'Q')

        lc.add_data('offset', offset)
        lc.add_data('size', size)

        self.macho.add_lc(lc)

    def parse_lcs(self):
        for i in range(self.macho.nlcs):
            cmd = get_int(self.f)
            size = get_int(self.f)

            if self.macho.endi == 'little':
                cmd = little(cmd, 'I')
                size = little(size, 'I')

            try:
                cmd = dictionary.loadcommands[cmd]
            except:
                data = {
                    'offset': self.f.tell() - 8,
                    'cmd': cmd
                }
                a = Abnormality(title='UNKNOWN LOADCOMMAND', data=data)
                self.addAbnormality(a)
                lc = LoadCommand(cmd=cmd, size=size)
                self.macho.add_lc(lc)
                self.f.read(size - 8)
                continue

            lc = LoadCommand(cmd=cmd, size=size)

            if cmd == 'SEGMENT' or cmd == 'SEGMENT_64':
                self.parse_segment(lc)
            elif cmd == 'SYMTAB':
                self.parse_symtab(lc)
            elif cmd == 'SYMSEG':
                self.parse_symseg(lc)
            elif cmd == 'THREAD' or cmd == 'UNIXTHREAD':
                self.parse_thread(lc)
            elif cmd == 'LOADFVMLIB' or cmd == 'IDFVMLIB':
                self.parse_fvmlib(lc)
            elif cmd == 'IDENT':
                self.parse_ident(lc)
            elif cmd == 'FVMFILE':
                self.parse_fvmfile(lc)
            elif cmd == 'PREPAGE':
                self.parse_prepage(lc)
            elif cmd == 'DYSYMTAB':
                self.parse_dysymtab(lc)
            elif (cmd == 'LOAD_DYLIB' or cmd == 'ID_DYLIB' or
                  cmd == 'LAZY_LOAD_DYLIB' or cmd == 'LOAD_WEAK_DYLIB' or
                  cmd == 'REEXPORT_DYLIB' or cmd == 'LOAD_UPWARD_DYLIB'):
                self.parse_load_dylib(lc)
            elif (cmd == 'LOAD_DYLINKER' or cmd == 'ID_DYLINKER' or
                  cmd == 'DYLD_ENVIRONMENT'):
                self.parse_load_dylinker(lc)
            elif cmd == 'PREBOUND_DYLIB':
                self.parse_prebound_dylib(lc)
            elif cmd == 'ROUTINES' or cmd == 'ROUTINES_64':
                self.parse_routines(lc)
            elif (cmd == 'SUB_FRAMEWORK' or cmd == 'SUB_UMBRELLA' or
                  cmd == 'SUB_CLIENT' or cmd == 'SUB_LIBRARY'):
                self.parse_sub_stuff(lc)
            elif cmd == 'TWOLEVEL_HINTS':
                self.parse_twolevel_hints(lc)
            elif cmd == 'PREBIND_CKSUM':
                self.parse_prebind_cksum(lc)
            elif cmd == 'UUID':
                self.parse_uuid(lc)
            elif (cmd == 'CODE_SIGNATURE' or cmd == 'SEGMENT_SPLIT_INFO' or
                  cmd == 'FUNCTION_STARTS' or cmd == 'DATA_IN_CODE' or
                  cmd == 'DYLIB_CODE_SIGN_DRS' or
                  cmd == 'LINKER_OPTIMIZATION_HINT'):
                self.parse_linkedit_data(lc)
            elif cmd == 'ENCRYPTION_INFO' or cmd == 'ENCRYPTION_INFO_64':
                self.parse_encryption_info(lc)
            elif cmd == 'DYLD_INFO' or cmd == 'DYLD_INFO_ONLY':
                self.parse_dyld_info(lc)
            elif (cmd == 'VERSION_MIN_MACOSX' or
                  cmd == 'VERSION_MIN_IPHONEOS' or
                  cmd == 'VERSION_MIN_WATCHOS'):
                self.parse_version_min_os(lc)
            elif cmd == 'SOURCE_VERSION':
                self.parse_source_version(lc)
            elif cmd == 'LINKER_OPTION':
                self.parse_linker_option(lc)
            elif cmd == 'RPATH':
                self.parse_rpath(lc)
            elif cmd == 'MAIN':
                self.parse_main(lc)

