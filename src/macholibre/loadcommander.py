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
from utilities import little, getInt, getLL, readstring, strip
from segment import Segment
from section import Section
from osversion import OSVersion
from symboltable import SymbolTable
from stringtable import StringTable
from loadcommand import LoadCommand
from abnormality import Abnormality


class LoadCommander(object):

    # Constructor
    def __init__(self, f=None, macho=None, file_size=None):
        # Fields
        self._f = f
        self._macho = macho
        self._file_size = file_size
        self._abnormalities = []

    # Getters
    def getMachO(self): return self._macho

    def getAbnormalities(self): return self._abnormalities

    # Setters
    def setMachO(self, macho): self._macho = macho

    # Functions
    def addAbnormality(self, abnormality): self._abnormalities.append(abnormality)

    def parseSectionAttrs(self, section, attrs):
        for a in dictionary.section_attrs:
            if attrs & a == a:
                section.addAttr(dictionary.section_attrs[a])

    def parseSectionFlags(self, section, flags):
        section_type = dictionary.section_types[flags & 0xff]
        section.setType(section_type)
        attrs = flags & 0xffffff00
        self.parseSectionAttrs(section, attrs)

    def parseSection(self):
        name = strip(self._f.read(16))
        segname = strip(self._f.read(16))
        addr = getInt(self._f) if self._macho.is32Bit() else getLL(self._f)
        size = getInt(self._f) if self._macho.is32Bit() else getLL(self._f)
        offset = getInt(self._f)
        align = getInt(self._f)
        reloff = getInt(self._f)
        nreloc = getInt(self._f)
        flags = getInt(self._f)
        self._f.read(8) if self._macho.is32Bit() else self._f.read(12)

        if self._macho.isLittle():
            addr = little(addr, 'I') if self._macho.is32Bit() \
                else little(addr, 'Q')
            size = little(size, 'I') if self._macho.is32Bit() \
                else little(size, 'Q')
            offset = little(offset, 'I')
            align = little(align, 'I')
            reloff = little(reloff, 'I')
            nreloc = little(nreloc, 'I')
            flags = little(flags, 'I')

        section = Section(name=name, segname=segname, addr=addr, offset=offset,
                          align=align, reloff=reloff, nreloc=nreloc, size=size)
        self.parseSectionFlags(section, flags)

        return section

    def parseSegmentFlags(self, segment, flags):
        j = 1
        while j < 9:
            if flags & j == j:
                segment.addFlag(dictionary.segment_flags[j])
            j <<= 1

    def parseSegment(self, lc):
        name = strip(self._f.read(16))
        vmaddr = getInt(self._f) if self._macho.is32Bit() else getLL(self._f)
        vmsize = getInt(self._f) if self._macho.is32Bit() else getLL(self._f)
        offset = getInt(self._f) if self._macho.is32Bit() else getLL(self._f)
        segsize = getInt(self._f) if self._macho.is32Bit() else getLL(self._f)
        maxprot = getInt(self._f)
        initprot = getInt(self._f)
        nsects = getInt(self._f)
        flags = getInt(self._f)

        if self._macho.isLittle():
            vmaddr = little(vmaddr, 'I') if self._macho.is32Bit() \
                else little(vmaddr, 'Q')
            vmsize = little(vmsize, 'I') if self._macho.is32Bit() \
                else little(vmsize, 'Q')
            offset = little(offset, 'I') if self._macho.is32Bit() \
                else little(offset, 'Q')
            segsize = little(segsize, 'I') if self._macho.is32Bit() \
                else little(segsize, 'Q')
            maxprot = little(maxprot, 'I')
            initprot = little(initprot, 'I') 
            nsects = little(nsects, 'I')
            flags = little(flags, 'I')

        maxprot = dictionary.protections[maxprot & 0b111]
        initprot = dictionary.protections[initprot & 0b111]        

        segment = Segment(cmd=lc.getCmd(), size=lc.getSize(), name=name,
                          vmaddr=vmaddr, vmsize=vmsize, offset=offset,
                          segsize=segsize, maxprot=maxprot, initprot=initprot,
                          nsects=nsects)

        if self._macho.is32Bit():
            sect_size = 68
        else:
            sect_size = 80
        for i in range(segment.getNSects()):
            if self._f.tell() + sect_size > self._file_size:
                data = {
                    'offset': self._f.tell(),
                    'file_size': self._file_size
                }
                a = Abnormality(title='SECTION OUT OF BOUNDS', data=data)
                break
            sect = self.parseSection()
            segment.addSect(sect)

        self.parseSegmentFlags(segment, flags)
        self._macho.addLC(segment)

    def parseSymTab(self, lc):
        symoff = getInt(self._f)
        nsyms = getInt(self._f)
        stroff = getInt(self._f)
        strsize = getInt(self._f)

        if self._macho.isLittle():
            symoff = little(symoff, 'I')
            nsyms = little(nsyms, 'I')
            stroff = little(stroff, 'I')
            strsize = little(strsize, 'I')

        symtab = SymbolTable(offset=symoff, nsyms=nsyms)
        strtab = StringTable(offset=stroff, size=strsize)

        self._macho.setSymTab(symtab)
        self._macho.setStrTab(strtab)

        lc.addData('symoff', symoff)
        lc.addData('nsyms', nsyms)
        lc.addData('stroff', stroff)
        lc.addData('strsize', strsize)

        self._macho.addLC(lc)

    def parseSymSeg(self, lc):
        offset = getInt(self._f)
        size = getInt(self._f)

        if self._macho.isLittle():
            offset = little(offset, 'I')
            size = little(size, 'I')

        lc.addData('offset', offset)
        lc.addData('size', size)

        self._macho.addLC(lc)

    def parseThread(self, lc):
        state = getInt(self._f)
        count = getInt(self._f)
        self._f.read(lc.getSize() - 16)

        if self._macho.isLittle():
            state = little(state, 'I')
            count = little(count, 'I')

        try:
            state = dictionary.thread_states[state]
        except:
            data = {
                'offset': self._f.tell() - lc.getSize(),
                'state': state
            }
            a = Abnormality(title='INVALID THREAD STATE FLAVOR', data=data)
            self.addAbnormality(a)

        lc.addData('state', state)
        lc.addData('count', count)

        self._macho.addLC(lc)

    def parseFVMLib(self, lc):
        self._f.read(lc.getSize() - 8)
        lc.addData('msg', 'OBSOLETE')
        self._macho.addLC(lc)

    def parseIdent(self, lc):
        self._f.read(lc.getSize() - 8)
        lc.addData('msg', 'OBSOLETE')
        self._macho.addLC(lc)

    def parseFVMFile(self, lc):
        self._f.read(lc.getSize() - 8)
        lc.addData('msg', 'INTERNAL ONLY')
        self._macho.addLC(lc)

    def parsePrePage(self, lc):
        self._f.read(lc.getSize() - 8)
        lc.addData('msg', 'INTERNAL ONLY')
        self._macho.addLC(lc)

    def parseDySymTab(self, lc):
        il = getInt(self._f)
        nl = getInt(self._f)
        ie = getInt(self._f)
        ne = getInt(self._f)
        iu = getInt(self._f)
        nu = getInt(self._f)
        self._f.read(lc.getSize() - 32)

        if self._macho.isLittle():
            il = little(il, 'I')
            nl = little(nl, 'I')
            ie = little(ie, 'I')
            ne = little(ne, 'I')
            iu = little(iu, 'I')
            nu = little(nu, 'I')

        self._macho.getSymTab().setIL(il)
        self._macho.getSymTab().setNL(nl)
        self._macho.getSymTab().setIE(ie)
        self._macho.getSymTab().setNE(ne)
        self._macho.getSymTab().setIU(iu)
        self._macho.getSymTab().setNU(nu)

        lc.addData('il', il)
        lc.addData('nl', nl)
        lc.addData('ie', ie)
        lc.addData('ne', ne)
        lc.addData('iu', iu)
        lc.addData('nu', nu)

        self._macho.addLC(lc)

    def parseLoadDylib(self, lc):
        offset = getInt(self._f)

        if self._macho.isLittle():
            offset = little(offset, 'I')

        # skip to dylib
        self._f.read(offset - 12)
        dylib = strip(self._f.read(lc.getSize() - 24))
        self._macho.addDylib(dylib)

        lc.addData('dylib', dylib)

        self._macho.addLC(lc)

    def parseLoadDylinker(self, lc):
        # first char is \n
        name = strip(self._f.read(lc.getSize() - 8)[1:])
        lc.addData('name', name)

        self._macho.addLC(lc)

    def parsePreboundDylib(self, lc):
        dylib = readstring(self._f)
        self._f.read(lc.getSize() - (9 + len(dylib)))

        lc.addData('dylib', dylib)

        self._macho.addLC(lc)

    def parseRoutines(self, lc):
        if lc.getCmd() == 'ROUTINES':
            init_address = getInt(self._f)
            init_module = getInt(self._f)
            if self._macho.isLittle():
                init_address = little(init_address, 'I')
                init_module = little(init_module, 'I')
            self._f.read(24)
        else:
            init_address = getLL(self._f)
            init_module = getLL(self._f)
            if self._macho.isLittle():
                init_address = little(init_address, 'Q')
                init_module = little(init_module, 'Q')
            self._f.read(48)

        lc.addData('init_address', init_address)
        lc.addData('init_module', init_module)

        self._macho.addLC(lc)

    def parseSubStuff(self, lc):
        name = strip(self._f.read(lc.getSize() - 8))
        lc.addData('name', name)

        self._macho.addLC(lc)

    def parseTwoLevelHints(self, lc):
        offset = getInt(self._f)
        nhints = getInt(self._f)

        if self._macho.isLittle():
            offset = little(offset, 'I')
            nhints = little(nhints, 'I')

        lc.addData('offset', offset)
        lc.addData('nhints', nhints)

        self._macho.addLC(lc)

    def parsePrebindCksum(self, lc):
        cksum = getInt(self._f)

        if self._macho.isLittle():
            cksum = little(cksum, 'I')

        lc.addData('cksum', cksum)

        self._macho.addLC(lc)

    def parseUUID(self, lc):
        uuid = self._f.read(16)

        if self._macho.isLittle():
            uuid = UUID(bytes=little(uuid, '16s'))
        else:
            uuid = UUID(bytes=uuid)

        lc.addData('uuid', uuid.hex)

        self._macho.addLC(lc)

    def parseLinkedITData(self, lc):
        offset = getInt(self._f)
        size = getInt(self._f)

        if self._macho.isLittle():
            offset = little(offset, 'I')
            size = little(size, 'I')

        lc.addData('offset', offset)
        lc.addData('size', size)

        self._macho.addLC(lc)

    def parseEncryptionInfo(self, lc):
        offset = getInt(self._f)
        size = getInt(self._f)
        id = getInt(self._f)

        if self._macho.isLittle():
            offset = little(offset, 'I')
            size = little(size, 'I')
            id = little(id, 'I')

        lc.addData('offset', offset)
        lc.addData('size', size)
        lc.addData('id', id)

        if lc.getCmd() == 'ENCRYPTION_INFO_64':
            # Skip padding
            self._f.read(4)

        self._macho.addLC(lc)

    def parseDyldInfo(self, lc):
        rebase_off = getInt(self._f)
        rebase_size = getInt(self._f)
        bind_off = getInt(self._f)
        bind_size = getInt(self._f)
        weak_bind_off = getInt(self._f)
        weak_bind_size = getInt(self._f)
        lazy_bind_off = getInt(self._f)
        lazy_bind_size = getInt(self._f)
        export_off = getInt(self._f)
        export_size = getInt(self._f)

        if self._macho.isLittle():
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

        lc.addData('rebase_off', rebase_off)
        lc.addData('rebase_size', rebase_size)
        lc.addData('bind_off', bind_off)
        lc.addData('bind_size', bind_size)
        lc.addData('weak_bind_off', weak_bind_off)
        lc.addData('weak_bind_size', weak_bind_size)
        lc.addData('lazy_bind_off', lazy_bind_off)
        lc.addData('lazy_bind_size', lazy_bind_size)
        lc.addData('export_off', export_off)
        lc.addData('export_size', export_size)

        self._macho.addLC(lc)

    def parseVersionMinOS(self, lc):
        version = getInt(self._f)
        sdk = getInt(self._f)

        if self._macho.isLittle():
            version = little(version, 'I')
            sdk = little(sdk, 'I')

        vx = version >> 16
        vy = (version >> 8) & 0xff
        vz = version & 0xff
        version = OSVersion(vx=vx, vy=vy, vz=vz)

        sx = str(sdk >> 16)
        sy = str((sdk >> 8) & 0xff)
        sz = str(sdk & 0xff)
        sdk = sx + '.' + sy + '.' + sz

        lc.addData('version', version.getVersion())
        lc.addData('sdk', sdk)

        self._macho.setMinOS(version)
        self._macho.addLC(lc)

    def parseSourceVersion(self, lc):
        version = getLL(self._f)
        if self._macho.isLittle():
            version = little(version, 'Q')

        a = str((version >> 40) & 0xffffff)
        b = str((version >> 30) & 0x3ff)
        c = str((version >> 20) & 0x3ff)
        d = str((version >> 10) & 0x3ff)
        e = str(version & 0x3ff)

        # TODO: fix source version.
        version = a + '.' + b + '.' + c + '.' + d + '.' + e

        lc.addData('version', version)

        self._macho.addLC(lc)

    def parseLinkerOption(self, lc):
        count = getInt(self._f)
        if self._macho.isLittle():
            count = little(count, 'I')
        linker_options = []
        start = self._f.tell()
        for i in range(count):
            linker_option = readstring(self._f)
            linker_options.append(linker_option)

        length = self._f.tell() - start
        self._f.read(lc.getSize() - length - 12)

        lc.addData('count', count)
        lc.addData('linker_options', linker_options)

        self._macho.addLC(lc)

    def parseRPath(self, lc):
        # first char is \n
        path = strip(self._f.read(lc.getSize() - 8)[1:])
        lc.addData('path', path)

        self._macho.addLC(lc)

    def parseMain(self, lc):
        offset = getLL(self._f)
        size = getLL(self._f)

        if self._macho.isLittle():
            offset = little(offset, 'Q')
            size = little(size, 'Q')

        lc.addData('offset', offset)
        lc.addData('size', size)

        self._macho.addLC(lc)

    def parseLCs(self):
        for i in range(self._macho.getNLCs()):
            cmd = getInt(self._f)
            size = getInt(self._f)

            if self._macho.getEndi() == 'little':
                cmd = little(cmd, 'I')
                size = little(size, 'I')

            # print ('(offset, cmd, size): (' + str(self._f.tell() - 8) + ', ' +
            #       str(cmd) + ', ' + str(size) + ')')

            try:
                cmd = dictionary.loadcommands[cmd]
            except:
                data = {
                    'offset': self._f.tell() - 8,
                    'cmd': cmd
                }
                a = Abnormality(title='UNKNOWN LOADCOMMAND', data=data)
                self.addAbnormality(a)
                lc = LoadCommand(cmd=cmd, size=size)
                self._macho.addLC(lc)
                self._f.read(size - 8)
                continue

            lc = LoadCommand(cmd=cmd, size=size)

            if cmd == 'SEGMENT' or cmd == 'SEGMENT_64':
                self.parseSegment(lc)
            elif cmd == 'SYMTAB':
                self.parseSymTab(lc)
            elif cmd == 'SYMSEG':
                self.parseSymSeg(lc)
            elif cmd == 'THREAD' or cmd == 'UNIXTHREAD':
                self.parseThread(lc)
            elif cmd == 'LOADFVMLIB' or cmd == 'IDFVMLIB':
                self.parseFVMLib(lc)
            elif cmd == 'IDENT':
                self.parseIdent(lc)
            elif cmd == 'FVMFILE':
                self.parseFVMFile(lc)
            elif cmd == 'PREPAGE':
                self.parsePrePage(lc)
            elif cmd == 'DYSYMTAB':
                self.parseDySymTab(lc)
            elif (cmd == 'LOAD_DYLIB' or cmd == 'ID_DYLIB' or
                  cmd == 'LAZY_LOAD_DYLIB' or cmd == 'LOAD_WEAK_DYLIB' or
                  cmd == 'REEXPORT_DYLIB' or cmd == 'LOAD_UPWARD_DYLIB'):
                self.parseLoadDylib(lc)
            elif (cmd == 'LOAD_DYLINKER' or cmd == 'ID_DYLINKER' or
                  cmd == 'DYLD_ENVIRONMENT'):
                self.parseLoadDylinker(lc)
            elif cmd == 'PREBOUND_DYLIB':
                self.parsePreboundDylib(lc)
            elif cmd == 'ROUTINES' or cmd == 'ROUTINES_64':
                self.parseRoutines(lc)
            elif (cmd == 'SUB_FRAMEWORK' or cmd == 'SUB_UMBRELLA' or
                  cmd == 'SUB_CLIENT' or cmd == 'SUB_LIBRARY'):
                self.parseSubStuff(lc)
            elif cmd == 'TWOLEVEL_HINTS':
                self.parseTwoLevelHints(lc)
            elif cmd == 'PREBIND_CKSUM':
                self.parsePrebindCksum(lc)
            elif cmd == 'UUID':
                self.parseUUID(lc)
            elif (cmd == 'CODE_SIGNATURE' or cmd == 'SEGMENT_SPLIT_INFO' or
                  cmd == 'FUNCTION_STARTS' or cmd == 'DATA_IN_CODE' or
                  cmd == 'DYLIB_CODE_SIGN_DRS' or
                  cmd == 'LINKER_OPTIMIZATION_HINT'):
                self.parseLinkedITData(lc)
            elif cmd == 'ENCRYPTION_INFO' or cmd == 'ENCRYPTION_INFO_64':
                self.parseEncryptionInfo(lc)
            elif cmd == 'DYLD_INFO' or cmd == 'DYLD_INFO_ONLY':
                self.parseDyldInfo(lc)
            elif (cmd == 'VERSION_MIN_MACOSX' or
                  cmd == 'VERSION_MIN_IPHONEOS' or
                  cmd == 'VERSION_MIN_WATCHOS'):
                self.parseVersionMinOS(lc)
            elif cmd == 'SOURCE_VERSION':
                self.parseSourceVersion(lc)
            elif cmd == 'LINKER_OPTION':
                self.parseLinkerOption(lc)
            elif cmd == 'RPATH':
                self.parseRPath(lc)
            elif cmd == 'MAIN':
                self.parseMain(lc)
