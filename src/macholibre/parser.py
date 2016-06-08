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


import hashlib
import plistlib
import dictionary

from file import File
from macho import MachO
from math import exp, log
from symbol import Symbol
from signature import Signature
from universal import Universal
from ctypescrypto import cms, oid
from abnormality import Abnormality
from certificate import Certificate
from entitlement import Entitlement
from requirement import Requirement
from codedirectory import CodeDirectory
from loadcommander import LoadCommander
from functionimport import FunctionImport
from utilities import getFileName, getInt, getLL, little, readstring


class Parser(object):

    # Constructor
    def __init__(self, path=None):
        # Fields
        self._abnormalities = []
        self._path = path
        self._file = File(name=getFileName(self._path))
        self._f = open(path, 'rb')

    # Getters
    def getAbnormalities(self): return self._abnormalities

    def getPath(self): return self._path

    def getFile(self): return self._file

    def getF(self): return self._f

    # Setters
    def setPath(self, path): self._path = path

    def setFile(self, file): self._file = file

    def setF(self, f): self._f = f

    # Functions
    def addAbnormality(self, abnormality):
        self._abnormalities.append(abnormality)

    def identifyFile(self, offset):
        prev = self._f.tell()
        self._f.seek(offset)
        magic = getInt(self._f)
        self._f.seek(prev)
        if magic not in dictionary.machos:
            return magic
        return dictionary.machos[magic]

    def getFileSize(self):
        prev = self._f.tell()
        self._f.seek(0)
        size = len(self._f.read())
        self._f.seek(prev)
        return size

    def getFileHashes(self):
        self._f.seek(0)
        b = self._f.read()
        md5 = hashlib.md5(b).hexdigest()
        sha1 = hashlib.sha1(b).hexdigest()
        sha256 = hashlib.sha256(b).hexdigest()
        return {'md5': md5, 'sha1': sha1, 'sha256': sha256}

    def getCertNameData(self, name, o):
        try:
            return name[o]
        except KeyError:
            return 'n/a'

    def listMachOFlags(self, flags):
        l = []
        j = 0
        while j < 28:
            if (0x1 & (flags >> j)) == 0x1:
                l.append(dictionary.flags[2 ** j])
            j = j + 1

        return l

    def parseSyms(self, macho):
        prev = self._f.tell()
        true_offset = macho.getOffset() + macho.getSymTab().getOffset()
        if macho.is64Bit():
            symbol_size = 60
        else:
            symbol_size = 56
        # print 'to:', true_offset
        # print macho.getOffset(), macho.getSize()
        if (true_offset < macho.getOffset() + macho.getSize() and
                true_offset < self._file.getSize()):
            self._f.seek(true_offset)
            for i in range(macho.getSymTab().getNSyms()):
                # print self._f.tell()
                if ((self._f.tell() + symbol_size > macho.getOffset() +
                     macho.getSize()) or (self._f.tell() + symbol_size >
                                          self._file.getSize())):
                    data = {
                        'offset': self._f.tell(),
                        'mach-o_size': macho.getSize(),
                        'mach-o_offset': macho.getOffset(),
                        'file_size': self._file.getSize()
                    }
                    a = Abnormality(title='REMAINING SYMBOLS OUT OF BOUNDS',
                                    data=data)
                    self.addAbnormality(a)
                    self._f.seek(prev)
                    return
                else:
                    index = getInt(self._f)
                    sym_type = int(self._f.read(1).encode('hex'), 16)
                    sect = int(self._f.read(1).encode('hex'), 16)
                    desc = int(self._f.read(2).encode('hex'), 16)
                    value = None
                    if macho.is64Bit():
                        if macho.isLittle():
                            value = little(getLL(self._f), 'Q')
                        else:
                            value = getLL(self._f)
                    else:
                        if macho.isLittle():
                            value = little(getInt(self._f), 'I')
                        else:
                            value = getInt(self._f)

                if macho.isLittle():
                    index = little(index, 'I')

                if sym_type >= 32:
                    if sym_type in dictionary.stabs:
                        stab = dictionary.stabs[sym_type]
                    else:
                        offset = self._f.tell() - symbol_size
                        data = {
                            'offset': offset,
                            'index': index,
                            'sym_type': sym_type,
                            'sect': sect,
                            'desc': desc,
                            'value': value
                        }
                        a = Abnormality(title='UNKNOWN STAB', data=data)
                        self.addAbnormality(a)
                        continue
                    sym = Symbol(index=index, stab=stab, sect=sect,
                                 value=value)
                    macho.getSymTab().addSym(sym)
                else:
                    pext = sym_type & 0x10
                    if sym_type & 0x0e in dictionary.n_types:
                        n_type = dictionary.n_types[sym_type & 0x0e]
                    else:
                        offset = self._f.tell() - symbol_size
                        data = {
                            'offset': offset,
                            'index': index,
                            'pext': pext,
                            'n_type': sym_type & 0x0e,
                            'sect': sect,
                            'desc': desc,
                            'value': value
                        }
                        a = Abnormality(title='UNKNOWN N_TYPE', data=data)
                        self.addAbnormality(a)
                    ext = sym_type & 0x01

                    if macho.isLittle():
                        dylib = desc & 0x0f
                        ref = (desc >> 8) & 0xff
                    else:
                        dylib = (desc >> 8) & 0xff
                        ref = desc & 0x0f

                    sym = Symbol(index=index, pext=pext, sym_type=n_type,
                                 ext=ext, sect=sect, dylib=dylib, ref=ref,
                                 value=value)
                    macho.getSymTab().addSym(sym)

                # print self._f.tell()
                # print sym.getIndex(), sym.getValue()
        else:
            data = {
                'offset': true_offset,
                'mach-o_size': macho.getSize(),
                'mach-o_offset': macho.getOffset(),
                'file_size': self._file.getSize()
            }
            a = Abnormality(title='SYMBOL TABLE OUT OF BOUNDS', data=data)
            self.addAbnormality(a)

        self._f.seek(prev)

    def parseImportsAndStrings(self, macho):
        prev = self._f.tell()
        true_offset = macho.getOffset() + macho.getStrTab().getOffset()

        # blacklist = ('dyld_', '_OBJC_', '.objc_', '___stack_chk_')

        if macho.hasFlag('TWOLEVEL'):
            for i in macho.getSymTab().genSyms():
                if i.isImp():
                    self._f.seek(true_offset + i.getIndex())
                    if ((self._f.tell() > (true_offset +
                                           macho.getStrTab().getSize())) or
                            (self._f.tell() > self._file.getSize())):
                        data = {
                            'offset': self._f.tell(),
                            'strtab_offset': true_offset,
                            'strtab_size': macho.getStrTab().getSize(),
                            'file_size': self._file.getSize()
                        }
                        a = Abnormality(title='BAD STRING INDEX', data=data)
                        self.addAbnormality(a)
                        continue
                    func = readstring(self._f)
                    # if func.startswith(blacklist):
                    #    continue
                    if i.getDylib() == 0:
                        dylib = 'SELF_LIBRARY'
                    elif i.getDylib() <= len(macho.getDylibs()):
                        dylib = macho.getDylibs()[i.getDylib() - 1]
                    elif i.getDylib() == 254:
                        dylib = 'DYNAMIC_LOOKUP'
                    elif i.getDylib() == 255:
                        dylib = 'EXECUTABLE'
                    else:
                        data = {
                            'dylib': i.getDylib(),
                            'dylib_len': len(macho.getDylibs())
                        }
                        a = Abnormality(title='DYLIB OUT OF RANGE', data=data)
                        self.addAbnormality(a)
                        dylib = str(i.getDylib()) + ' (OUT OF RANGE)'
                    imp = FunctionImport(func=func, dylib=dylib)
                    macho.addImport(imp)
                else:
                    self._f.seek(true_offset + i.getIndex())
                    if ((self._f.tell() > (true_offset +
                                           macho.getStrTab().getSize())) or
                            (self._f.tell() > self._file.getSize())):
                        data = {
                            'offset': self._f.tell(),
                            'strtab_offset': true_offset,
                            'strtab_size': macho.getStrTab().getSize(),
                            'file_size': self._file.getSize()
                        }
                        a = Abnormality(title='BAD STRING INDEX', data=data)
                        self.addAbnormality(a)
                        continue
                    string = readstring(self._f)
                    if string != '':
                        macho.getStrTab().addString(string)
        else:
            for i in macho.getSymTab().genSyms():
                if i.isImp():
                    self._f.seek(true_offset + i.getIndex())
                    if self._f.tell() > (true_offset +
                                         macho.getStrTab().getSize()):
                        data = {
                            'offset': self._f.tell(),
                            'strtab_offset': true_offset,
                            'strtab_size': macho.getStrTab().getSize()
                        }
                        a = Abnormality(title='BAD STRING INDEX', data=data)
                        self.addAbnormality(a)
                        continue
                    func = readstring(self._f)
                    imp = FunctionImport(func=func)
                    macho.addImport(imp)
                else:
                    self._f.seek(true_offset + i.getIndex())
                    string = readstring(self._f)
                    if string != '':
                        macho.getStrTab().addString(string)

        self._f.seek(prev)

    def parseCerts(self, signature, offset):
        prev = self._f.tell()
        true_offset = signature.getOffset() + offset
        self._f.seek(true_offset)
        magic = getInt(self._f)
        if magic != dictionary.signatures['BLOBWRAPPER']:
            data = {
                'offset': true_offset,
                'magic': hex(magic),
                'expected': hex(dictionary.signatures['BLOBWRAPPER'])
            }
            a = Abnormality(title='BAD MAGIC - BLOBWRAPPER', data=data)
            self.addAbnormality(a)
            self._f.seek(prev)
            return
        size = getInt(self._f) - 8
        # out = open('cms', 'wb')
        # out.write(self._f.read(size))
        # out.close()
        # exit(0)
        if size > 0:
            signed_data = cms.CMS(self._f.read(size), format='DER')
            for cert in signed_data.certs:
                serial = cert.serial
                subject = {
                    'country': self.getCertNameData(cert.subject,
                                                    oid.Oid('C')),
                    'org': self.getCertNameData(cert.subject, oid.Oid('O')),
                    'org_unit': self.getCertNameData(cert.subject,
                                                     oid.Oid('OU')),
                    'common_name': self.getCertNameData(cert.subject,
                                                        oid.Oid('CN'))
                }
                issuer = {
                    'country': self.getCertNameData(cert.issuer, oid.Oid('C')),
                    'org': self.getCertNameData(cert.issuer, oid.Oid('O')),
                    'org_unit': self.getCertNameData(cert.issuer,
                                                     oid.Oid('OU')),
                    'common_name': self.getCertNameData(cert.issuer,
                                                        oid.Oid('CN'))
                }
                ca = cert.check_ca()
                cert = Certificate(serial=serial, subject=subject,
                                   issuer=issuer, ca=ca)
                signature.addCert(cert)
        else:
            data = {
                'offset': true_offset,
                'size': size
            }
            a = Abnormality(title='NON-POSITIVE CMS SIZE', data=data)
            self.addAbnormality(a)

        self._f.seek(prev)

    def parseCodeDirectory(self, signature, offset):
        prev = self._f.tell()
        true_offset = signature.getOffset() + offset
        self._f.seek(true_offset)
        magic = getInt(self._f)
        if magic != dictionary.signatures['CODEDIRECTORY']:
            data = {
                'offset': true_offset,
                'magic': hex(magic),
                'expected': hex(dictionary.signatures['CODEDIRECTORY'])
            }
            a = Abnormality(title='BAD MAGIC - CODEDIRECTORY', data=data)
            self.addAbnormality(a)
            self._f.seek(prev)
            return
        # Skip size
        self._f.read(4)
        version = getInt(self._f)
        # Not sure how to parse flags yet...
        flags = getInt(self._f)
        hash_offset = getInt(self._f)
        ident_offset = getInt(self._f)
        n_special_slots = getInt(self._f)
        n_code_slots = getInt(self._f)
        code_limit = getInt(self._f)
        hash_size = int(self._f.read(1).encode('hex'), 16)
        hash_type = dictionary.hashes[int(self._f.read(1).encode('hex'), 16)]
        if version >= 0x20200:
            platform = int(self._f.read(1).encode('hex'), 16)
        else:
            # Skip spare1
            self._f.read(1)
        page_size = int(round(exp(int(self._f.read(1).encode('hex'),
                                      16) * log(2))))
        # Skip spare2
        self._f.read(4)
        if version >= 0x20100:
            scatter_offset = getInt(self._f)
        if version >= 0x20200:
            team_id_offset = getInt(self._f)
            self._f.seek(true_offset + team_id_offset)
            team_id = readstring(self._f)
        self._f.seek(true_offset + ident_offset)
        identity = readstring(self._f)
        codedirectory = CodeDirectory(version=version, flags=flags,
                                      hash_offset=hash_offset,
                                      n_special_slots=n_special_slots,
                                      n_code_slots=n_code_slots,
                                      code_limit=code_limit,
                                      hash_size=hash_size, hash_type=hash_type,
                                      page_size=page_size, identity=identity)
        if version >= 0x20100:
            codedirectory.setScatterOffset(scatter_offset)
        if version >= 0x20200:
            codedirectory.setPlatform(platform)
            codedirectory.setTeamIDOffset(team_id_offset)
            codedirectory.setTeamID(team_id)
        self._f.seek(true_offset + hash_offset - n_special_slots * hash_size)
        count = n_special_slots + n_code_slots
        while count > 0:
            hash = self._f.read(hash_size).encode('hex')
            codedirectory.addHash(hash)
            count -= 1

        signature.setCodeDirectory(codedirectory)
        self._f.seek(prev)

    # Mimicking OID parser implementation from:
    # http://opensource.apple.com/source/Security/Security-57337.20.44/OSX/libsecurity_cdsa_utilities/lib/cssmdata.cpp
    def getOID(self, db, p):
        q = 0
        while True:
            q = q * 128 + (db[p] & ~0x80)
            if p < len(db) and db[p] & 0x80:
                p += 1
            else:
                p += 1
                break
        return q, p

    def toOID(self, length):
        if length == 0:
            return ''
        data_bytes = [int(self._f.read(1).encode('hex'),
                          16) for i in range(length)]
        p = 0
        # first byte is composite (q1, q2)
        oid1, p = self.getOID(data_bytes, p)
        q1 = min(oid1 / 40, 2)
        data = str(q1) + '.' + str(oid1 - q1 * 40)

        while p < len(data_bytes):
            d, p = self.getOID(data_bytes, p)
            data += '.' + str(d)

        self._f.read(-length & 3)
        return data

    def parseEntitlement(self, signature, offset):
        prev = self._f.tell()
        true_offset = signature.getOffset() + offset
        self._f.seek(true_offset)
        magic = getInt(self._f)
        if magic != dictionary.signatures['ENTITLEMENT']:
            data = {
                'offset': true_offset,
                'magic': hex(magic),
                'expected': hex(dictionary.signatures['ENTITLEMENT'])
            }
            a = Abnormality(title='BAD MAGIC - ENTITLEMENT', data=data)
            self.addAbnormality(a)
            self._f.seek(prev)
            return
        size = getInt(self._f) - 8
        plist = plistlib.readPlistFromString(self._f.read(size))
        entitlement = Entitlement(size=size, plist=plist)
        signature.addEntitlement(entitlement)
        self._f.seek(prev)

    def parseData(self):
        length = getInt(self._f)
        data = self._f.read(length)
        # Skip padding
        self._f.read(-length & 3)
        return data

    def parseMatch(self):
        match_type = getInt(self._f)
        if match_type in dictionary.matches:
            match_type = dictionary.matches[match_type]
        if match_type == 'matchExists':
            return ' /* exists */'
        elif match_type == 'matchEqual':
            return ' = "' + str(self.parseData()) + '"'
        elif match_type == 'matchContains':
            return ' ~ "' + str(self.parseData()) + '"'
        elif match_type == 'matchBeginsWith':
            return ' = "' + str(self.parseData()) + '*"'
        elif match_type == 'matchEndsWith':
            return ' = "*' + str(self.parseData()) + '"'
        elif match_type == 'matchLessThan':
            return ' < ' + str(int(self.parseData().encode('hex'), 16))
        elif match_type == 'matchGreaterThan':
            return ' > ' + str(int(self.parseData().encode('hex'), 16))
        elif match_type == 'matchLessEqual':
            return ' <= ' + str(int(self.parseData().encode('hex'), 16))
        elif match_type == 'matchGreaterEqual':
            return ' >= ' + str(int(self.parseData().encode('hex'), 16))
        else:
            return ' UNKNOWN MATCH TYPE (' + str(match_type) + ')'

    def parseExpression(self, in_or):
        # Zero out flags in high byte
        operator = dictionary.operators[getInt(self._f) & 0xfff]
        expression = ''
        if operator == 'False':
            expression += 'never'
        elif operator == 'True':
            expression += 'always'
        elif operator == 'Ident':
            expression += 'identity "' + str(self.parseData()) + '"'
        elif operator == 'AppleAnchor':
            expression += 'anchor apple'
        elif operator == 'AppleGenericAnchor':
            expression += 'anchor apple generic'
        elif operator == 'AnchorHash':
            cert_slot = getInt(self._f)
            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]
            else:
                cert_slot = str(cert_slot)
            expression += ('certificate ' + cert_slot + ' = ' +
                           str(self.parseData().encode('hex')))
        elif operator == 'InfoKeyValue':
            expression += ('info[' + str(self.parseData()) + '] = "' +
                           str(self.parseData()) + '"')
        elif operator == 'And':
            if in_or:
                expression += ('(' + self.parseExpression(False) + ' and ' +
                               self.parseExpression(False) + ')')
            else:
                expression += (self.parseExpression(False) + ' and ' +
                               self.parseExpression(False))
        elif operator == 'Or':
            if in_or:
                expression += ('(' + self.parseExpression(True) + ' or ' +
                               self.parseExpression(True) + ')')
            else:
                expression += (self.parseExpression(True) + ' or ' +
                               self.parseExpression(True))
        elif operator == 'Not':
            expression += '! ' + self.parseExpression(False)
        elif operator == 'CDHash':
            expression += 'cdhash ' + str(self.parseData().encode('hex'))
        elif operator == 'InfoKeyField':
            expression += ('info[' + str(self.parseData()) + ']' +
                           self.parseMatch())
        elif operator == 'EntitlementField':
            expression += ('entitlement[' + str(self.parseData()) +
                           ']' + self.parseMatch())
        elif operator == 'CertField':
            cert_slot = getInt(self._f)
            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]
            else:
                cert_slot = str(cert_slot)
            expression += ('certificate ' + cert_slot + '[' +
                           str(self.parseData()) + ']' + self.parseMatch())
        elif operator == 'CertGeneric':
            cert_slot = getInt(self._f)
            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]
            else:
                cert_slot = str(cert_slot)
            length = getInt(self._f)
            expression += ('certificate ' + cert_slot + '[field.' +
                           self.toOID(length) + ']' + self.parseMatch())
        elif operator == 'CertPolicy':
            cert_slot = getInt(self._f)
            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]
            else:
                cert_slot = str(cert_slot)
            expression += ('certificate ' + cert_slot + '[policy.' +
                           str(self.parseData()) + ']' + self.parseMatch())
        elif operator == 'TrustedCert':
            cert_slot = getInt(self._f)
            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]
            else:
                cert_slot = str(cert_slot)
            expression += 'certificate ' + cert_slot + ' trusted'
        elif operator == 'TrustedCerts':
            expression += 'anchor trusted'
        elif operator == 'NamedAnchor':
            expression += 'anchor apple ' + str(self.parseData())
        elif operator == 'NamedCode':
            expression += '(' + str(self.parseData()) + ')'
        elif operator == 'Platform':
            expression += 'platform = ' + str(getInt(self._f))

        if isinstance(expression, unicode):
            return expression
        else:
            return unicode(expression, errors='replace')

    def parseRequirement(self, requirement, offset):
        prev = self._f.tell()
        true_offset = offset + requirement.getOffset()
        self._f.seek(true_offset)
        magic = getInt(self._f)
        if magic != dictionary.signatures['REQUIREMENT']:
            data = {
                'offset': true_offset,
                'magic': hex(magic),
                'expected': hex(dictionary.signatures['REQUIREMENT'])
            }
            a = Abnormality(title='BAD MAGIC - REQUIREMENT', data=data)
            self.addAbnormality(a)
            self._f.seek(prev)
            return
        # Skip size and kind
        self._f.read(8)
        requirement.setExpression(self.parseExpression(False))

        self._f.seek(prev)

    def parseRequirements(self, signature, offset):
        prev = self._f.tell()
        true_offset = signature.getOffset() + offset
        self._f.seek(true_offset)
        magic = getInt(self._f)
        if magic != dictionary.signatures['REQUIREMENTS']:
            data = {
                'offset': true_offset,
                'magic': hex(magic),
                'expected': hex(dictionary.signatures['REQUIREMENTS'])
            }
            a = Abnormality(title='BAD MAGIC - REQUIREMENTS', data=data)
            self.addAbnormality(a)
            self._f.seek(prev)
            return
        # Skip size
        self._f.read(4)
        count = getInt(self._f)
        while count > 0:
            req_type = dictionary.requirements[getInt(self._f)]
            offset = getInt(self._f)
            requirement = Requirement(req_type=req_type, offset=offset)
            self.parseRequirement(requirement, true_offset)
            signature.addRequirement(requirement)
            count -= 1

        self._f.seek(prev)

    def parseSig(self, macho):
        if not macho.hasLC('CODE_SIGNATURE'):
            return
        prev = self._f.tell()
        true_offset = (macho.getOffset() +
                       macho.getLC('CODE_SIGNATURE').getData()['offset'])
        if true_offset >= self._file.getSize():
            data = {
                'offset': true_offset,
                'file_size': self._file.getSize()
            }
            a = Abnormality(title='CODE_SIGNATURE OUT OF BOUNDS', data=data)
            self.addAbnormality(a)
            return
        self._f.seek(true_offset)
        magic = getInt(self._f)
        if magic != dictionary.signatures['EMBEDDED_SIGNATURE']:
            data = {
                'offset': true_offset,
                'magic': hex(magic),
                'expected': hex(dictionary.signatures['EMBEDDED_SIGNATURE'])
            }
            a = Abnormality(title='BAD MAGIC - EMBEDDED_SIGNATURE', data=data)
            self.addAbnormality(a)
            self._f.seek(prev)
            return
        size = getInt(self._f)
        count = getInt(self._f)
        signature = Signature(offset=true_offset, size=size, count=count)
        while count > 0:
            index_type = getInt(self._f)
            try:
                index_type = dictionary.indeces[index_type]
            except:
                data = {
                    'offset': self._f.tell() - 4,
                    'index_type': index_type
                }
                a = Abnormality(title='INVALID CODE_SIGNATURE INDEX_TYPE',
                                data=data)
                self.addAbnormality(a)
            offset = getInt(self._f)
            if index_type == 'SignatureSlot':
                self.parseCerts(signature, offset)
            elif index_type == 'CodeDirectorySlot':
                self.parseCodeDirectory(signature, offset)
            elif index_type == 'EntitlementSlot':
                self.parseEntitlement(signature, offset)
            elif index_type == 'RequirementsSlot':
                self.parseRequirements(signature, offset)
            count -= 1

        macho.setSignature(signature)
        self._f.seek(prev)

    def parseMachO(self, macho):
        self._f.seek(macho.getOffset())
        # skip magic
        self._f.read(4)
        cputype = getInt(self._f)
        # print 'cputype: ' + str(cputype)
        # print 'offset: ' + str(self._f.tell())
        subtype = getInt(self._f)
        filetype = getInt(self._f)
        nlcs = getInt(self._f)
        slcs = getInt(self._f)
        flags = getInt(self._f)

        if macho.is64Bit():
            # skip padding
            self._f.read(4)

        if macho.isLittle():
            cputype = little(cputype, 'I')
            subtype = little(subtype, 'I')
            filetype = little(filetype, 'I')
            nlcs = little(nlcs, 'I')
            slcs = little(slcs, 'I')
            flags = little(flags, 'I')

        try:
            cpu = dictionary.cputypes[cputype][-2]
        except:
            cpu = cputype
            data = {
                'offset': macho.getOffset() + 4,
                'cputype': cputype
            }
            a = Abnormality(title='UNKNOWN CPUTYPE', data=data)
            self.addAbnormality(a)
        try:
            subtype = dictionary.cputypes[cputype][subtype]
        except:
            data = {
                'offset': macho.getOffset() + 8,
                'cputype': cputype,
                'subtype': subtype
            }
            a = Abnormality(title='UNKNOWN SUBTYPE', data=data)
            self.addAbnormality(a)
        try:
            filetype = dictionary.filetypes[filetype]
        except:
            data = {
                'offset': macho.getOffset() + 12,
                'filetype': filetype
            }
            a = Abnormality(title='UNKNOWN FILETYPE', data=data)
            self.addAbnormality(a)
        flags = self.listMachOFlags(flags)

        macho.setCPUType(cpu)
        macho.setSubType(subtype)
        macho.setFileType(filetype)
        macho.setNLCs(nlcs)
        macho.setSLCs(slcs)
        macho.setFlags(flags)

        lc = LoadCommander(f=self._f, macho=macho, file_size=self._file.getSize())
        lc.parseLCs()
        self._abnormalities += lc.getAbnormalities()

        # Need to investigate whether the presence of a
        # symbol/string table is expected and whether the
        # abscence is indicative of shenanigans.
        if macho.hasLC('SYMTAB'):
            self.parseSyms(macho)
            self.parseImportsAndStrings(macho)

        if macho.hasLC('CODE_SIGNATURE'):
            self.parseSig(macho)

        if not macho.isArchive():
            self._file.setContent(macho)

    def parseUniversal(self):
        self._f.seek(0)
        # skip magic
        self._f.read(4)
        nmachos = getInt(self._f)
        u = Universal(nmachos=nmachos)
        u_size = self.getFile().getSize()
        for i in range(u.getNMachOs()):
            # skip cputype, subtype
            self._f.read(8)
            offset = getInt(self._f)
            size = getInt(self._f)
            # Abnormality OUT_OF_BOUNDS check
            if offset + size > u_size:
                data = {
                    'offset': offset,
                    'size': size,
                    'file_size': u_size
                }
                a = Abnormality(title='MACH-O OUT OF BOUNDS', data=data)
                self.addAbnormality(a)
                continue
            # skip align
            self._f.read(4)
            identity = self.identifyFile(offset)
            # Abnormality BAD_MAGIC check
            if identity not in dictionary.machos.values():
                data = {
                    'offset': offset,
                    'magic': identity,
                }
                a = Abnormality(title='BAD MAGIC - MACH-O')
                self.addAbnormality(a)
                continue
            u.addMachO(MachO(archive=True, offset=offset, arch=identity[0],
                             endi=identity[1], size=size))

        for i in u.genMachOs():
            self.parseMachO(i)

        self._file.setContent(u)

    def parseFile(self):
        size = self.getFileSize()
        hashes = self.getFileHashes()
        self._file.setSize(size)
        self._file.setHashes(hashes)
        identity = self.identifyFile(0)
        if identity == 'universal':
            self.parseUniversal()
        else:
            self.parseMachO(MachO(archive=False, offset=0, arch=identity[0],
                                      endi=identity[1], size=self.getFileSize()))
