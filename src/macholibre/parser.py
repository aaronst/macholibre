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
from utilities import get_file_name, get_int, get_ll, little, readstring


class Parser(object):

    # Constructor
    def __init__(self, path=None):
        # Fields
        self.abnormalities = []
        self.path = path
        self.file = File(name=get_file_name(self.path))
        self.f = open(path, 'rb')

    # Functions
    def add_abnormality(self, abnormality):
        self.abnormalities.append(abnormality)

    def identify_file(self, offset):
        prev = self.f.tell()
        self.f.seek(offset)
        magic = get_int(self.f)
        self.f.seek(prev)
        if magic not in dictionary.machos:
            return magic
        return dictionary.machos[magic]

    def get_file_size(self):
        prev = self.f.tell()
        self.f.seek(0)
        size = len(self.f.read())
        self.f.seek(prev)
        return size

    def get_file_hashes(self):
        self.f.seek(0)
        b = self.f.read()
        md5 = hashlib.md5(b).hexdigest()
        sha1 = hashlib.sha1(b).hexdigest()
        sha256 = hashlib.sha256(b).hexdigest()
        return {'md5': md5, 'sha1': sha1, 'sha256': sha256}

    def get_cert_name_data(self, name, o):
        try:
            return name[o]
        except KeyError:
            return 'n/a'

    def list_macho_flags(self, flags):
        l = []
        j = 0
        while j < 28:
            if (0x1 & (flags >> j)) == 0x1:
                l.append(dictionary.flags[2 ** j])
            j = j + 1

        return l

    def parse_syms(self, macho):
        prev = self.f.tell()
        true_offset = macho.offset + macho.symtab.offset
        if macho.is_64_bit():
            symbol_size = 60
        else:
            symbol_size = 56
        if (true_offset < macho.offset + macho.size and
                true_offset < self.file.size):
            self.f.seek(true_offset)
            for i in range(macho.symtab.nsyms):
                if ((self.f.tell() + symbol_size > macho.offset +
                     macho.size) or (self.f.tell() + symbol_size >
                                          self.file.size)):
                    data = {
                        'offset': self.f.tell(),
                        'mach-o_size': macho.size,
                        'mach-o_offset': macho.offset,
                        'file_size': self.file.size
                    }
                    a = Abnormality(title='REMAINING SYMBOLS OUT OF BOUNDS',
                                    data=data)
                    self.add_abnormality(a)
                    self.f.seek(prev)
                    return
                else:
                    index = get_int(self.f)
                    sym_type = int(self.f.read(1).encode('hex'), 16)
                    sect = int(self.f.read(1).encode('hex'), 16)
                    desc = int(self.f.read(2).encode('hex'), 16)
                    value = None
                    if macho.is_64_bit():
                        if macho.is_little():
                            value = little(get_ll(self.f), 'Q')
                        else:
                            value = get_ll(self.f)
                    else:
                        if macho.is_little():
                            value = little(get_int(self.f), 'I')
                        else:
                            value = get_int(self.f)

                if macho.is_little():
                    index = little(index, 'I')

                if sym_type >= 32:
                    if sym_type in dictionary.stabs:
                        stab = dictionary.stabs[sym_type]
                    else:
                        offset = self.f.tell() - symbol_size
                        data = {
                            'offset': offset,
                            'index': index,
                            'sym_type': sym_type,
                            'sect': sect,
                            'desc': desc,
                            'value': value
                        }
                        a = Abnormality(title='UNKNOWN STAB', data=data)
                        self.add_abnormality(a)
                        continue
                    sym = Symbol(index=index, stab=stab, sect=sect,
                                 value=value)
                    macho.symtab.add_sym(sym)
                else:
                    pext = sym_type & 0x10
                    if sym_type & 0x0e in dictionary.n_types:
                        n_type = dictionary.n_types[sym_type & 0x0e]
                    else:
                        offset = self.f.tell() - symbol_size
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
                        self.add_abnormality(a)
                    ext = sym_type & 0x01

                    if macho.is_little():
                        dylib = desc & 0x0f
                        ref = (desc >> 8) & 0xff
                    else:
                        dylib = (desc >> 8) & 0xff
                        ref = desc & 0x0f

                    sym = Symbol(index=index, pext=pext, sym_type=n_type,
                                 ext=ext, sect=sect, dylib=dylib, ref=ref,
                                 value=value)
                    macho.symtab.add_sym(sym)

        else:
            data = {
                'offset': true_offset,
                'mach-o_size': macho.size,
                'mach-o_offset': macho.offset,
                'file_size': self.file.size
            }
            a = Abnormality(title='SYMBOL TABLE OUT OF BOUNDS', data=data)
            self.add_abnormality(a)

        self.f.seek(prev)

    def parse_imports_and_strings(self, macho):
        prev = self.f.tell()
        true_offset = macho.offset + macho.strtab.offset

        if macho.has_flag('TWOLEVEL'):
            for i in macho.symtab.gen_syms():
                if i.is_imp():
                    self.f.seek(true_offset + i.index)
                    if ((self.f.tell() > (true_offset +
                                           macho.strtab.size)) or
                            (self.f.tell() > self.file.size)):
                        data = {
                            'offset': self.f.tell(),
                            'strtab_offset': true_offset,
                            'strtab_size': macho.strtab.size,
                            'file_size': self.file.size
                        }
                        a = Abnormality(title='BAD STRING INDEX', data=data)
                        self.add_abnormality(a)
                        continue
                    func = readstring(self.f)
                    if i.dylib == 0:
                        dylib = 'SELF_LIBRARY'
                    elif i.dylib <= len(macho.dylibs):
                        dylib = macho.dylibs[i.dylib - 1]
                    elif i.dylib == 254:
                        dylib = 'DYNAMIC_LOOKUP'
                    elif i.dylib == 255:
                        dylib = 'EXECUTABLE'
                    else:
                        data = {
                            'dylib': i.dylib,
                            'dylib_len': len(macho.dylibs)
                        }
                        a = Abnormality(title='DYLIB OUT OF RANGE', data=data)
                        self.add_abnormality(a)
                        dylib = str(i.dylib) + ' (OUT OF RANGE)'
                    imp = FunctionImport(func=func, dylib=dylib)
                    macho.add_import(imp)
                else:
                    self.f.seek(true_offset + i.index)
                    if ((self.f.tell() > (true_offset +
                                           macho.strtab.size)) or
                            (self.f.tell() > self.file.size)):
                        data = {
                            'offset': self.f.tell(),
                            'strtab_offset': true_offset,
                            'strtab_size': macho.strtab.size,
                            'file_size': self.file.size
                        }
                        a = Abnormality(title='BAD STRING INDEX', data=data)
                        self.add_abnormality(a)
                        continue
                    string = readstring(self.f)
                    if string != '':
                        macho.strtab.add_string(string)
        else:
            for i in macho.symtab.gen_syms():
                if i.is_imp():
                    self.f.seek(true_offset + i.index)
                    if self.f.tell() > (true_offset +
                                         macho.strtab.size):
                        data = {
                            'offset': self.f.tell(),
                            'strtab_offset': true_offset,
                            'strtab_size': macho.strtab.size
                        }
                        a = Abnormality(title='BAD STRING INDEX', data=data)
                        self.add_abnormality(a)
                        continue
                    func = readstring(self.f)
                    imp = FunctionImport(func=func)
                    macho.add_import(imp)
                else:
                    self.f.seek(true_offset + i.index)
                    string = readstring(self.f)
                    if string != '':
                        macho.strtab.add_string(string)

        self.f.seek(prev)

    def parse_certs(self, signature, offset):
        prev = self.f.tell()
        true_offset = signature.offset + offset
        self.f.seek(true_offset)
        magic = get_int(self.f)
        if magic != dictionary.signatures['BLOBWRAPPER']:
            data = {
                'offset': true_offset,
                'magic': hex(magic),
                'expected': hex(dictionary.signatures['BLOBWRAPPER'])
            }
            a = Abnormality(title='BAD MAGIC - BLOBWRAPPER', data=data)
            self.add_abnormality(a)
            self.f.seek(prev)
            return
        size = get_int(self.f) - 8
        if size > 0:
            signed_data = cms.CMS(self.f.read(size), format='DER')
            for cert in signed_data.certs:
                serial = cert.serial
                subject = {
                    'country': self.get_cert_name_data(cert.subject,
                                                    oid.Oid('C')),
                    'org': self.get_cert_name_data(cert.subject, oid.Oid('O')),
                    'org_unit': self.get_cert_name_data(cert.subject,
                                                     oid.Oid('OU')),
                    'common_name': self.get_cert_name_data(cert.subject,
                                                        oid.Oid('CN'))
                }
                issuer = {
                    'country': self.get_cert_name_data(cert.issuer, oid.Oid('C')),
                    'org': self.get_cert_name_data(cert.issuer, oid.Oid('O')),
                    'org_unit': self.get_cert_name_data(cert.issuer,
                                                     oid.Oid('OU')),
                    'common_name': self.get_cert_name_data(cert.issuer,
                                                        oid.Oid('CN'))
                }
                ca = cert.check_ca()
                cert = Certificate(serial=serial, subject=subject,
                                   issuer=issuer, ca=ca)
                signature.add_cert(cert)
        else:
            data = {
                'offset': true_offset,
                'size': size
            }
            a = Abnormality(title='NON-POSITIVE CMS SIZE', data=data)
            self.add_abnormality(a)

        self.f.seek(prev)

    def parse_codedirectory(self, signature, offset):
        prev = self.f.tell()
        true_offset = signature.offset + offset
        self.f.seek(true_offset)
        magic = get_int(self.f)
        if magic != dictionary.signatures['CODEDIRECTORY']:
            data = {
                'offset': true_offset,
                'magic': hex(magic),
                'expected': hex(dictionary.signatures['CODEDIRECTORY'])
            }
            a = Abnormality(title='BAD MAGIC - CODEDIRECTORY', data=data)
            self.add_abnormality(a)
            self.f.seek(prev)
            return
        # Skip size
        self.f.read(4)
        version = get_int(self.f)
        # Not sure how to parse flags yet...
        flags = get_int(self.f)
        hash_offset = get_int(self.f)
        ident_offset = get_int(self.f)
        n_special_slots = get_int(self.f)
        n_code_slots = get_int(self.f)
        code_limit = get_int(self.f)
        hash_size = int(self.f.read(1).encode('hex'), 16)
        hash_type = dictionary.hashes[int(self.f.read(1).encode('hex'), 16)]
        if version >= 0x20200:
            platform = int(self.f.read(1).encode('hex'), 16)
        else:
            # Skip spare1
            self.f.read(1)
        page_size = int(round(exp(int(self.f.read(1).encode('hex'),
                                      16) * log(2))))
        # Skip spare2
        self.f.read(4)
        if version >= 0x20100:
            scatter_offset = get_int(self.f)
        if version >= 0x20200:
            team_id_offset = get_int(self.f)
            self.f.seek(true_offset + team_id_offset)
            team_id = readstring(self.f)
        self.f.seek(true_offset + ident_offset)
        identity = readstring(self.f)
        codedirectory = CodeDirectory(version=version, flags=flags,
                                      hash_offset=hash_offset,
                                      n_special_slots=n_special_slots,
                                      n_code_slots=n_code_slots,
                                      code_limit=code_limit,
                                      hash_size=hash_size, hash_type=hash_type,
                                      page_size=page_size, identity=identity)
        if version >= 0x20100:
            codedirectory.scatter_offset = scatter_offset
        if version >= 0x20200:
            codedirectory.platform = platform
            codedirectory.team_id_offset = team_id_offset
            codedirectory.team_id = team_id
        self.f.seek(true_offset + hash_offset - n_special_slots * hash_size)
        count = n_special_slots + n_code_slots
        while count > 0:
            hash = self.f.read(hash_size).encode('hex')
            codedirectory.add_hash(hash)
            count -= 1

        signature.codedirectory = codedirectory
        self.f.seek(prev)

    # Mimicking OID parser implementation from:
    # http://opensource.apple.com/source/Security/Security-57337.20.44/OSX/libsecurity_cdsa_utilities/lib/cssmdata.cpp
    def get_oid(self, db, p):
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
        if length == 0:
            return ''
        data_bytes = [int(self.f.read(1).encode('hex'),
                          16) for i in range(length)]
        p = 0
        # first byte is composite (q1, q2)
        oid1, p = self.get_oid(data_bytes, p)
        q1 = min(oid1 / 40, 2)
        data = str(q1) + '.' + str(oid1 - q1 * 40)

        while p < len(data_bytes):
            d, p = self.get_oid(data_bytes, p)
            data += '.' + str(d)

        self.f.read(-length & 3)
        return data

    def parse_entitlement(self, signature, offset):
        prev = self.f.tell()
        true_offset = signature.offset + offset
        self.f.seek(true_offset)
        magic = get_int(self.f)
        if magic != dictionary.signatures['ENTITLEMENT']:
            data = {
                'offset': true_offset,
                'magic': hex(magic),
                'expected': hex(dictionary.signatures['ENTITLEMENT'])
            }
            a = Abnormality(title='BAD MAGIC - ENTITLEMENT', data=data)
            self.add_abnormality(a)
            self.f.seek(prev)
            return
        size = get_int(self.f) - 8
        plist = plistlib.readPlistFromString(self.f.read(size))
        entitlement = Entitlement(size=size, plist=plist)
        signature.add_entitlement(entitlement)
        self.f.seek(prev)

    def parse_data(self):
        length = get_int(self.f)
        data = self.f.read(length)
        # Skip padding
        self.f.read(-length & 3)
        return data

    def parse_match(self):
        match_type = get_int(self.f)
        if match_type in dictionary.matches:
            match_type = dictionary.matches[match_type]
        if match_type == 'matchExists':
            return ' /* exists */'
        elif match_type == 'matchEqual':
            return ' = "' + str(self.parse_data()) + '"'
        elif match_type == 'matchContains':
            return ' ~ "' + str(self.parse_data()) + '"'
        elif match_type == 'matchBeginsWith':
            return ' = "' + str(self.parse_data()) + '*"'
        elif match_type == 'matchEndsWith':
            return ' = "*' + str(self.parse_data()) + '"'
        elif match_type == 'matchLessThan':
            return ' < ' + str(int(self.parse_data().encode('hex'), 16))
        elif match_type == 'matchGreaterThan':
            return ' > ' + str(int(self.parse_data().encode('hex'), 16))
        elif match_type == 'matchLessEqual':
            return ' <= ' + str(int(self.parse_data().encode('hex'), 16))
        elif match_type == 'matchGreaterEqual':
            return ' >= ' + str(int(self.parse_data().encode('hex'), 16))
        else:
            return ' UNKNOWN MATCH TYPE (' + str(match_type) + ')'

    def parse_expression(self, in_or):
        # Zero out flags in high byte
        operator = dictionary.operators[get_int(self.f) & 0xfff]
        expression = ''
        if operator == 'False':
            expression += 'never'
        elif operator == 'True':
            expression += 'always'
        elif operator == 'Ident':
            expression += 'identity "' + str(self.parse_data()) + '"'
        elif operator == 'AppleAnchor':
            expression += 'anchor apple'
        elif operator == 'AppleGenericAnchor':
            expression += 'anchor apple generic'
        elif operator == 'AnchorHash':
            cert_slot = get_int(self.f)
            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]
            else:
                cert_slot = str(cert_slot)
            expression += ('certificate ' + cert_slot + ' = ' +
                           str(self.parse_data().encode('hex')))
        elif operator == 'InfoKeyValue':
            expression += ('info[' + str(self.parse_data()) + '] = "' +
                           str(self.parse_data()) + '"')
        elif operator == 'And':
            if in_or:
                expression += ('(' + self.parse_expression(False) + ' and ' +
                               self.parse_expression(False) + ')')
            else:
                expression += (self.parse_expression(False) + ' and ' +
                               self.parse_expression(False))
        elif operator == 'Or':
            if in_or:
                expression += ('(' + self.parse_expression(True) + ' or ' +
                               self.parse_expression(True) + ')')
            else:
                expression += (self.parse_expression(True) + ' or ' +
                               self.parse_expression(True))
        elif operator == 'Not':
            expression += '! ' + self.parse_expression(False)
        elif operator == 'CDHash':
            expression += 'cdhash ' + str(self.parse_data().encode('hex'))
        elif operator == 'InfoKeyField':
            expression += ('info[' + str(self.parse_data()) + ']' +
                           self.parse_match())
        elif operator == 'EntitlementField':
            expression += ('entitlement[' + str(self.parse_data()) +
                           ']' + self.parse_match())
        elif operator == 'CertField':
            cert_slot = get_int(self.f)
            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]
            else:
                cert_slot = str(cert_slot)
            expression += ('certificate ' + cert_slot + '[' +
                           str(self.parse_data()) + ']' + self.parse_match())
        elif operator == 'CertGeneric':
            cert_slot = get_int(self.f)
            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]
            else:
                cert_slot = str(cert_slot)
            length = get_int(self.f)
            expression += ('certificate ' + cert_slot + '[field.' +
                           self.to_oid(length) + ']' + self.parse_match())
        elif operator == 'CertPolicy':
            cert_slot = get_int(self.f)
            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]
            else:
                cert_slot = str(cert_slot)
            expression += ('certificate ' + cert_slot + '[policy.' +
                           str(self.parse_data()) + ']' + self.parse_match())
        elif operator == 'TrustedCert':
            cert_slot = get_int(self.f)
            if cert_slot in dictionary.cert_slots:
                cert_slot = dictionary.cert_slots[cert_slot]
            else:
                cert_slot = str(cert_slot)
            expression += 'certificate ' + cert_slot + ' trusted'
        elif operator == 'TrustedCerts':
            expression += 'anchor trusted'
        elif operator == 'NamedAnchor':
            expression += 'anchor apple ' + str(self.parse_data())
        elif operator == 'NamedCode':
            expression += '(' + str(self.parse_data()) + ')'
        elif operator == 'Platform':
            expression += 'platform = ' + str(get_int(self.f))

        if isinstance(expression, unicode):
            return expression
        else:
            return unicode(expression, errors='replace')

    def parse_requirement(self, requirement, offset):
        prev = self.f.tell()
        true_offset = offset + requirement.offset
        self.f.seek(true_offset)
        magic = get_int(self.f)
        if magic != dictionary.signatures['REQUIREMENT']:
            data = {
                'offset': true_offset,
                'magic': hex(magic),
                'expected': hex(dictionary.signatures['REQUIREMENT'])
            }
            a = Abnormality(title='BAD MAGIC - REQUIREMENT', data=data)
            self.add_abnormality(a)
            self.f.seek(prev)
            return
        # Skip size and kind
        self.f.read(8)
        requirement.expression = self.parse_expression(False)

        self.f.seek(prev)

    def parse_requirements(self, signature, offset):
        prev = self.f.tell()
        true_offset = signature.offset + offset
        self.f.seek(true_offset)
        magic = get_int(self.f)
        if magic != dictionary.signatures['REQUIREMENTS']:
            data = {
                'offset': true_offset,
                'magic': hex(magic),
                'expected': hex(dictionary.signatures['REQUIREMENTS'])
            }
            a = Abnormality(title='BAD MAGIC - REQUIREMENTS', data=data)
            self.add_abnormality(a)
            self.f.seek(prev)
            return
        # Skip size
        self.f.read(4)
        count = get_int(self.f)
        while count > 0:
            req_type = dictionary.requirements[get_int(self.f)]
            offset = get_int(self.f)
            requirement = Requirement(req_type=req_type, offset=offset)
            self.parse_requirement(requirement, true_offset)
            signature.add_requirement(requirement)
            count -= 1

        self.f.seek(prev)

    def parse_sig(self, macho):
        if not macho.has_lc('CODE_SIGNATURE'):
            return
        prev = self.f.tell()
        true_offset = (macho.offset +
                       macho.get_lc('CODE_SIGNATURE').data['offset'])
        if true_offset >= self.file.size:
            data = {
                'offset': true_offset,
                'file_size': self.file.size
            }
            a = Abnormality(title='CODE_SIGNATURE OUT OF BOUNDS', data=data)
            self.add_abnormality(a)
            return
        self.f.seek(true_offset)
        magic = get_int(self.f)
        if magic != dictionary.signatures['EMBEDDED_SIGNATURE']:
            data = {
                'offset': true_offset,
                'magic': hex(magic),
                'expected': hex(dictionary.signatures['EMBEDDED_SIGNATURE'])
            }
            a = Abnormality(title='BAD MAGIC - EMBEDDED_SIGNATURE', data=data)
            self.add_abnormality(a)
            self.f.seek(prev)
            return
        size = get_int(self.f)
        count = get_int(self.f)
        signature = Signature(offset=true_offset, size=size, count=count)
        while count > 0:
            index_type = get_int(self.f)
            try:
                index_type = dictionary.indeces[index_type]
            except:
                data = {
                    'offset': self.f.tell() - 4,
                    'index_type': index_type
                }
                a = Abnormality(title='INVALID CODE_SIGNATURE INDEX_TYPE',
                                data=data)
                self.add_abnormality(a)
            offset = get_int(self.f)
            if index_type == 'SignatureSlot':
                self.parse_certs(signature, offset)
            elif index_type == 'CodeDirectorySlot':
                self.parse_codedirectory(signature, offset)
            elif index_type == 'EntitlementSlot':
                self.parse_entitlement(signature, offset)
            elif index_type == 'RequirementsSlot':
                self.parse_requirements(signature, offset)
            count -= 1

        macho.signature = signature
        self.f.seek(prev)

    def parse_macho(self, macho):
        self.f.seek(macho.offset)
        # skip magic
        self.f.read(4)
        cputype = get_int(self.f)
        subtype = get_int(self.f)
        filetype = get_int(self.f)
        nlcs = get_int(self.f)
        slcs = get_int(self.f)
        flags = get_int(self.f)

        if macho.is_64_bit():
            # skip padding
            self.f.read(4)

        if macho.is_little():
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
                'offset': macho.offset + 4,
                'cputype': cputype
            }
            a = Abnormality(title='UNKNOWN CPUTYPE', data=data)
            self.add_abnormality(a)
        try:
            subtype = dictionary.cputypes[cputype][subtype]
        except:
            data = {
                'offset': macho.offset + 8,
                'cputype': cputype,
                'subtype': subtype
            }
            a = Abnormality(title='UNKNOWN SUBTYPE', data=data)
            self.add_abnormality(a)
        try:
            filetype = dictionary.filetypes[filetype]
        except:
            data = {
                'offset': macho.offset + 12,
                'filetype': filetype
            }
            a = Abnormality(title='UNKNOWN FILETYPE', data=data)
            self.add_abnormality(a)
        flags = self.list_macho_flags(flags)

        macho.cputype = cpu
        macho.subtype = subtype
        macho.filetype = filetype
        macho.nlcs = nlcs
        macho.slcs = slcs
        macho.flags = flags

        lc = LoadCommander(f=self.f, macho=macho, file_size=self.file.size)
        lc.parse_lcs()
        self.abnormalities += lc.abnormalities

        # Need to investigate whether the presence of a
        # symbol/string table is expected and whether the
        # abscence is indicative of shenanigans.
        if macho.has_lc('SYMTAB'):
            self.parse_syms(macho)
            self.parse_imports_and_strings(macho)

        if macho.has_lc('CODE_SIGNATURE'):
            self.parse_sig(macho)

        if not macho.is_archive():
            self.file.content = macho

    def parse_universal(self):
        self.f.seek(0)
        # skip magic
        self.f.read(4)
        nmachos = get_int(self.f)
        u = Universal(nmachos=nmachos)
        u_size = self.file.size
        for i in range(u.nmachos):
            # skip cputype, subtype
            self.f.read(8)
            offset = get_int(self.f)
            size = get_int(self.f)
            # Abnormality OUT_OF_BOUNDS check
            if offset + size > u_size:
                data = {
                    'offset': offset,
                    'size': size,
                    'file_size': u_size
                }
                a = Abnormality(title='MACH-O OUT OF BOUNDS', data=data)
                self.add_abnormality(a)
                continue
            # skip align
            self.f.read(4)
            identity = self.identify_file(offset)
            # Abnormality BAD_MAGIC check
            if identity not in dictionary.machos.values():
                data = {
                    'offset': offset,
                    'magic': identity,
                }
                a = Abnormality(title='BAD MAGIC - MACH-O')
                self.add_abnormality(a)
                continue
            u.add_macho(MachO(archive=True, offset=offset, arch=identity[0],
                             endi=identity[1], size=size))

        for i in u.gen_machos():
            self.parse_macho(i)

        self.file.content = u

    def parse_file(self):
        size = self.get_file_size()
        hashes = self.get_file_hashes()
        self.file.size = size
        self.file.hashes = hashes
        identity = self.identify_file(0)
        if identity == 'universal':
            self.parse_universal()
        else:
            self.parse_macho(MachO(archive=False, offset=0, arch=identity[0],
                                      endi=identity[1], size=self.get_file_size()))

