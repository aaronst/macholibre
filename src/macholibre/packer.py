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


from json import dump


class Packer(object):

    # Constructor
    def __init__(self, analyzer=None):
        self.analyzer = analyzer

    # Functions
    def pack_sect(self, sect):
        s = {}
        s['name'] = sect.name
        s['segname'] = sect.segname
        s['addr'] = sect.addr
        s['offset'] = sect.offset
        s['align'] = sect.align
        s['reloff'] = sect.reloff
        s['nreloc'] = sect.nreloc
        s['size'] = sect.size
        s['type'] = sect.type
        s['attributes'] = []
        for i in sect.gen_attrs():
            s['attributes'].append(i)

        return s

    def pack_symbol(self, symbol):
        s = {}
        s['index'] = symbol.index
        if symbol.is_stab():
            s['stab'] = symbol.stab
        else:
            s['pext'] = symbol.pext
            s['type'] = symbol.type
            s['ext'] = symbol.ext
            s['dylib'] = symbol.dylib
            s['ref'] = symbol.ref
        s['sect'] = symbol.sect
        s['value'] = symbol.value

        return s

    def pack_segment(self, segment):
        s = {}
        s['cmd'] = segment.cmd
        s['size'] = segment.size
        s['name'] = segment.name
        s['vmaddr'] = segment.vmaddr
        s['vmsize'] = segment.vmsize
        s['offset'] = segment.offset
        s['segsize'] = segment.segsize
        s['maxprot'] = segment.maxprot
        s['initprot'] = segment.initprot
        s['nsects'] = segment.nsects
        s['sects'] = []
        for i in segment.gen_sects():
            s['sects'].append(self.pack_sect(i))
        s['flags'] = []
        for i in segment.gen_flags():
            s['flags'].append(i)

        return s

    def pack_lc(self, lc):
        if lc.is_segment():
            l = self.pack_segment(lc)
        else:
            l = {}
            l['cmd'] = lc.cmd
            l['size'] = lc.size
            for i in lc.data.iteritems():
                l[i[0]] = i[1]

        return l

    def pack_symtab(self, symtab):
        s = {}
        s['offset'] = symtab.offset
        s['nsyms'] = symtab.nsyms
        if symtab.il is not None:
            s['ilocal'] = symtab.il
        if symtab.nl is not None:
            s['nlocal'] = symtab.nl
        if symtab.ie is not None:
            s['iexternal'] = symtab.ie
        if symtab.ne is not None:
            s['nexternal'] = symtab.ne
        if symtab.iu is not None:
            s['iundefined'] = symtab.iu
        if symtab.nu is not None:
            s['nundefined'] = symtab.nu
        s['syms'] = []
        for i in symtab.gen_syms():
            s['syms'].append(self.pack_symbol(i))

        return s

    def pack_strtab(self, strtab):
        s = {}
        s['offset'] = strtab.offset
        s['size'] = strtab.size
        s['strings'] = strtab.strings

        return s

    def pack_import(self, imp):
        return (imp.func, imp.dylib)

    def pack_codedirectory(self, cd):
        c = {}
        c['version'] = cd.version
        c['flags'] = cd.flags
        c['hash_offset'] = cd.hash_offset
        if cd.ident_offset is not None:
            c['ident_offset'] = cd.ident_offset
        c['n_special_slots'] = cd.n_special_slots
        c['n_code_slots'] = cd.n_code_slots
        c['code_limit'] = cd.code_limit
        c['hash_size'] = cd.hash_size
        c['hash_type'] = cd.hash_type
        if cd.platform is not None:
            c['platform'] = cd.platform
        c['page_size'] = cd.page_size
        if cd.scatter_offset is not None:
            c['scatter_offset'] = cd.scatter_offset
        if cd.team_id is not None:
            c['team_id_offset'] = cd.team_id_offset
            c['team_id'] = cd.team_id
        c['identity'] = cd.identity
        c['hashes'] = []
        for i in cd.gen_hashes():
            c['hashes'].append(i)

        return c

    def pack_entitlement(self, entitlement):
        e = {}
        e['size'] = entitlement.size
        e['plist'] = entitlement.plist

        return e

    def pack_requirement(self, req):
        r = {}
        r['type'] = req.type
        r['offset'] = req.offset
        r['expression'] = req.expression

        return r

    def pack_cert(self, cert):
        c = {}
        c['serial'] = cert.serial
        c['subject'] = cert.subject
        c['issuer'] = cert.issuer
        c['ca'] = cert.is_ca()

        return c

    def pack_signature(self, sig):
        s = {}
        s['offset'] = sig.offset
        s['size'] = sig.size
        s['count'] = sig.count
        s['codedirectory'] = self.pack_codedirectory(sig.codedirectory)
        s['entitlements'] = []
        for i in sig.gen_entitlements():
            s['entitlements'].append(self.pack_entitlement(i))
        s['requirements'] = []
        for i in sig.gen_requirements():
            s['requirements'].append(self.pack_requirement(i))
        s['certs'] = []
        for i in sig.gen_certs():
            s['certs'].append(self.pack_cert(i))

        return s

    def pack_macho(self, macho):
        m = {}
        m['offset'] = macho.offset
        m['size'] = macho.size
        m['cputype'] = macho.cputype
        m['subtype'] = macho.subtype
        m['filetype'] = macho.filetype
        m['nlcs'] = macho.nlcs
        m['slcs'] = macho.slcs
        m['flags'] = macho.flags
        m['lcs'] = []
        for i in macho.gen_lcs():
            m['lcs'].append(self.pack_lc(i))
        m['dylibs'] = macho.dylibs
        if macho.symtab is not None:
            m['symtab'] = self.pack_symtab(macho.symtab)
        if macho.strtab is not None:
            m['strtab'] = self.pack_strtab(macho.strtab)
        m['imports'] = []
        for i in macho.gen_imports():
            m['imports'].append(self.pack_import(i))
        if macho.signature is not None:
            m['signature'] = self.pack_signature(macho.signature)
        if macho.minos is not None:
            m['minos'] = macho.minos.version
        m['analytics'] = macho.analytics

        return m

    def pack_universal(self, universal):
        u = {}
        u['nmachos'] = universal.nmachos
        u['machos'] = []
        for i in universal.gen_machos():
            u['machos'].append(self.pack_macho(i))

        return u

    def pack_abnormality(self, abnormality):
        a = {}
        a['title'] = abnormality.title
        a['data'] = abnormality.data

        return a

    def pack(self, f=None):
        file = {}
        file['name'] = self.analyzer.parser.file.name
        file['size'] = self.analyzer.parser.file.size
        file['hashes'] = self.analyzer.parser.file.hashes
        if self.analyzer.parser.file.is_universal():
            u = self.analyzer.parser.file.content
            file['universal'] = self.pack_universal(u)
        else:
            m = self.analyzer.parser.file.content
            file['macho'] = self.pack_macho(m)

        file['abnormalities'] = []
        for i in self.analyzer.parser.abnormalities:
            file['abnormalities'].append(self.pack_abnormality(i))

        if f is None:
            return file
        else:
            dump(file, f, encoding='utf-8', ensure_ascii=False)

