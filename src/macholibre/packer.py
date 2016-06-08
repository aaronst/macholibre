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
        self._analyzer = analyzer

    # Getters
    def getAnalyzer(self): return self._analyzer

    # Setters
    def setAnalyzer(self, analyzer): self._analyzer = analyzer

    # Functions
    def packSect(self, sect):
        s = {}
        s['name'] = sect.getName()
        s['segname'] = sect.getSegName()
        s['addr'] = sect.getAddr()
        s['offset'] = sect.getOffset()
        s['align'] = sect.getAlign()
        s['reloff'] = sect.getRelOff()
        s['nreloc'] = sect.getNReloc()
        s['size'] = sect.getSize()
        s['type'] = sect.getType()
        s['attributes'] = []
        for i in sect.genAttrs():
            s['attributes'].append(i)

        return s

    def packSymbol(self, symbol):
        s = {}
        s['index'] = symbol.getIndex()
        if symbol.isStab():
            s['stab'] = symbol.getStab()
        else:
            s['pext'] = symbol.getPext()
            s['type'] = symbol.getType()
            s['ext'] = symbol.getExt()
            s['dylib'] = symbol.getDylib()
            s['ref'] = symbol.getRef()
        s['sect'] = symbol.getSect()
        s['value'] = symbol.getValue()

        return s

    def packSegment(self, segment):
        s = {}
        s['cmd'] = segment.getCmd()
        s['size'] = segment.getSize()
        s['name'] = segment.getName()
        s['vmaddr'] = segment.getVMAddr()
        s['vmsize'] = segment.getVMSize()
        s['offset'] = segment.getOffset()
        s['segsize'] = segment.getSegSize()
        s['maxprot'] = segment.getMaxProt()
        s['initprot'] = segment.getInitProt()
        s['nsects'] = segment.getNSects()
        s['sects'] = []
        for i in segment.genSects():
            s['sects'].append(self.packSect(i))
        s['flags'] = []
        for i in segment.genFlags():
            s['flags'].append(i)

        return s

    def packLC(self, lc):
        if lc.isSegment():
            l = self.packSegment(lc)
        else:
            l = {}
            l['cmd'] = lc.getCmd()
            l['size'] = lc.getSize()
            for i in lc.getData().iteritems():
                l[i[0]] = i[1]

        return l

    def packSymTab(self, symtab):
        s = {}
        s['offset'] = symtab.getOffset()
        s['nsyms'] = symtab.getNSyms()
        if symtab.getIL() is not None:
            s['ilocal'] = symtab.getIL()
        if symtab.getNL() is not None:
            s['nlocal'] = symtab.getNL()
        if symtab.getIE() is not None:
            s['iexternal'] = symtab.getIE()
        if symtab.getNE() is not None:
            s['nexternal'] = symtab.getNE()
        if symtab.getIU() is not None:
            s['iundefined'] = symtab.getIU()
        if symtab.getNU() is not None:
            s['nundefined'] = symtab.getNU()
        s['syms'] = []
        for i in symtab.genSyms():
            s['syms'].append(self.packSymbol(i))

        return s

    def packStrTab(self, strtab):
        s = {}
        s['offset'] = strtab.getOffset()
        s['size'] = strtab.getSize()
        s['strings'] = strtab.getStrings()

        return s

    def packImport(self, imp):
        return (imp.getFunc(), imp.getDylib())

    def packCodeDirectory(self, cd):
        c = {}
        c['version'] = cd.getVersion()
        c['flags'] = cd.getFlags()
        c['hash_offset'] = cd.getHashOffset()
        if cd.getIdentOffset() is not None:
            c['ident_offset'] = cd.getIdentOffset()
        c['n_special_slots'] = cd.getNSpecialSlots()
        c['n_code_slots'] = cd.getNCodeSlots()
        c['code_limit'] = cd.getCodeLimit()
        c['hash_size'] = cd.getHashSize()
        c['hash_type'] = cd.getHashType()
        if cd.getPlatform() is not None:
            c['platform'] = cd.getPlatform()
        c['page_size'] = cd.getPageSize()
        if cd.getScatterOffset() is not None:
            c['scatter_offset'] = cd.getScatterOffset()
        if cd.getTeamID() is not None:
            c['team_id_offset'] = cd.getTeamIDOffset()
            c['team_id'] = cd.getTeamID()
        c['identity'] = cd.getIdentity()
        c['hashes'] = []
        for i in cd.genHashes():
            c['hashes'].append(i)

        return c

    def packEntitlement(self, entitlement):
        e = {}
        e['size'] = entitlement.getSize()
        e['plist'] = entitlement.getPlist()

        return e

    def packRequirement(self, req):
        r = {}
        r['type'] = req.getType()
        r['offset'] = req.getOffset()
        r['expression'] = req.getExpression()

        return r

    def packCert(self, cert):
        c = {}
        c['serial'] = cert.getSerial()
        c['subject'] = cert.getSubject()
        c['issuer'] = cert.getIssuer()
        c['ca'] = cert.isCA()

        return c

    def packSignature(self, sig):
        s = {}
        s['offset'] = sig.getOffset()
        s['size'] = sig.getSize()
        s['count'] = sig.getCount()
        s['codedirectory'] = self.packCodeDirectory(sig.getCodeDirectory())
        s['entitlements'] = []
        for i in sig.genEntitlements():
            s['entitlements'].append(self.packEntitlement(i))
        s['requirements'] = []
        for i in sig.genRequirements():
            s['requirements'].append(self.packRequirement(i))
        s['certs'] = []
        for i in sig.genCerts():
            s['certs'].append(self.packCert(i))

        return s

    def packMachO(self, macho):
        m = {}
        m['offset'] = macho.getOffset()
        m['size'] = macho.getSize()
        m['cputype'] = macho.getCPUType()
        m['subtype'] = macho.getSubType()
        m['filetype'] = macho.getFileType()
        m['nlcs'] = macho.getNLCs()
        m['slcs'] = macho.getSLCs()
        m['flags'] = macho.getFlags()
        m['lcs'] = []
        for i in macho.genLCs():
            m['lcs'].append(self.packLC(i))
        m['dylibs'] = macho.getDylibs()
        if macho.getSymTab() is not None:
            m['symtab'] = self.packSymTab(macho.getSymTab())
        if macho.getStrTab() is not None:
            m['strtab'] = self.packStrTab(macho.getStrTab())
        m['imports'] = []
        for i in macho.genImports():
            m['imports'].append(self.packImport(i))
        if macho.getSignature() is not None:
            m['signature'] = self.packSignature(macho.getSignature())
        if macho.getMinOS() is not None:
            m['minos'] = macho.getMinOS().getVersion()
        m['analytics'] = macho.getAnalytics()

        return m

    def packUniversal(self, universal):
        u = {}
        u['nmachos'] = universal.getNMachOs()
        u['machos'] = []
        for i in universal.genMachOs():
            u['machos'].append(self.packMachO(i))

        return u

    def packAbnormality(self, abnormality):
        a = {}
        a['title'] = abnormality.getTitle()
        a['data'] = abnormality.getData()

        return a

    def pack(self, f=None):
        file = {}
        file['name'] = self._analyzer.getParser().getFile().getName()
        file['size'] = self._analyzer.getParser().getFile().getSize()
        file['hashes'] = self._analyzer.getParser().getFile().getHashes()
        if self._analyzer.getParser().getFile().isUniversal():
            u = self._analyzer.getParser().getFile().getContent()
            file['universal'] = self.packUniversal(u)
        else:
            m = self._analyzer.getParser().getFile().getContent()
            file['macho'] = self.packMachO(m)

        file['abnormalities'] = []
        for i in self._analyzer.getParser().getAbnormalities():
            file['abnormalities'].append(self.packAbnormality(i))

        if f is None:
            return file
        else:
            dump(file, f, encoding='utf-8', ensure_ascii=False)
