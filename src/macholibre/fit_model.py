import sys
import pandas as pd

from analyzer import Analyzer
from packer import Packer
from parser import Parser
from sklearn.externals import joblib
from glob import glob


filetypes = [
    'OBJECT',
    'EXECUTE',
    'BUNDLE',
    'DYLIB',
    'PRELOAD',
    'CORE',
    'DYLINKER'
]

header_flags = [
    'NOUNDEFS',
    'INCRLINK',
    'DYLDLINK',
    'BINDATLOAD',
    'PREBOUND',
    'SPLIT_SEGS',
    'TWOLEVEL',
    'FORCE_FLAT',
    'SUBSECTIONS_VIA_SYMBOLS'
]

# Load commands that were present in > ~25% of samples from either set.
load_commands = [
    'LOAD_DYLIB',
    'SYMTAB',
    'DYSYMTAB',
    'UUID',
    'FUNCTION_STARTS',
    'DATA_IN_CODE',
    'VERSION_MIN_MACOSX',
    'LOAD_DYLINKER',
    'CODE_SIGNATURE',
    'DLYD_INFO_ONLY',
    'SEGMENT (__LINKEDIT)',
    'SEGMENT (__DATA)',
    'UNIXTHREAD',
    'SEGMENT (__TEXT)',
    'SEGMENT_64 (__LINKEDIT)',
    'SEGMENT_64 (__DATA)',
    'SEGMENT_64 (__TEXT)',
    'SEGMENT_64 (/usr/lib/dyld)',
    'SEGMENT (__OBJC)',
    'ID_DYLIB',
    'SEGMENT (/usr/lib/dyld)',
    'SEGMENT (__IMPORT)',
    'SEGMENT (__PAGEZERO)',
    'SEGMENT_64 (__PAGEZERO)'
]

# Sections that were present in > ~25% of samples from either set.
sections = [
    '__TEXT, __text',
    '__TEXT, __cstring',
    '__DATA, __data',
    '__DATA, __cfstring',
    '__TEXT, __stub_helper',
    '__DATA, __la_symbol_ptr',
    '__TEXT, __unwind_info',
    '__TEXT, __const',
    '__DATA, __nl_symbol_ptr',
    '__DATA, __bss',
    '__DATA, __const',
    '__DATA, __common',
    '__DATA, __dyld',
    '__TEXT, __eh_frame',
    '__DATA, __objc_imageinfo',
    '__DATA, __objc_classrefs',
    '__DATA, __objc_selrefs',
    '__DATA, __objc_const',
    '__TEXT, __objc_classname',
    '__TEXT, __objc_methname',
    '__TEXT, __gcc_except_tab',
    '__TEXT, __objc_methtype',
    '__DATA, __objc_protolist',
    '__DATA, __objc_data',
    '__DATA, __got',
    '__TEXT, __stubs',
    '__OBJC, __module_info',
    '__OBJC, __message_refs',
    '__OBJC, __cls_refs',
    '__OBJC, __image_info',
    '__OBJC, __symbols',
    '__OBJC, __meta_class',
    '__OBJC, __class',
    '__OBJC, __inst_meth',
    '__IMPORT, __jump_table',
    '__OBJC, __instance_vars',
    '__IMPORT, __pointers'
]

# Imported symbols that were present in > ~25% of samples from either set.
imports = [
    '___CFConstantStringClassReference',
    '___stack_chk_guard',
    '_objc_msgSend',
    '___stack_chk_fail',
    '_free',
    '_malloc',
    '_strlen',
    '_CFRelease',
    'dyld_stub_binder',
    '_exit',
    '_memcpy',
    '_strcmp',
    '_kCFAllocationDefault',
    '_objc_enumerationMutation',
    '_NSLog',
    '_calloc',
    '_memcmp',
    '_NSApp',
    '_OBJC_CLASS_$_NSString',
    '_strncmp',
    '_objc_msgSend_stret',
    '__objc_empty_cache',
    '_OBJC_CLASS_$_NSObject',
    '_pthread_mutex_lock',
    '_pthread_mutex_unlock',
    '_Unwind_Resume',
    '___error',
    '_memset',
    '_fprintf',
    '.objc_class_name_NSString',
    '_memmove',
    '___gxx_personality_v0',
    '_objc_msgSendSuper',
    '_strcpy',
]

dylibs = [
    '/usr/lib/libSystem.B.dylib',
    '/usr/lib/libobjc.A.dylib',
    '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation',
    '/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation',
    '/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit',
    '/usr/lib/libgcc_s.1.dylib',
    '/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa',
    '/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices',
    '/System/Library/Frameworks/Security.framework/Versions/A/Security',
    '/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit',
    '/System/Library/Frameworks/WebKit.framework/Versions/A/WebKit',
    '/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices',
    '/usr/lib/libstdc++.6.dylib',
    '/System/Library/Frameworks/QuartzCore.framework/Versions/A/QuartzCore',
    '/System/Library/Frameworks/Carbon.framework/Versions/A/Carbon',
    '/usr/lib/libz.1.dylib',
    '@loader_path/../Frameworks/Sparkle.framework/Versions/A/Sparkle',
    '/usr/lib/libc++.1.dylib',
    '/usr/lib/libsqlite3.dylib'
]

dylib_counts = [
    '/usr/lib/libSystem.B.dylib',
    '/usr/lib/libobjc.A.dylib',
    '/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit',
    '/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation',
    '/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation',
    '@executable_path/rbframework.dylib',
    '/usr/lib/libstdc++.6.dylib',
    '/usr/lib/libc++.1.dylib',
    '/System/Library/Frameworks/Carbon.framework/Versions/A/Carbon',
    '/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices',
    '/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices',
    '/usr/lib/libgcc_s.1.dylib',
    'SELF_LIBRARY',
    '/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa',
    '/System/Library/Frameworks/Foundation.framework/Foundation',
    '/System/Library/Frameworks/Security.framework/Security',
    '/System/Library/Frameworks/UIKit.framework/UIKit',
    'System/Library/Frameworks/Security.framework/Versions/A/Security',
    '/usr/lib/libsqlite3.dylib',
    '/usr/lib/libxml2.2.dylib',
    '/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit',
    '/usr/lib/libz.1.dylib',
    '/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics',
    '@executable_path/../Frameworks/QtGui.framework/Versions/4/QtGui',
    '@rpath/SharedUtils.dylib',
    '/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration',
    '/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices',
    '/System/Library/Frameworks/CoreLocation.framework/CoreLocation',
    '/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration',
    '/System/Library/Frameworks/QuickTime.framework/Versions/A/QuickTime',
    '/System/Library/Frameworks/AVFoundation.framework/AVFoundation',
    '/usr/lib/libbz2.1.0.dylib',
    '/System/Library/Frameworks/QuartzCore.framework/QuartzCore',
    '/System/Library/Frameworks/OpenGL.framework/Versions/A/OpenGL',
    '@executable_path/../Frameworks/QtNetwork.framework/Versions/4/QtNetwork',
    '/usr/lib/libsasl2.2.dylib',
    '/usr/lib/libcrypto.0.9.8.dylib',
    '/usr/lib/libiconv.2.dylib',
    '@executable_path/../Frameworks/QtCore.framework/Versions/4/QtCore',
    '/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony',
    '/System/Library/Frameworks/CoreData.framework/CoreData',
    '/System/Library/Frameworks/ImageIO.framework/ImageIO',
    '/System/Library/Frameworks/OpenGLES.framework/OpenGLES'
]

features = tuple(
    ['alignment',
     'm_size',
     's_size',
     'nsyms',
     'nlcs',
     'slcs',
     'sig_size',
     'ndylibs',
     'nimports',
     'entropy',
     'nstrings'] +
    filetypes +
    header_flags +
    load_commands +
    sections +
    imports +
    #dylibs +
    dylib_counts)

def build_row(r):
    out = []
    for f in features:
        if f in r:
            out.append(r[f])
        else:
            out.append(0)
    return out


def build_dataframe(good, bad):
    df = pd.DataFrame(columns = features)
    current = 0
    row = {}
    symbol = False
    cmd = None
    segment_name = None
    section_name = None

    print 'Parsing good json'
    for prefix, event, value in ijson.parse(good):
        if prefix.endswith('.macho') or prefix.endswith('.machos.item'):
            if len(row) > 0:
                row['alignment'] = 'good'
                df.loc[current] = build_row(row)
                current += 1
                row = {}
        elif prefix.endswith('.macho.size') or prefix.endswith('.machos.item.size'):
            row['m_size'] = value / 1024.0
        elif prefix.endswith('.strtab.size'):
            row['s_size'] = value / 1024.0
        elif prefix.endswith('.slcs'):
            row['slcs'] = value / 1024.0
        elif prefix.endswith('.signature.size'):
            row['sig_size'] = value / 1024.0
        elif prefix.endswith('.symtab.nsyms'):
            row['nsyms'] = value
        elif prefix.endswith('.nlcs'):
            row['nlcs'] = value
        elif prefix.endswith('.ndylibs'):
            row['ndylibs'] = value
        elif prefix.endswith('.nimps'):
            row['nimports'] = value
        elif prefix.endswith('.entropy'):
            row['entropy'] = value
        elif prefix.endswith('.strtab.strings'):
            row['nstrings'] = 0
        elif prefix.endswith('.strtab.strings.item'):
            row['nstrings'] += 1
        elif prefix.endswith('.macho.flags.item') or prefix.endswith('.machos.item.flags.item'):
            row[value] = 10
        elif prefix.endswith('.filetype'):
            row[value] = 10
        elif prefix.endswith('.lcs.item.cmd'):
            if value == 'SEGMENT' or 'SEGMENT_64':
                if segment_name is None:
                    cmd = value
                else:
                    lc = value + ' (' + segment_name + ')'
                    if lc in load_commands:
                        row[lc] = 10
                    segment_name = None
            else:
                if value in load_commands:
                    row[value] = 10
        elif prefix.endswith('.lcs.item.name'):
            if cmd is None:
                segment_name = value
            else:
                lc = cmd + ' (' + value + ')'
                if lc in load_commands:
                    row[lc] = 10
                cmd = None
        elif prefix.endswith('.sects.item.segname'):
            if section_name is None:
                segment_name = value
            else:
                s = value + ', ' + section_name
                if s in sections:
                    row[s] = 10
                section_name = None
        elif prefix.endswith('.sects.item.name'):
            if segment_name is None:
                section_name = value
            else:
                s = segment_name + ', ' + value
                if s in sections:
                    row[s] = 10
                segment_name = None
        elif prefix.endswith('.imports.item'):
            symbol = True
        elif prefix.endswith('.imports.item.item') and symbol:
            if value in imports:
                row[value] = 10
            symbol = False
        elif prefix.endswith('.imports.item.item') and not symbol:
            if value in dylib_counts:
                if value in row:
                    row[value] += 1
                else:
                    row[value] = 1
        #elif prefix.endswith('.dylibs.item'):
        #    if value in dylibs:
        #        row[value] = 10

    print 'Parsing bad json'
    for prefix, event, value in ijson.parse(bad):
        if prefix.endswith('.macho') or prefix.endswith('.machos.item'):
            if len(row) > 0:
                row['alignment'] = 'bad'
                df.loc[current] = build_row(row)
                current += 1
                row = {}
        elif prefix.endswith('.macho.size') or prefix.endswith('.machos.item.size'):
            row['m_size'] = value / 1024.0
        elif prefix.endswith('.strtab.size'):
            row['s_size'] = value / 1024.0
        elif prefix.endswith('.slcs'):
            row['slcs'] = value / 1024.0
        elif prefix.endswith('.signature.size'):
            row['sig_size'] = value / 1024.0
        elif prefix.endswith('.symtab.nsyms'):
            row['nsyms'] = value
        elif prefix.endswith('.nlcs'):
            row['nlcs'] = value
        elif prefix.endswith('.ndylibs'):
            row['ndylibs'] = value
        elif prefix.endswith('.nimps'):
            row['nimports'] = value
        elif prefix.endswith('.entropy'):
            row['entropy'] = value
        elif prefix.endswith('.strtab.strings'):
            row['nstrings'] = 0
        elif prefix.endswith('.strtab.strings.item'):
            row['nstrings'] += 1
        elif prefix.endswith('.macho.flags.item') or prefix.endswith('.machos.item.flags.item'):
            row[value] = 10
        elif prefix.endswith('.filetype'):
            row[value] = 10
        elif prefix.endswith('.lcs.item.cmd'):
            if value == 'SEGMENT' or 'SEGMENT_64':
                if segment_name is None:
                    cmd = value
                else:
                    lc = value + ' (' + segment_name + ')'
                    if lc in load_commands:
                        row[lc] = 10
                    segment_name = None
            else:
                if value in load_commands:
                    row[value] = 10
        elif prefix.endswith('.lcs.item.name'):
            if cmd is None:
                segment_name = value
            else:
                lc = cmd + ' (' + value + ')'
                if lc in load_commands:
                    row[lc] = 10
                cmd = None
        elif prefix.endswith('.sects.item.segname'):
            if section_name is None:
                segment_name = value
            else:
                s = value + ', ' + section_name
                if s in sections:
                    row[s] = 10
                section_name = None
        elif prefix.endswith('.sects.item.name'):
            if segment_name is None:
                section_name = value
            else:
                s = segment_name + ', ' + value
                if s in sections:
                    row[s] = 10
                segment_name = None
        elif prefix.endswith('.imports.item'):
            symbol = True
        elif prefix.endswith('.imports.item.item') and symbol:
            if value in imports:
                row[value] = 10
            symbol = False
        elif prefix.endswith('.imports.item.item') and not symbol:
            if value in dylib_counts:
                if value in row:
                    row[value] += 1
                else:
                    row[value] = 1
        #elif prefix.endswith('.dylibs.item'):
        #    if value in dylibs:
        #        row[value] = 10

    return df


def split_data(df):
    x = []
    y = []
    for index, row in df.iterrows():
        data = []
        for f in features:
            if f != 'alignment':
                data.append(row[f])
        x.append(data)
        y.append(row['alignment'])

    x = numpy.array(x)
    y = numpy.array(y)
    numpy.save('data_x.npy', x)
    numpy.save('data_y.npy', y)
    return x, y



model = joblib.load('model.pkl')

