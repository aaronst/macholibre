#!/usr/bin/env python


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


# CPU Types, CPU Subtypes, Filetypes, Load Commands, Flags as defined in the
# following official Apple, inc. header files:
# /usr/include/mach/machine.h
# /usr/include/mach-o/loader.h

cert_slots = {
    -1: 'root',
    0: 'leaf'
}

hashes = {
    0: 'No Hash',
    1: 'SHA-1',
    2: 'SHA-256'
}

segment_flags = {
    1: 'HIGHVM',
    2: 'FVMLIB',
    4: 'NORELOC',
    8: 'PROTECTED_VERSION_1'
}

n_types = {
    0x0: 'UNDF',
    0x2: 'ABS',
    0xe: 'SECT',
    0xc: 'PBUD',
    0xa: 'INDR'
}

machos = {
    4277009102: (False, False),  # 32 bit, big endian
    4277009103: (True, False),   # 64 bit, big endian
    3472551422: (False, True),   # 32 bit, little endian
    3489328638: (True, True)     # 64 bit, little endian
}

requirements = {
    1: 'HostRequirementType',
    2: 'GuestRequirementType',
    3: 'DesignatedRequirementType',
    4: 'LibraryRequirementType',
    5: 'PluginRequirementType',
}

indeces = {
    0: 'CodeDirectorySlot',
    1: 'InfoSlot',
    2: 'RequirementsSlot',
    3: 'ResourceDirSlot',
    4: 'ApplicationSlot',
    5: 'EntitlementSlot',
    0x10000: 'SignatureSlot'
}

matches = {
    0: 'matchExists',
    1: 'matchEqual',
    2: 'matchContains',
    3: 'matchBeginsWith',
    4: 'matchEndsWith',
    5: 'matchLessThan',
    6: 'matchGreaterThan',
    7: 'matchLessEqual',
    8: 'matchGreaterEqual'
}

protections = {
    0b000: '---',
    0b001: 'r--',
    0b010: '-w-',
    0b011: 'rw-',
    0b100: '--x',
    0b101: 'r-x',
    0b110: '-wx',
    0b111: 'rwx'
}

signatures = {
    'REQUIREMENT': 0xfade0c00,
    'REQUIREMENTS': 0xfade0c01,
    'CODEDIRECTORY': 0xfade0c02,
    'ENTITLEMENT': 0xfade7171,
    'BLOBWRAPPER': 0xfade0b01,
    'EMBEDDED_SIGNATURE': 0xfade0cc0,
    'DETACHED_SIGNATURE': 0xfade0cc1,
    'CODE_SIGN_DRS': 0xfade0c05
}

section_attrs = {
    0x80000000: 'PURE_INSTRUCTIONS',
    0x40000000: 'NO_TOC',
    0x20000000: 'STRIP_STATIC_SYMS',
    0x10000000: 'NO_DEAD_STRIP',
    0x08000000: 'LIVE_SUPPORT',
    0x04000000: 'SELF_MODIFYING_CODE',
    0x02000000: 'DEBUG',
    0x00000400: 'SOME_INSTRUCTIONS',
    0x00000200: 'EXT_RELOC',
    0x00000100: 'LOC_RELOC'
}

filetypes = {
    1: 'OBJECT',
    2: 'EXECUTE',
    3: 'FVMLIB',
    4: 'CORE',
    5: 'PRELOAD',
    6: 'DYLIB',
    7: 'DYLINKER',
    8: 'BUNDLE',
    9: 'DYLIB_STUB',
    10: 'DSYM',
    11: 'KEXT_BUNDLE'
}

section_types = {
    0x0: 'REGULAR',
    0x1: 'ZEROFILL',
    0x2: 'CSTRING_LITERALS',
    0x3: '4BYTE_LITERALS',
    0x4: '8BYTE_LITERALS',
    0x5: 'LITERAL_POINTERS',
    0x6: 'NON_LAZY_SYMBOL_POINTERS',
    0x7: 'LAZY_SYMBOL_POINTERS',
    0x8: 'SYMBOL_STUBS',
    0x9: 'MOD_INIT_FUNC_POINTERS',
    0xa: 'MOD_TERM_FUNC_POINTERS',
    0xb: 'COALESCED',
    0xc: 'GB_ZEROFILL',
    0xd: 'INTERPOSING',
    0xe: '16BYTE_LITERALS',
    0xf: 'DTRACE_DOF',
    0x10: 'LAZY_DYLIB_SYMBOL_POINTERS',
    0x11: 'THREAD_LOCAL_REGULAR',
    0x12: 'THREAD_LOCAL_ZEROFILL',
    0x13: 'THREAD_LOCAL_VARIABLES',
    0x14: 'THREAD_LOCAL_VARIABLE_POINTERS',
    0x15: 'THREAD_LOCAL_INIT_FUNCTION_POINTERS'
}

operators = {
    0: 'False',
    1: 'True',
    2: 'Ident',
    3: 'AppleAnchor',
    4: 'AnchorHash',
    5: 'InfoKeyValue',
    6: 'And',
    7: 'Or',
    8: 'CDHash',
    9: 'Not',
    10: 'InfoKeyField',
    11: 'CertField',
    12: 'TrustedCert',
    13: 'TrustedCerts',
    14: 'CertGeneric',
    15: 'AppleGenericAnchor',
    16: 'EntitlementField',
    17: 'CertPolicy',
    18: 'NamedAnchor',
    19: 'NamedCode',
    20: 'Platform'
}

thread_states = {
    1: 'x86_THREAD_STATE32',
    2: 'x86_FLOAT_STATE32',
    3: 'x86_EXCEPTION_STATE32',
    4: 'x86_THREAD_STATE64',
    5: 'x86_FLOAT_STATE64',
    6: 'x86_EXCEPTION_STATE64',
    7: 'x86_THREAD_STATE',
    8: 'x86_FLOAT_STATE',
    9: 'x86_EXCEPTION_STATE',
    10: 'x86_DEBUG_STATE32',
    11: 'x86_DEBUG_STATE64',
    12: 'x86_DEBUG_STATE',
    13: 'THREAD_STATE_NONE',
    14: 'x86_SAVED_STATE_1 (INTERNAL ONLY)',
    15: 'x86_SAVED_STATE_2 (INTERNAL ONLY)',
    16: 'x86_AVX_STATE32',
    17: 'x86_AVX_STATE64',
    18: 'x86_AVX_STATE'
}

flags = {
    1: 'NOUNDEFS',
    2: 'INCRLINK',
    4: 'DYLDLINK',
    8: 'BINDATLOAD',
    16: 'PREBOUND',
    32: 'SPLIT_SEGS',
    64: 'LAZY_INIT',
    128: 'TWOLEVEL',
    256: 'FORCE_FLAT',
    512: 'NOMULTIDEFS',
    1024: 'NOFIXPREBINDING',
    2048: 'PREBINDABLE',
    4096: 'ALLMODSBOUND',
    8192: 'SUBSECTIONS_VIA_SYMBOLS',
    16384: 'CANONICAL',
    32768: 'WEAK_DEFINES',
    65536: 'BINDS_TO_WEAK',
    131072: 'ALLOW_STACK_EXECUTION',
    262144: 'ROOT_SAFE',
    524288: 'SETUID_SAFE',
    1048576: 'NOREEXPORTED_DYLIBS',
    2097152: 'PIE',
    4194304: 'DEAD_STRIPPABLE_DYLIB',
    8388608: 'HAS_TLV_DESCRIPTORS',
    16777216: 'NO_HEAP_EXECUTION',
    33554432: 'APP_EXTENSION_SAFE'
}

stabs = {
    0x20: 'GSYM',
    0x22: 'FNAME',
    0x24: 'FUN',
    0x26: 'STSYM',
    0x28: 'LCSYM',
    0x2a: 'MAIN',
    0x2e: 'BNSYM',
    0x30: 'PC',
    0x32: 'AST',
    0x3a: 'MAC_UNDEF',
    0x3c: 'OPT',
    0x40: 'RSYM',
    0x44: 'SLINE',
    0x46: 'DSLINE',
    0x48: 'BSLINE',
    0x4e: 'ENSYM',
    0x60: 'SSYM',
    0x64: 'SO',
    0x66: 'OSO',
    0x80: 'LSYM',
    0x82: 'BINCL',
    0x84: 'SOL',
    0x86: 'PARAMS',
    0x88: 'VERSION',
    0x8a: 'OLEVEL',
    0xa0: 'PSYM',
    0xa2: 'EINCL',
    0xa4: 'ENTRY',
    0xc0: 'LBRAC',
    0xc2: 'EXCL',
    0xe0: 'RBRAC',
    0xe2: 'BCOMM',
    0xe4: 'ECOMM',
    0xe8: 'ECOML',
    0xfe: 'LENG'
}

loadcommands = {
    1: 'SEGMENT',
    2: 'SYMTAB',
    3: 'SYMSEG',
    4: 'THREAD',
    5: 'UNIXTHREAD',
    6: 'LOADFVMLIB',
    7: 'IDFVMLIB',
    8: 'IDENT',
    9: 'FVMFILE',
    10: 'PREPAGE',
    11: 'DYSYMTAB',
    12: 'LOAD_DYLIB',
    13: 'ID_DYLIB',
    14: 'LOAD_DYLINKER',
    15: 'ID_DYLINKER',
    16: 'PREBOUND_DYLIB',
    17: 'ROUTINES',
    18: 'SUB_FRAMEWORK',
    19: 'SUB_UMBRELLA',
    20: 'SUB_CLIENT',
    21: 'SUB_LIBRARY',
    22: 'TWOLEVEL_HINTS',
    23: 'PREBIND_CKSUM',
    25: 'SEGMENT_64',
    26: 'ROUTINES_64',
    27: 'UUID',
    29: 'CODE_SIGNATURE',
    30: 'SEGMENT_SPLIT_INFO',
    32: 'LAZY_LOAD_DYLIB',
    33: 'ENCRYPTION_INFO',
    34: 'DYLD_INFO',
    36: 'VERSION_MIN_MACOSX',
    37: 'VERSION_MIN_IPHONEOS',
    38: 'FUNCTION_STARTS',
    39: 'DYLD_ENVIRONMENT',
    41: 'DATA_IN_CODE',
    42: 'SOURCE_VERSION',
    43: 'DYLIB_CODE_SIGN_DRS',
    44: 'ENCRYPTION_INFO_64',
    45: 'LINKER_OPTION',
    46: 'LINKER_OPTIMIZATION_HINT',
    47: 'VERSION_MIN_TVOS',
    48: 'VERSION_MIN_WATCHOS',
    49: 'NOTE',
    50: 'BUILD_VERSION',
    2147483672: 'LOAD_WEAK_DYLIB',
    2147483676: 'RPATH',
    2147483679: 'REEXPORT_DYLIB',
    2147483682: 'DYLD_INFO_ONLY',
    2147483683: 'LOAD_UPWARD_DYLIB',
    2147483688: 'MAIN',
}

# CPU Types & Subtypes as defined in
# http://opensource.apple.com/source/cctools/cctools-822/include/mach/machine.h
cputypes = {
    -1: {
        -2: 'ANY',
        -1: 'MULTIPLE',
        0: 'LITTLE_ENDIAN',
        1: 'BIG_ENDIAN'
    },
    1: {
        -2: 'VAX',
        -1: 'MULTIPLE',
        0: 'VAX_ALL',
        1: 'VAX780',
        2: 'VAX785',
        3: 'VAX750',
        4: 'VAX730',
        5: 'UVAXI',
        6: 'UVAXII',
        7: 'VAX8200',
        8: 'VAX8500',
        9: 'VAX8600',
        10: 'VAX8650',
        11: 'VAX8800',
        12: 'UVAXIII'
    },
    6: {
        -2: 'MC680x0',
        -1: 'MULTIPLE',
        1: 'MC680x0_ALL or MC68030',
        2: 'MC68040',
        3: 'MC68030_ONLY'
    },
    7: {-2: 'X86 (I386)',
        -1: 'MULITPLE',
        0: 'INTEL_MODEL_ALL',
        3: 'X86_ALL, X86_64_ALL, I386_ALL, or 386',
        4: 'X86_ARCH1 or 486',
        5: '586 or PENT',
        8: 'X86_64_H or PENTIUM_3',
        9: 'PENTIUM_M',
        10: 'PENTIUM_4',
        11: 'ITANIUM',
        12: 'XEON',
        15: 'INTEL_FAMILY_MAX',
        22: 'PENTPRO',
        24: 'PENTIUM_3_M',
        26: 'PENTIUM_4_M',
        27: 'ITANIUM_2',
        28: 'XEON_MP',
        40: 'PENTIUM_3_XEON',
        54: 'PENTII_M3',
        86: 'PENTII_M5',
        103: 'CELERON',
        119: 'CELERON_MOBILE',
        132: '486SX'
    },
    10: {
        -2: 'MC98000',
        -1: 'MULTIPLE',
        0: 'MC98000_ALL',
        1: 'MC98601'
    },
    11: {
        -2: 'HPPA',
        -1: 'MULITPLE',
        0: 'HPPA_ALL or HPPA_7100',
        1: 'HPPA_7100LC'
    },
    12: {
        -2: 'ARM',
        -1: 'MULTIPLE',
        0: 'ARM_ALL',
        1: 'ARM_A500_ARCH',
        2: 'ARM_A500',
        3: 'ARM_A440',
        4: 'ARM_M4',
        5: 'ARM_V4T',
        6: 'ARM_V6',
        7: 'ARM_V5TEJ',
        8: 'ARM_XSCALE',
        9: 'ARM_V7',
        10: 'ARM_V7F',
        11: 'ARM_V7S',
        12: 'ARM_V7K',
        13: 'ARM_V8',
        14: 'ARM_V6M',
        15: 'ARM_V7M',
        16: 'ARM_V7EM'
    },
    13: {
        -2: 'MC88000',
        -1: 'MULTIPLE',
        0: 'MC88000_ALL',
        1: 'MMAX_JPC or MC88100',
        2: 'MC88110'
    },
    14: {
        -2: 'SPARC',
        -1: 'MULTIPLE',
        0: 'SPARC_ALL or SUN4_ALL',
        1: 'SUN4_260',
        2: 'SUN4_110'
    },
    15: {
        -2: 'I860 (big-endian)',
        -1: 'MULTIPLE',
        0: 'I860_ALL',
        1: 'I860_860'
    },
    18: {
        -2: 'POWERPC',
        -1: 'MULTIPLE',
        0: 'POWERPC_ALL',
        1: 'POWERPC_601',
        2: 'POWERPC_602',
        3: 'POWERPC_603',
        4: 'POWERPC_603e',
        5: 'POWERPC_603ev',
        6: 'POWERPC_604',
        7: 'POWERPC_604e',
        8: 'POWERPC_620',
        9: 'POWERPC_750',
        10: 'POWERPC_7400',
        11: 'POWERPC_7450',
        100: 'POWERPC_970'
    },
    16777223: {
        -2: 'X86_64',
        -1: 'MULTIPLE',
        0: 'INTEL_MODEL_ALL',
        3: 'X86_ALL, X86_64_ALL, I386_ALL, or 386',
        4: 'X86_ARCH1 or 486',
        5: '586 or PENT',
        8: 'X86_64_H or PENTIUM_3',
        9: 'PENTIUM_M',
        10: 'PENTIUM_4',
        11: 'ITANIUM',
        12: 'XEON',
        15: 'INTEL_FAMILY_MAX',
        22: 'PENTPRO',
        24: 'PENTIUM_3_M',
        26: 'PENTIUM_4_M',
        27: 'ITANIUM_2',
        28: 'XEON_MP',
        40: 'PENTIUM_3_XEON',
        54: 'PENTII_M3',
        86: 'PENTII_M5',
        103: 'CELERON',
        119: 'CELERON_MOBILE',
        132: '486SX',
        2147483648 + 0: 'INTEL_MODEL_ALL',
        2147483648 + 3: 'X86_ALL, X86_64_ALL, I386_ALL, or 386',
        2147483648 + 4: 'X86_ARCH1 or 486',
        2147483648 + 5: '586 or PENT',
        2147483648 + 8: 'X86_64_H or PENTIUM_3',
        2147483648 + 9: 'PENTIUM_M',
        2147483648 + 10: 'PENTIUM_4',
        2147483648 + 11: 'ITANIUM',
        2147483648 + 12: 'XEON',
        2147483648 + 15: 'INTEL_FAMILY_MAX',
        2147483648 + 22: 'PENTPRO',
        2147483648 + 24: 'PENTIUM_3_M',
        2147483648 + 26: 'PENTIUM_4_M',
        2147483648 + 27: 'ITANIUM_2',
        2147483648 + 28: 'XEON_MP',
        2147483648 + 40: 'PENTIUM_3_XEON',
        2147483648 + 54: 'PENTII_M3',
        2147483648 + 86: 'PENTII_M5',
        2147483648 + 103: 'CELERON',
        2147483648 + 119: 'CELERON_MOBILE',
        2147483648 + 132: '486SX'
    },
    16777228: {
        -2: 'ARM64',
        -1: 'MULTIPLE',
        0: 'ARM64_ALL',
        1: 'ARM64_V8',
        2147483648 + 0: 'ARM64_ALL',
        2147483648 + 1: 'ARM64_V8'
    },
    16777234: {
        -2: 'POWERPC64',
        -1: 'MULTIPLE',
        0: 'POWERPC_ALL',
        1: 'POWERPC_601',
        2: 'POWERPC_602',
        3: 'POWERPC_603',
        4: 'POWERPC_603e',
        5: 'POWERPC_603ev',
        6: 'POWERPC_604',
        7: 'POWERPC_604e',
        8: 'POWERPC_620',
        9: 'POWERPC_750',
        10: 'POWERPC_7400',
        11: 'POWERPC_7450',
        100: 'POWERPC_970',
        2147483648 + 0: 'POWERPC_ALL (LIB64)',
        2147483648 + 1: 'POWERPC_601 (LIB64)',
        2147483648 + 2: 'POWERPC_602 (LIB64)',
        2147483648 + 3: 'POWERPC_603 (LIB64)',
        2147483648 + 4: 'POWERPC_603e (LIB64)',
        2147483648 + 5: 'POWERPC_603ev (LIB64)',
        2147483648 + 6: 'POWERPC_604 (LIB64)',
        2147483648 + 7: 'POWERPC_604e (LIB64)',
        2147483648 + 8: 'POWERPC_620 (LIB64)',
        2147483648 + 9: 'POWERPC_750 (LIB64)',
        2147483648 + 10: 'POWERPC_7400 (LIB64)',
        2147483648 + 11: 'POWERPC_7450 (LIB64)',
        2147483648 + 100: 'POWERPC_970 (LIB64)'
    }
}
