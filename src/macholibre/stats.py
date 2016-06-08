#!/usr/bin/python

# MachoLibre
# Universal & Mach-O Binary Parser
# aaron@icebrg.io
# July 2015

import sys
import pandas as pd
import seaborn as sns
import ijson.backends.yajl2_cffi as ijson

from collections import Counter


def gen_imports_data(json):
    imports = Counter()
    total = 0
    function = False
    # execute = None
    # temp_imports = []
    for prefix, event, value in ijson.parse(json):
        #if prefix.endswith('.macho') or prefix.endswith('.machos.item'):
        #    if execute:
        #        for t in set(temp_imports):
        #            imports[t] += 1
        #        del temp_imports[:]
        #    execute = None
        if prefix.endswith('.filetype'):
            #if value == 'EXECUTE':
            #    execute = True
            total += 1
            #else:
            #    execute = False
        if prefix.endswith('.imports.item'):
            function = True
        if prefix.endswith('.imports.item.item') and function:
            #if execute or execute is None:
            #    temp_imports.append(value)
            imports[value] += 1
            function = False

    for i in imports:
        imports[i] = imports[i] * (1.0 / total)

    return imports


def gen_imports_bar(good, bad):
    print 'Parsing good json.'
    g = gen_imports_data(good)
    print 'Total Good:', len(g)
    print 'Parsing bad json.'
    b = gen_imports_data(bad)
    print 'Total Bad:', len(b)

    mcg = map(lambda x: x[0], g.most_common(25))
    mcb = map(lambda x: x[0], b.most_common(25))

    most_common = set(mcg + mcb)
    for k in g.keys():
        if k not in most_common:
            del g[k]
    print 'Filtered Good:', len(g)

    for k in b.keys():
        if k not in most_common:
            del b[k]
    print 'Filtered Bad:', len(b)

    gimports, gcounts = zip(*g.most_common())
    bimports, bcounts = zip(*b.most_common())
    gdata = pd.DataFrame({'alignment': 'good', 'symbol': gimports,
                          'count': gcounts})
    bdata = pd.DataFrame({'alignment': 'bad', 'symbol': bimports,
                          'count': bcounts})

    data = gdata.append(bdata).sort_values('count', ascending=False)
    print data

    sns.barplot(x='symbol', y='count', hue='alignment', data=data)


def gen_dylibs_count_data(json):
    dylibs = Counter()
    total = 0
    dylib = False
    for prefix, event, value in ijson.parse(json):
        if prefix.endswith('.filetype'):
            total += 1
        elif prefix.endswith('.imports.item.item'):
            if dylib:
                dylibs[value] += 1
                dylib = False
            else:
                dylib = True

    for d in dylibs:
        dylibs[d] = dylibs[d] * (1.0 / total)

    return dylibs
                


def gen_dylibs_count(good, bad):
    print 'Parsing good json.'
    g = gen_dylibs_count_data(good)
    print 'Total Good:', len(g)
    print 'Parsing bad json.'
    b = gen_dylibs_count_data(bad)
    print 'Total Bad:', len(b)

    mcg = map(lambda x: x[0], g.most_common(50))
    mcb = map(lambda x: x[0], b.most_common(50))

    most_common = set(mcg + mcb)
    for k in g.keys():
        if k not in most_common:
            del g[k]
    print 'Filtered Good:', len(g)

    for k in b.keys():
        if k not in most_common:
            del b[k]
    print 'Filtered Bad:', len(b)

    gdylibs, gcounts = zip(*g.most_common())
    bdylibs, bcounts = zip(*b.most_common())
    gdata = pd.DataFrame({'alignment': 'good', 'dylib': gdylibs,
                          'count': gcounts})
    bdata = pd.DataFrame({'alignment': 'bad', 'dylib': bdylibs,
                          'count': bcounts})

    data = gdata.append(bdata).sort_values('count', ascending=False)
    print data

    sns.barplot(x='dylib', y='count', hue='alignment', data=data)


def gen_lcs_data(json):
    lcs = Counter()
    total = 0
    # execute = None
    temp = None
    segment = False
    segment_64 = False
    for prefix, event, value in ijson.parse(json):
        if prefix.endswith('.filetype'):
            total += 1
        if prefix.endswith('.lcs.item.cmd'):
            if value == 'LOAD_DYLIB':
                continue
            elif value == 'SEGMENT':
                segment = True
            elif value == 'SEGMENT_64':
                segment_64 = True
            else:
                lcs[value] += 1
        if prefix.endswith('.lcs.item.name'):
            if segment:
                lcs['SEGMENT (' + value + ')'] += 1
                segment = False
            elif segment_64:
                lcs['SEGMENT_64 (' + value + ')'] += 1
                segment_64 = False

    print 'Samples parsed:', total

    for l in lcs.keys():
        lcs[l] = lcs[l] * (1.0 / total)

    return lcs


def gen_lcs_bar(good, bad):
    print 'Parsing good json.'
    g = gen_lcs_data(good)
    print 'Total Good:', len(g)
    print 'Parsing bad json.'
    b = gen_lcs_data(bad)
    print 'Total Bad:', len(b)

    mcg = map(lambda x: x[0], g.most_common(25))
    mcb = map(lambda x: x[0], b.most_common(25))

    most_common = set(mcg + mcb)
    for k in g.keys():
        if k not in most_common:
            del g[k]
    print 'Filtered Good:', len(g)

    for k in b.keys():
        if k not in most_common:
            del b[k]
    print 'Filtered Bad:', len(b)

    glcs, gcounts = zip(*g.most_common())
    blcs, bcounts = zip(*b.most_common())
    gdata = pd.DataFrame({'alignment': 'good', 'load command': glcs,
                          'count': gcounts})
    bdata = pd.DataFrame({'alignment': 'bad', 'load command': blcs,
                          'count': bcounts})

    data = gdata.append(bdata).sort_values('count', ascending=False)
    print data

    sns.barplot(x='load command', y='count', hue='alignment', data=data)


def gen_imports_diff_bar(good, bad):
    g = gen_imports_data(good)
    b = gen_imports_data(bad)

    imports = (b - g).most_common(50)
    functions, counts = zip(*imports)
    data = pd.DataFrame({'function': functions, 'count': counts})

    sns.barplot(x='function', y='count', data=data)


def gen_nimports_data(json):
    data = []
    execute = None
    temp = None
    for prefix, event, value in ijson.parse(json):
        if prefix.endswith('.macho') or prefix.endswith('.machos.item'):
            if execute and temp is not None:
                data.append(temp)
                temp = None
            execute = None
        if prefix.endswith('.filetype'):
            if value == 'EXECUTE':
                execute = True
            else:
                execute = False
        if prefix.endswith('.nimps'):
            temp = value

    if temp is not None and execute:
        data.append(temp)

    return data


def gen_nimports_hist(good, bad):
    g = filter(lambda x: x <= 200, gen_nimports_data(good))
    #b = filter(lambda x: x <= 3000, gen_nimports_data(bad))
    
    p = sns.distplot(g)
    p.set(xlim=(0, 200))


def gen_dylibs_data(json):
    dylibs = Counter()
    total = 0
    # execute = None
    # temp_dylibs = []
    for prefix, event, value in ijson.parse(json):
        #if prefix.endswith('.macho') or prefix.endswith('.machos.item'):
            #if execute:
            #    for d in set(temp_dylibs):
            #        dylibs[d] += 1
            #    del temp_dylibs[:]
            #execute = None
        if prefix.endswith('.filetype'):
            #if value == 'EXECUTE':
            #    execute = True
            total += 1
            #else:
            #    execute = False
        if prefix.endswith('.dylibs.item'):
            #if execute or execute is None:
            #    temp_dylibs.append(value)
            dylibs[value] += 1

    #if execute:
    #    for d in set(temp_dylibs):
    #        dylibs[d] += 1

    for i in dylibs:
        dylibs[i] = dylibs[i] * (1.0 / total)

    return dylibs


def gen_dylibs_bar(good, bad):
    print 'Parsing good json.'
    g = gen_dylibs_data(good)
    print 'Total Good:', len(g)
    print 'Parsing bad json.'
    b = gen_dylibs_data(bad)
    print 'Total Bad:', len(b)

    mcg = map(lambda x: x[0], g.most_common(25))
    mcb = map(lambda x: x[0], b.most_common(25))

    most_common = set(mcg + mcb)
    for k in g.keys():
        if k not in most_common:
            del g[k]
    print 'Filtered Good:', len(g)

    for k in b.keys():
        if k not in most_common:
            del b[k]
    print 'Filtered Bad:', len(b)

    gdylibs, gcounts = zip(*g.most_common())
    bdylibs, bcounts = zip(*b.most_common())
    gdata = pd.DataFrame({'alignment': 'good', 'dylib': gdylibs,
                          'count': gcounts})
    bdata = pd.DataFrame({'alignment': 'bad', 'dylib': bdylibs,
                          'count': bcounts})

    data = gdata.append(bdata).sort_values('count', ascending=False)
    print data

    sns.barplot(x='dylib', y='count', hue='alignment', data=data)


def gen_dylibs_diff_bar(good, bad):
    g = gen_dylibs_data(good)
    b = gen_dylibs_data(bad)

    libs = (b - g).most_common(50)
    # g = g.most_common(50)
    # b = b.most_common(50)

    dylibs, counts = zip(*libs)
    data = pd.DataFrame({'dylib': dylibs, 'count': counts})
    sns.barplot(x='dylib', y='count', data=data)


def gen_ndylibs_data(json):
    data = []
    for prefix, event, value in ijson.parse(json):
        if prefix.endswith('.ndylibs'):
            data.append(value)

    return data


def gen_ndylibs_hist(good, bar):
    g = gen_ndylibs_data(good)
    b = gen_ndylibs_data(bad)
    p1 = sns.distplot(g)
    p2 = sns.distplot(b)
    p1.set(xlim=(0, 50))
    p2.set(xlim=(0, 50))


def gen_filetypes_data(json):
    filetypes = Counter()
    for i in json:
        if 'universal' in i.keys():
            for j in i['universal']['machos']:
                filetypes[j['filetype']] += 1
        else:
            filetypes[i['macho']['filetype']] += 1

    return filetypes


def gen_filetypes_data_new(json):
    filetypes = Counter()
    total = 0
    for prefix, event, value in json:
        if prefix.endswith('.filetype'):
            total += 1
            filetypes[value] += 1

    

    return filetypes


def gen_filetypes_bar(good):#, bad):
    g = gen_filetypes_data_new(good)
    #b = gen_filetypes_data(bad)
    gtypes, gcounts = zip(*g.iteritems())
    #btypes, bcounts = zip(*b.iteritems())
    gdata = pd.DataFrame({'alignment': 'good', 'file type': gtypes,
                          'count': gcounts})
    #bdata = pd.DataFrame({'alignment': 'bad', 'file type': btypes,
    #                     'count': bcounts})
    data = gdata#.append(bdata)
    print data
    sns.barplot(x='file type', y='count', hue='alignment', data=data)


def gen_snlcr_data(json):
    data = []
    for i in json:
        if 'universal' in i.keys():
            for j in i['universal']['machos']:
                data.append(j['analytics']['snlcr'])
        else:
            data.append(i['macho']['analytics']['snlcr'])

    return data


def gen_slcs_data(json):
    slcs = []
    for prefix, event, value in ijson.parse(json):
        if prefix.endswith('.slcs'):
            slcs.append(value)

    return slcs


def gen_slcs_hist(good, bad):
    g = gen_slcs_data(good)
    b = gen_slcs_data(bad)
    p = sns.distplot(g)
    p.set(xlim=(0, 6000))
    p2 = sns.distplot(b)
    p2.set(xlim=(0, 6000))


def gen_sects_data(json):
    sects = Counter()
    total = 0
    segname = None
    name = None
    for prefix, event, value in ijson.parse(json):
        if prefix.endswith('.filetype'):
            total += 1
        elif prefix.endswith('.sects.item.segname'):
            if name is None:
                segname = value
            else:
                sects[value + ', ' + name] += 1
                name = None
        elif prefix.endswith('.sects.item.name'):
            if segname is None:
                name = value
            else:
                sects[segname + ', ' + value] += 1
                segname = None

    for s in sects.keys():
        sects[s] = sects[s] * (1.0 / total)

    return sects


def gen_sects_bar(good, bad):
    print 'Parsing good json.'
    g = gen_sects_data(good)
    print 'Total Good:', len(g)
    print 'Parsing bad json.'
    b = gen_sects_data(bad)
    print 'Total Bad:', len(b)

    mcg = map(lambda x: x[0], g.most_common(25))
    mcb = map(lambda x: x[0], b.most_common(25))

    most_common = set(mcg + mcb)
    for k in g.keys():
        if k not in most_common:
            del g[k]
    print 'Filtered Good:', len(g)

    for k in b.keys():
        if k not in most_common:
            del b[k]
    print 'Filtered Bad:', len(b)

    gsects, gcounts = zip(*g.most_common())
    bsects, bcounts = zip(*b.most_common())
    gdata = pd.DataFrame({'alignment': 'good', 'section': gsects,
                          'count': gcounts})
    bdata = pd.DataFrame({'alignment': 'bad', 'section': bsects,
                          'count': bcounts})

    data = gdata.append(bdata).sort_values('count', ascending=False)
    print data

    sns.barplot(x='section', y='count', hue='alignment', data=data)


def gen_entropy_data(json):
    entropy = []
    for prefix, event, value in ijson.parse(json):
        if prefix.endswith('.entropy'):
            entropy.append(float(value))

    return entropy


def gen_entropy_hist(good, bad):
    g = gen_entropy_data(good)
    b = gen_entropy_data(bad)
    p1 = sns.distplot(g, color='g')
    p2 = sns.distplot(b, color='r')
    p1.set(xlim=(0,1))
    p2.set(xlim=(0,1))


def gen_abnormalities_data(json):
    abnormalities = Counter()
    total = 0
    temp = []
    for prefix, event, value in ijson.parse(json):
        if prefix.endswith('.filetype'):
            total += 1
        elif prefix.endswith('.abnormalities'):
            del temp[:]
        elif prefix.endswith('.abnormalities.item.title'):
            if value not in temp:
                abnormalities[value] += 1
                temp.append(value)

    for a in abnormalities.keys():
        abnormalities[a] = abnormalities[a] * (1.0 / total)

    return abnormalities


def gen_abnormalities_bar(good, bad):
    print 'Parsing good json.'
    g = gen_abnormalities_data(good)
    print 'Total Good:', len(g)
    print 'Parsing bad json.'
    b = gen_abnormalities_data(bad)
    print 'Total Bad:', len(b)

    mcg = map(lambda x: x[0], g.most_common(25))
    mcb = map(lambda x: x[0], b.most_common(25))

    most_common = set(mcg + mcb)
    for k in g.keys():
        if k not in most_common:
            del g[k]
    print 'Filtered Good:', len(g)

    for k in b.keys():
        if k not in most_common:
            del b[k]
    print 'Filtered Bad:', len(b)

    gabnormalities, gcounts = zip(*g.most_common())
    babnormalities, bcounts = zip(*b.most_common())
    gdata = pd.DataFrame({'alignment': 'good', 'abnormality': gabnormalities,
                          'count': gcounts})
    bdata = pd.DataFrame({'alignment': 'bad', 'abnormality': babnormalities,
                          'count': bcounts})

    data = gdata.append(bdata).sort_values('count', ascending=False)
    print data

    sns.barplot(x='abnormality', y='count', hue='alignment', data=data)


good = open(sys.argv[1], 'rb')
bad = open(sys.argv[2], 'rb')

# gen_imports_bar(good, bad)
# gen_lcs_bar(good, bad)
# gen_nimports_hist(good, bad)
gen_dylibs_count(good, bad)
# gen_dylibs_bar(good, bad)
# gen_ndylibs_hist(good, bad)
# gen_filetypes_bar(good, bad)
# gen_slcs_hist(good, bad)
# gen_sects_bar(good, bad)
# gen_entropy_hist(good, bad)
#gen_abnormalities_bar(good, bad)

sns.plt.xticks(rotation=-70, horizontalalignment='left')
sns.plt.show()
