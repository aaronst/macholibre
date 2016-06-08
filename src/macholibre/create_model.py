import sys
import numpy as np
import pandas as pd
import sklearn
import json
import matplotlib
import matplotlib.pyplot as plt

from tqdm import tqdm
from glob import glob
from collections import Counter
from sklearn.externals import joblib
from sklearn.linear_model import RandomizedLogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.pipeline import Pipeline
from sklearn.cross_validation import train_test_split
from sklearn.metrics import confusion_matrix

from parser import Parser
from analyzer import Analyzer
from packer import Packer


def processFile(path):
    try:
        p = Parser(path=path)
        p.parseFile()
        a = Analyzer(parser=p)
        a.analyze()
        j = Packer(analyzer=a)
        return j.pack()
    except:
        print path
        exit(1)

def build_row(m, label):
    global dylibs_good, dylibs_bad, imports_good, imports_bad, strings_good, strings_bad
    row = {}
    row['mach-o size'] = m['size']
    row['file type'] = m['filetype']
    row['cpu type'] = m['cputype']
    row['cpu subtype'] = m['subtype']
    row['number of flags'] = len(m['flags'])
    for f in m['flags']:
        row[f] = 1
    row['number of load commands'] = m['nlcs']
    row['size of load commands'] = m['slcs']
    for l in m['lcs']:
        if l['cmd'] in ('SEGMENT', 'SEGMENT_64'):
            row[l['name']] = 1
            row['size of ' + l['name']] = l['segsize']
            row['number of ' + l['name'] + ' sections'] = l['nsects']
        elif l['cmd'] in ('DYLD_INFO', 'DYLD_INFO_ONLY'):
            row['bind offset'] = l['bind_off']
            row['bind size'] = l['bind_size']
            row['export offset'] = l['export_off']
            row['export size'] = l['export_size']
            row['lazy bind offset'] = l['lazy_bind_off']
            row['lazy bind size'] = l['lazy_bind_size']
            row['rebase offset'] = l['rebase_off']
            row['rebase size'] = l['rebase_size']
            row['weak bind offset'] = l['weak_bind_off']
            row['weak bind size'] = l['weak_bind_size']
        elif l['cmd'] in ('MAIN', 'UNIXTHREAD'):
            continue
        else:
            row[l['cmd']] = 1
    row['number of dylibs'] = len(m['dylibs'])
    for d in m['dylibs']:
        row[d] = 1
    #    if label == 'good':
    #        dylibs_good[d] += 1
    #    else:
    #        dylibs_bad[d] += 1
    row['number of imports'] = len(m['imports'])
    #for i in m['imports']:
        #row[i[0]] = 1
    #    if label == 'good':
    #        imports_good[i[0]] += 1
    #    else:
    #        imports_bad[i[0]] += 1
    row['entropy'] = m['analytics']['entropy']
    row['number of segments'] = len(filter(lambda x: x['cmd'] in ('SEGMENT', 'SEGMENT_64'), m['lcs']))
    if 'strtab' in m:
        row['string table size'] = m['strtab']['size']
        row['number of strings'] = len(m['strtab']['strings'])
        row['number of unique strings'] = len(set(m['strtab']['strings']))
    #    for s in set(m['strtab']['strings']):
    #        if not (s.startswith('___') or s.startswith('GCC_except_table')):
    #            if label == 'good':
    #                strings_good[s] += 1
    #            else:
    #                strings_bad[s] += 1
    if 'symtab' in m:
        if 'nlocal' in m['symtab']:
            row['number of local symbols'] = m['symtab']['nlocal']
        if 'nexternal' in m['symtab']:
            row['number of external symbols'] = m['symtab']['nexternal']
        if 'nundefined' in m['symtab']:
            row['number of undefined symbols'] = m['symtab']['nundefined']
    if 'signature' in m:
        row['size of code signature'] = m['signature']['size']
        row['number of entitlements'] = len(m['signature']['entitlements'])
        row['number of requirements'] = len(m['signature']['requirements'])
        row['number of certificates'] = len(m['signature']['certs'])
    return row

def build_df(j, label):
    global raw_data
    if 'universal' in j:
        for m in j['universal']['machos']:
            row = build_row(m, label)
            row['label'] = label
            row['hash'] = j['name']
            row['file size'] = j['size']
            row['number of architectures'] = len(j['universal']['machos'])
            row['number of abnormalities'] = len(j['abnormalities'])
            raw_data = raw_data.append(row, ignore_index=True)
    else:
        m = j['macho']
        row = build_row(m, label)
        row['label'] = label
        row['hash'] = j['name']
        row['file size'] = j['size']
        row['number of architectures'] = 1
        row['number of abnormalities'] = len(j['abnormalities'])
        raw_data = raw_data.append(row, ignore_index=True)
    #print len(raw_data)

def plot_cm(cm, labels):
    # Compute percentanges
    percent = (cm * 100.0) / np.array(np.matrix(cm.sum(axis=1)).T)
    print 'Confusion Matrix Stats'
    for i, label_i in enumerate(labels):
        for j, label_j in enumerate(labels):
            print "%s/%s: %.2f%% (%d/%d)" % (label_i, label_j, (percent[i][j]), cm[i][j], cm[i].sum())

    # Show confusion matrix
    # Thanks to kermit666 from stackoverflow
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.grid(b=False)
    cax = ax.matshow(percent, cmap='coolwarm',vmin=0,vmax=100)
    plt.title('Confusion matrix of the classifier')
    fig.colorbar(cax)
    ax.set_xticklabels([''] + labels)
    ax.set_yticklabels([''] + labels)
    plt.xlabel('Predicted')
    plt.ylabel('True')
    plt.show()

def learn(f):
    global raw_data
    print 'testing classifier'
    data = raw_data[raw_data['label'] != 'unknown']
    data = data[data['file type'] == 'EXECUTE']
    X = data.as_matrix(f)
    y = np.array(data['label'].tolist())
    #clf = RandomForestClassifier(n_estimators=100)
    clf = ExtraTreesClassifier(n_estimators=100)
    #clf = AdaBoostClassifier()
    scores = sklearn.cross_validation.cross_val_score(clf, X, y, cv=10)
    print("predicted accuracy: %0.2f (+/- %0.2f)" % (scores.mean(), scores.std() * 2))
    seed = 3301
    X_train, X_test, y_train, y_test = train_test_split(X, y, random_state=seed)
    clf.fit(X_train, y_train)
    scores = clf.score(X_test, y_test)
    print("actual accuracy: %0.2f" % scores)
    importances = zip(f, clf.feature_importances_)
    importances.sort(key=lambda k:k[1], reverse=True)
    for im in importances[0:20]:
        print im[0].ljust(30), im[1]
    #y_pred = clf.predict(X_test)
    #labels = ['good', 'bad']
    #cm = confusion_matrix(y_test, y_pred, labels)
    #plot_cm(cm, labels)
    #joblib.dump(clf, 'model.pkl')
    return clf

def visualize():
    global raw_data
    good = raw_data[raw_data['label'] == 'good']
    bad = raw_data[raw_data['label'] == 'bad']
    good['SOURCE_VERSION'].value_counts().plot(kind='bar')
    plt.show()
    bad['SOURCE_VERSION'].value_counts().plot(kind='bar')
    plt.show()

def classify(clf, f):
    global raw_data
    data = raw_data[raw_data['label'] == 'unknown']
    data = data[data['file type'] == 'EXECUTE']
    X = data.as_matrix(f)
    y = np.array(data['hash'].tolist())
    predictions = clf.predict(X)
    for i in range(len(y)):
        print y[i], predictions[i]

#raw_data = pd.DataFrame()
#dylibs_good = Counter()
#dylibs_bad = Counter()
#imports_good = Counter()
#imports_bad = Counter()
#strings_good = Counter()
#strings_bad = Counter()

#print 'processing good mach-o\'s'
#for f in tqdm(glob(sys.argv[1])):
#    build_df(processFile(f), 'good')

#print 'processing bad mach-o\'s'
#for f in tqdm(glob(sys.argv[2])):
#    build_df(processFile(f), 'bad')

#print 'processing unknown mach-o\'s'
#for f in tqdm(glob(sys.argv[3])):
#    build_df(processFile(f), 'unknown')

#for k in dylibs_good:
#    dylibs_good[k] /= float(len(raw_data[raw_data['label'] == 'good']))
#for k in dylibs_bad:
#    dylibs_bad[k] /= float(len(raw_data[raw_data['label'] == 'bad']))
#for k in imports_good:
#    imports_good[k] /= float(len(raw_data[raw_data['label'] == 'good']))
#for k in imports_bad:
#    imports_bad[k] /= float(len(raw_data[raw_data['label'] == 'bad']))
#for k in strings_good:
#    strings_good[k] /= float(len(raw_data[raw_data['label'] == 'good']))
#for k in strings_bad:
#    strings_bad[k] /= float(len(raw_data[raw_data['label'] == 'bad']))

#raw_data.fillna(-1, inplace=True)
#raw_data = raw_data[~raw_data['cpu type'].isin(('POWERPC',
#                                                'POWERPC64',
#                                                'ARM', 'ARM64',
#                                                'MIPS', 'VAX'))]

#raw_data.to_pickle('data.pkl')
raw_data = pd.read_pickle('data.pkl')

#features = ['mach-o size', 'number of flags', 'number of load commands', 'size of load commands',
#            'size of __TEXT', 'size of __DATA', 'size of __LINKEDIT', 'number of segments']
features = list(raw_data.columns.values)
features.remove('label')
features.remove('hash')
features.remove('file type')
features.remove('cpu type')
features.remove('cpu subtype')
features.remove('/usr/lib/libobjc.A.dylib')
features.remove('@loader_path/../Frameworks/Sparkle.framework/Versions/A/Sparkle')
features.remove('/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation')
features.remove('/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit')
features.remove('/System/Library/Frameworks/WebKit.framework/Versions/A/WebKit')
features.remove('/System/Library/Frameworks/Cocoa.framework/Versions/A/Cocoa')
features.remove('/System/Library/Frameworks/ApplicationServices.framework/Versions/A/ApplicationServices')
features.remove('SOURCE_VERSION')
features.remove('CODE_SIGNATURE')
features.remove('number of entitlements')
features.remove('number of requirements')
features.remove('number of certificates')
features.remove('size of code signature')
#features = [x for x in features if not (str(x).startswith('/') or str(x).startswith('@'))]

#print 'dylibs:', len(dylibs_good | dylibs_bad)
#print '    good:'
#for k in dylibs_good.most_common(25):
#    print '    ' + k[0], k[1]
#print '    bad:'
#for k in dylibs_bad.most_common(25):
#    print '    ' + k[0], k[1]
#print 'imports:', len(imports_good | imports_bad)
#print '    good:'
#for k in imports_good.most_common(25):
#    print '    ' + k[0], k[1]
#print '    bad:'
#for k in imports_bad.most_common(25):
#    print '    ' + k[0], k[1]
#print 'strings:', len(strings_good | strings_bad)
#print '    good:'
#for k in strings_good.most_common(25):
#    print '    ' + k[0], k[1]
#print '    bad:'
#for k in strings_bad.most_common(25):
#    print '    ' + k[0], k[1]
#visualize()
m = learn(features)
classify(m, features)
