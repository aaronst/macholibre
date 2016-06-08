import sys
import numpy
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import ijson.backends.yajl2_cffi as ijson

from scipy import interp

from sklearn.externals import joblib
from sklearn.pipeline import Pipeline
from sklearn.feature_selection import f_classif, chi2, f_regression
from sklearn.feature_selection import GenericUnivariateSelect
from sklearn.feature_selection import VarianceThreshold
from sklearn.feature_selection import RFECV
from sklearn.feature_selection import SelectFromModel
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import LinearSVC
from sklearn.linear_model import RandomizedLogisticRegression
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.cross_validation import StratifiedKFold
from sklearn.cross_validation import cross_val_score
from sklearn.metrics import roc_curve, auc


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


def fetch_data():
    x = numpy.load('data_x.npy')
    y = numpy.load('data_y.npy')
    return x, y


def feature_selection_rfecv(x, y):
    # Create the RFE object and compute a cross-validated score.
    dtc = DecisionTreeClassifier()
    # The "accuracy" scoring is proportional to the number of correct classifications
    rfecv = RFECV(estimator=dtc, step=1, cv=StratifiedKFold(y, 2), scoring='accuracy')
    rfecv.fit(x, y)
    print 'Optimal number of features: %d' % rfecv.n_features_
    # Plot number of features VS. cross-validation scores
    plt.figure()
    plt.xlabel('Number of features selected')
    plt.ylabel('Cross validation score (nb of correct classifications)')
    plt.plot(range(1, len(rfecv.grid_scores_) + 1), rfecv.grid_scores_)
    plt.show()


def feature_selection(x, y):
    print 'Selecting Features'
    #svc = LinearSVC(C=1, penalty="l1", dual=False)
    #lr = LogisticRegression(solver='liblinear', penalty='l1', dual=False, C=1).fit(x, y)
    #print 'Feature Scores'
    #coefs = lr.coef_
    #i = 0
    #for f in features[1:]:
    #    print f + ': ' + str(coefs[0][i])
    #    i += 1
    #model = SelectFromModel(svc).fit(x, y)
    #x_new = model.transform(x)

    #x_new = GenericUnivariateSelect(chi2, mode='percentile', param=50).fit_transform(x, y)
    #x_new = VarianceThreshold(threshold=(.75 * (1 - .75))).fit_transform(x, y)
    x_new = x

    #dtc = DecisionTreeClassifier()
    rfc = RandomForestClassifier()

    print 'Training Random Forest'
    skf = StratifiedKFold(y, n_folds=100)
    mean_tpr = 0.0
    mean_fpr = numpy.linspace(0, 1, 100)

    for i in range(len(y)):
        if y[i] == 'bad':
            y[i] = 1
        else:
            y[i] = 0

    y = y.astype(int)
 
    for train_index, test_index in skf:
        x_train, x_test = x_new[train_index], x_new[test_index]
        y_train, y_test = y[train_index], y[test_index]

        probas = rfc.fit(x_train, y_train).predict_proba(x_test)
        fpr, tpr, thresholds = roc_curve(y_test, probas[:, 1])
        mean_tpr += interp(mean_fpr, fpr, tpr)
        mean_tpr[0] = 0.0

    mean_tpr /= len(skf)
    mean_tpr[-1] = 1.0
    mean_auc = auc(mean_fpr, mean_tpr)
    plt.plot(mean_fpr, mean_tpr, 'k--',
             label='Random Forest (AUC = %0.3F)' % mean_auc,
             lw=2, c='g')

    plt.plot([0, 1], [0, 1], '--', color=(0.6, 0.6, 0.6), label='Luck')

    plt.xlim([-0.05, 1.05])
    plt.ylim([-0.05, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.legend(loc="lower right", fancybox=True, shadow=True, fontsize=10)
    plt.tight_layout()
    #plt.savefig('the_new_goods.svg')
    print 'Done'
    plt.show()


def fast_classify(x, y):
    for i in range(len(y)):
        if y[i] == 'bad':
            y[i] = 1
        else:
            y[i] = -1
    y = y.astype(int) 
    rfc = RandomForestClassifier(n_estimators=10, min_samples_split=1, n_jobs=-1)
    scores = cross_val_score(rfc, x, y, cv=100)
    print("Accuracy: %0.2f (+/- %0.2f)" % (scores.mean(), scores.std() * 2))
    #rfc.fit(x, y)
    #joblib.dump(rfc, 'model.pkl')


def classify(x, y):
    #x = StandardScaler().fit_transform(x)
    skf = StratifiedKFold(y, n_folds=10)

    classifiers = [
        #KNeighborsClassifier(),
        #RandomizedLogisticRegression(),
        LogisticRegression(),
        DecisionTreeClassifier(),
        AdaBoostClassifier(),
        RandomForestClassifier(),
        #GaussianNB()
    ]

    names = [
        #'Randomized Logistic Regression',
        'Logistic Regression',
        'Decision Tree',
        'AdaBoost',
        'Random Forest'
    ]

    colors = [
        #'b',
        'g',
        'r',
        'c',
        'm'
    ]

    for c in classifiers:
        print 'Training ' + names[classifiers.index(c)]
        mean_tpr = 0.0
        mean_fpr = numpy.linspace(0, 1, 100)

        for train_index, test_index in skf:
            x_train, x_test = x[train_index], x[test_index]
            y_train, y_test = y[train_index], y[test_index]

            probas = c.fit(x_train, y_train).predict_proba(x_test)
            fpr, tpr, thresholds = roc_curve(y_test, probas[:, 1])
            mean_tpr += interp(mean_fpr, fpr, tpr)
            mean_tpr[0] = 0.0

        mean_tpr /= len(skf)
        mean_tpr[-1] = 1.0
        mean_auc = auc(mean_fpr, mean_tpr)
        plt.plot(mean_fpr, mean_tpr, 'k--',
                 label=names[classifiers.index(c)] + ' (AUC = %0.3F)' % mean_auc,
                 lw=2, c=colors[classifiers.index(c)])

    plt.plot([0, 1], [0, 1], '--', color=(0.6, 0.6, 0.6), label='Luck')

    plt.xlim([-0.05, 1.05])
    plt.ylim([-0.05, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.legend(loc="lower right", fancybox=True, shadow=True, fontsize=10)
    plt.tight_layout()
    plt.show()
    #plt.savefig("the_goods.svg")

good = open(sys.argv[1], 'rb')
bad = open(sys.argv[2], 'rb')
data = build_dataframe(good, bad)
x, y = split_data(data)
#x, y = fetch_data()
#feature_selection(x, y)
fast_classify(x, y)
#classify(x, y)

