#!/usr/bin/python

# MachoLibre
# Universal & Mach-O Binary Parser
# aaron@icebrg.io
# March 2016

from ctypescrypto import cms

sig = open('signed_data').read()
sig = cms.CMS(sig, format='DER')
print '=CERTS='
for cert in sig.certs:
    print 'Serial:', cert.serial
    print '    Subject: "' + str(cert.subject) + '"'
    print '    Issuer: "' + str(cert.issuer) + '"'
    print '    CA:', cert.check_ca()
