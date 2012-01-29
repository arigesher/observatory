'''
Created on Jan 28, 2012

@author: regs
'''

import construct
from TLSConstructs import *
import sys, traceback
from OpenSSL import crypto
import StringIO

testfile = '../testdata/128.104.80.200.results'
out = sys.stdout

input = open(testfile,'r')
data = input.read()
input.close()

recs = TLSRecord.parse(data)
certs = []
count = 0
for rec in recs:
    if rec.ContentType == 'handshake':
        handshake_messages = Handshake.parse(rec.data)
        for hand_msg in handshake_messages:
          if hand_msg.msg_type == 'certificate':
            cert_msg = Certificate.parse(hand_msg.body)
            data_read = 0
            while data_read < cert_msg.list_length:
              cert = ASNCert.parse(cert_msg.list_data[data_read:])
              data_read += cert.cert_length + 3
              certs.append(cert)
    for certificate in certs:
      count = count + 1
      try:
        buff = StringIO.StringIO()
        buff.write('-----BEGIN CERTIFICATE-----\n')
        buff.write(certificate.cert.encode('base64'))
        buff.write('-----END CERTIFICATE-----\n')
      except:
        traceback.print_exc()
        print "error with certificate %d in %s" % (count, testfile)
      
      print cert
      x509 = crypto.load_certificate(crypto.FILETYPE_ASN1,cert.cert)
      print dir(x509.get_pubkey())
      
      