'''
Created on Jan 28, 2012

@author: regs
'''
import simplejson as json
from OpenSSL.crypto import *


def json_encode_x509Name(x509name):
    if not isinstance(x509name , X509Name):
        raise TypeError('Must be of type %s'%(X509Name.__str__()))
    else:
        encoded_name = {}
        encoded_name['hash'] = x509name.hash()
        encoded_name['der_encoded_name'] = x509name.der()
        for component in x509name.get_component():
            encoded_name[component[0]] = component[1]
    return encoded_name

def json_encode_
            
        
    
def json_encode_x509(x509):
    if not isinstance(x509, crypto.X509) :
        raise TypeError('Must be of type crypto.X509')
    else:
        issuer = x509.get_issuer()
        pub_Key = x509.get_pubkey()
        serial = x509.get_serial_number()
        sig_algo = x509.get_signature_algorithm()
        subjet = x509.get_subject()
        not_before = x509.get_notBefore()
        not_after = x509.get_notAfter()
        subject_name_hash = x509.subject_name_hash()
        digest_sha1 = x509.digest('sha1')
        digest_md5 = x509.digest('md5')
        