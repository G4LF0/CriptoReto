
import rsa
from OpenSSL import crypto
import OpenSSL.crypto
from OpenSSL import crypto, SSL
from datetime import datetime
import hashlib
from Crypto.PublicKey import RSA
import hashlib
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import pss



def create_generate(name,country,state,city,serial,organization,unit,email, validity_e,publicKey,privateKey,output_f):

    certif = crypto.X509()
    certif.get_subject().CN=name
    certif.get_subject().C=country
    certif.get_subject().ST=state
    certif.get_subject().L=city
    certif.get_subject().O=organization
    certif.get_subject().OU=unit
    certif.get_subject().emailAddress=email
    certif.get_issuer().CN=name
    certif.get_issuer().C=country
    certif.get_issuer().ST=state
    certif.get_issuer().L=city
    certif.get_issuer().O=organization
    certif.get_issuer().OU=unit
    certif.get_issuer().emailAddress=email
    certif.set_serial_number(serial)
    certif.gmtime_adj_notBefore(0)
    certif.gmtime_adj_notAfter(validity_e)
    certif.set_issuer(certif.get_issuer())
    with open(publicKey, "rb") as pub_key:
        p_key_s = pub_key.read()
        x = crypto.load_publickey(crypto.FILETYPE_PEM, p_key_s)
    certif.set_pubkey(x)

    with open(privateKey, "rb") as priv_key:
        priv_key_s = priv_key.read()
        y = crypto.load_privatekey(crypto.FILETYPE_PEM, priv_key_s)
    
    certif.sign(y, 'sha256')
    with open(output_f,"wt") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certif).decode("utf-8"))

def check_certificate(certificate, key):
    pub_key = open(key).read()
    load = crypto.load_privatekey(crypto.FILETYPE_PEM, pub_key)

    cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(certificate).read())

    verifier = SSL.Context(OpenSSL.SSL.TLSv1_METHOD)

    verifier.use_privatekey(load)
    verifier.use_certificate(cert)

    try:
        verifier.check_privatekey()
        return True
    except SSL.Error:
        return False

def check_date_certificate(certificate):
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(certificate).read())

    expiration_date = cert.get_notAfter().decode()
    year = int(expiration_date[:4])
    month = int(expiration_date[4:6])
    day = int(expiration_date[6:8])

    expiration_date = datetime(year, month, day)
    today = datetime.now()

    if expiration_date > today:
        return True
    else:
        return False

def get_file_hash(file_name):

    file_hash = hashlib.sha256()

    with open(file_name, "rb") as file:
        ck = 0
        
        while ck != b'':
            ck = file.read(1024)
            file_hash.update(ck)
    
    return file_hash.hexdigest()


