
from flask import Flask, render_template, request, url_for
import pandas as pd
import numpy as np
import logging
from configparser import ConfigParser

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import pss
import rsa

from rsa import sign

import os

from utils import create_generate
from utils import check_certificate,check_date_certificate
from utils import get_file_hash

app = Flask(__name__)


@app.route("/", methods=["GET"])
def mainhome():
    return(render_template("main.html"))

@app.route("/about", methods=["GET"])
def about():
    return(render_template("about.html"))

@app.route("/create_keys", methods=["GET","POST"])
def crear_firmas():
    return(render_template("create_keys.html"))

@app.route("/generated_keys",methods=["GET","POST"])
def generated_keys():
    global pubKey
    global privKey

    name=request.form["name"]
    country=request.form["country"]
    state=request.form["state"]
    city=request.form["city"]
    organization=request.form["organization"]
    unit=request.form["unit"]
    email=request.form["email"]
    print(name,country,state,city,organization,unit,email,)
    serial= 0
    validity_e = 0
    output_f = "certificado.crt"
    pubKey = str(name) + "_public.pem"
    privKey = str(name) + "_private.pem"
    

    (publicKey, privateKey) = rsa.newkeys(2048)
    with open(pubKey, 'wb') as f:
        f.write(publicKey.save_pkcs1('PEM'))

    with open(privKey, 'wb') as f:
        f.write(privateKey.save_pkcs1('PEM'))

    print(output_f)
    print(pubKey,privKey)
    create_generate(name,country,state,city,
                    serial,organization,unit,email,
                    validity_e,pubKey,privKey,output_f)
    return(render_template("generated_keys.html"))

@app.route("/sign_document", methods=["GET","POST"])
def sign_document():
    return(render_template("sign_document.html"))

@app.route("/signer_document", methods=["GET","POST"])
def signer_document():

    ar = request.form["message"]
    key = request.form["key"]
    certificate = request.form["certificate"]
    

    if check_certificate(certificate,key):
        cer_ver="Your certificate is good to go"
    else:
        cer_ver="Your certificate is not good to go"
    file_hash = str(get_file_hash(ar))
    k = RSA.import_key(open(key).read())
    hs = SHA256.new(file_hash.encode("utf-8"))
    firma = pss.new(k)
    signature = firma.sign(hs)
    print(signature)
    file_out = open("firma.pem","wb")
    file_out.write(signature)
    file_out.close()
    return(render_template("signer_document.html",ver=cer_ver))

@app.route("/verify_document",methods=["GET","POST"])
def verify_document():
    return(render_template("verify_document.html"))

@app.route("/verified_document", methods=["GET","POST"])
def verified_document():
    
    ar = request.form["document"]
    key = request.form["key"]
    firma = request.form["firma"]

    file_hash = str(get_file_hash(ar))

    firma = open(firma, "rb")
    firma = firma.read()

    k = RSA.import_key(open(key).read())
    hs = SHA256.new(file_hash.encode("utf-8"))
    verifier = pss.new(k)
    try:
        verifier.verify(hs,firma)
        ver = "Your signature is authentic"
    except (ValueError,TypeError):
        ver = "Your signature is not authentic"

    return(render_template("verified_document.html", verification=ver))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, port=port)