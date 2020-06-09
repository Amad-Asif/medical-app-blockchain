#!/usr/bin/env python3


import datetime
import json

import time

import app.rsa as rsa
from app.db_utils import *

import requests
from flask import render_template, redirect, request, jsonify, url_for

from app import app

from base64 import b64encode, b64decode
import os

from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA


import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


# Stores the node's address.
CONNECTED_NODE_ADDRESS = "http://127.0.0.1:8000"
# Stores all the posts in the node.
posts = []

# Signs the document with the private key


def sign_document(message, id):
    # private_key = None
    # path = os.getcwd() + "/data/private_key" + "/private_key_doc_0001.pem"
    # with open(path, "r") as myfile:
    #     private_key = RSA.importKey(myfile.read())
    # hasher = SHA256.new(message.encode('utf-8'))
    # signer = PKCS1_v1_5.new(private_key)
    # signature = b64encode(signer.sign(hasher))
    # signature = base64.b64encode(signature)
    # return signature.decode()

    digest = SHA256.new()
    digest.update(message.encode('utf-8'))
    private_key = None
    path = os.getcwd() + "/data/private_key" + "/private_key_000" + id + "_patient.pem"
    with open(path, "r") as myfile:
        private_key = RSA.importKey(myfile.read())
    signature = b64encode(
        rsa.sign(message.encode('utf-8'), private_key, "SHA-256"))

    return signature.decode()

# Gets the data from node's /chain endpoint, parses the data, and stores it locally.


def decrypt_document(document, id):
    private_key = None
    encrypted = document["encrypted_record"]
    path = os.getcwd() + "/data/private_key" + "/private_key_doc_" + "000" + id + ".pem"
    with open(path, "r") as myfile:
        private_key = RSA.importKey(myfile.read())
    
    decrypted = rsa.decrypt(b64decode(encrypted), private_key)
    print("decrypted is ")
    print(decrypted)
    return decrypted

def fetch_posts():
    get_chain_address = "{0}/chain".format(CONNECTED_NODE_ADDRESS)
    response = requests.get(get_chain_address)
    if response.status_code == 200:
        content = []
        chain = json.loads(response.content.decode("utf-8"))
        for block in chain["chain"]:
            for tx in block["transactions"]:
                tx["index"] = block["index"]
                tx["hash"] = block["previous_hash"]
                content.append(tx)
        global posts
        posts = sorted(content, key=lambda k: k["timestamp"], reverse=True)


@app.route("/home")
# Renders the index.html (home page).
def index():
    fetch_posts()
    return render_template("index.html",
                           title="Medictron",
                           subtitle="A Decentralized Network for Medical Records Sharing",
                           posts=posts,
                           node_address=CONNECTED_NODE_ADDRESS,
                           readable_time=timestamp_to_string)


@app.route("/submit", methods=["POST"])
# The endpoint to create a new tranaction.
def submit_textarea():
    post_content = request.form["content"]
    author = request.form["author"]
    doc_signature = sign_document(post_content)
    post_object = {
        "author": author,
        "signature": doc_signature,
        "content": post_content,
    }

    # Submit a new transaction.
    new_tx_address = "{0}/new_transaction".format(CONNECTED_NODE_ADDRESS)
    requests.post(new_tx_address, json=post_object, headers={
                  "Content-type": "application/json"})
    return redirect("/home")


# Converts a timestamp (in UNIX time) to a string.
def timestamp_to_string(unix_time):
    return datetime.datetime.fromtimestamp(unix_time).strftime("%H:%M")


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'GET':
        return render_template('register.html', title='BlockChain', subtitle='Register')

    if request.method == 'POST':
        data = []
        data.append(request.form['name'])
        data.append(request.form['email'])
        data.append(request.form['contact'])
        data.append(request.form['username'])
        data.append(request.form['password'])
        data.append(request.form['public_key'])
        type = request.form['type']
        db_conn = get_db_conn()

        if type == 'doctor':
            data.append(request.form['speciality'])
            data.append(request.form['experience'])
            resp = insert_doctor(db_conn, data)
        else:
            db_conn = get_db_conn()
            resp = insert_patient(db_conn, data)

        return redirect('/login')


@app.template_filter('ctime')
def timectime(s):
    return time.ctime(s) # datetime.datetime.fromtimestamp(s)

@app.route('/', methods=['POST', 'GET'])
def login():
    if request.method == 'GET':
        return render_template('login.html', title="BlockChain", subtitle="Login")

    if request.method == 'POST':
        db_conn = get_db_conn()
        type = request.form['type']
        username = request.form['username']
        password = request.form['password']

        if type == 'doctor':
            resp = get_doctor(db_conn, username, password)
            if resp:
                insert_audit_trail(db_conn,resp[0][0],type, "User {} logged in successfully".format(username))
                return redirect(url_for('doctor', id=resp[0][0]))

        else:
            resp = get_patient(db_conn, username, password)
            if resp:
                insert_audit_trail(db_conn,resp[0][0],type, "User {} logged in successfully".format(username))
                return redirect(url_for('patient', id=resp[0][0]))

        return render_template('login.html', title="BlockChain", subtitle="Login")


@app.route('/patient', methods=['POST', 'GET'])
def patient():
    if request.method == 'GET':
        id = request.args['id']
        db_conn = get_db_conn()
        patient = get_patient_by_id(db_conn, id)
        doctors = get_all_doctors(db_conn)
        return render_template('patient.html', title='BlockChain', subtitle='Patient', patient=patient, doctors=doctors)

    if request.method == 'POST':
        db_conn = get_db_conn()
        data = []
        data.append(request.form['symptoms'])
        data.append(request.form['patient_id'])
        data.append(request.form['doctor_id'])

        record = request.form['symptoms']
        doc_id = request.form['doctor_id']
        # get public-key from db of doc-id
        # encrypt record using public-key of doctor
        pat_id = request.form['patient_id']

        doc_pub_key = get_doc_public_key_by_id(db_conn, doc_id)
        doc_pub_key = b64decode(doc_pub_key)
        doc_pub_key = RSA.importKey(doc_pub_key)

        encr_record = b64encode(rsa.encrypt(bytes(record, 'utf-8'), doc_pub_key))

        payload = {
            "record": record,
            "doctor_id": doc_id,
            "patient_id": pat_id,
            "encrypted_record": str(encr_record, "utf-8")
        }

        rec_signature = sign_document(record, pat_id)

        payload["signature"] = rec_signature


        # payload contains (encr_record, doc_id, patiend_id)
        # sign payload using patient's private key
        # Upon adding block confirm that the patient is authenticated by confirming the signature
        # we have the patient id, get public key from db
        # signature confirmed using the public key of the patient

        # When doctor logs in he has id
        # block in block chain has plain text doctor_id
        # if doctor id of block matches doctor's id
        # patient id is part of original payload before verifying signature
        # once the signature is verified at time of mining of block
        # we can remove the patient id from the block before it is added to block chain

        # The record is encrypted using doctor's public key
        # Doctor can decrypt it using his private key
        # only that doctor has his private key so the record is confidential

        patient = get_patient_by_id(db_conn, pat_id)
        doctors = get_all_doctors(db_conn)
        # insert_linked(db_conn, data)
        # symptom = request.form['symptoms']
        # doc_signature = sign_document(symptom)
        # post_object = {
        #     "author": pat_id,
        #     "signature": doc_signature,
        #     "content": symptom,
        # }

        # Submit a new transaction.
        new_tx_address = "{0}/new_transaction".format(CONNECTED_NODE_ADDRESS)
        requests.post(new_tx_address, json=payload, headers={
            "Content-type": "application/json"})

        return render_template('patient.html', title='BlockChain', subtitle='Patient', patient=patient, doctors=doctors)


@app.route('/doctor', methods=['GET'])
def doctor():
    get_chain_address = "{0}/chain".format(CONNECTED_NODE_ADDRESS)
    doc_posts = []
    db_conn = get_db_conn()
    response = requests.get(get_chain_address)
    chain = json.loads(response.content.decode("utf-8"))
    id = request.args['id']    
    if response.status_code == 200:
        content = []
        chain = json.loads(response.content.decode("utf-8"))
        for block in chain["chain"]:
            for tx in block["transactions"]:
                tx["index"] = block["index"]
                tx["hash"] = block["previous_hash"]
                if str(tx["doctor_id"]) ==  id:
                    tx["record"] = str(decrypt_document(tx, id), "utf-8")
                    tx["patient_info"] = get_patient_by_id(db_conn, tx["patient_id"]) 
                    content.append(tx)
        doc_posts = sorted(content, key=lambda k: k["timestamp"], reverse=True)
    
   
    doctor = get_doctor_by_id(db_conn, id)
    print(doc_posts)
    return render_template('doctor.html', title='BlockChain', subtitle='Doctor', doctor=doctor, data=doc_posts)

@app.route('/audit_logs', methods=['GET'])
def get_audit_logs():
    db_conn = get_db_conn()
    rows = get_audit_trail(db_conn)
    print(rows)
    

@app.route('/db')
def db_setup():
    db_conn = get_db_conn()
    # drop_table(db_conn, 'patients')
    # drop_table(db_conn, 'doctors')
    # drop_table(db_conn, 'linked')
    # create_tables(db_conn)
    doctors = get_all_doctors(db_conn)
    patients = get_all_patients(db_conn)
    linked = get_all_linked(db_conn)
    return jsonify({'doctors': doctors, 'patients': patients, 'linked': linked})
