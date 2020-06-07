#!/usr/bin/env python3


import datetime
import json

import app.rsa as rsa
import app.db_utils

import requests
from flask import render_template, redirect, request

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


def sign_document(message):
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
	path = os.getcwd() + "/data/private_key" + "/private_key_doc_0001.pem"
	with open(path, "r") as myfile:
		private_key = RSA.importKey(myfile.read())
	signature = b64encode(rsa.sign(message.encode('utf-8'), private_key, "SHA-256"))

	return signature.decode()

# Gets the data from node's /chain endpoint, parses the data, and stores it locally.


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

# Creates a new endpoint, and binds the function to the URL.


@app.route("/")
# Renders the index.html (home page).
def index():
    fetch_posts()
    return render_template("index.html",
                           title="Medictron",
                           subtitle="A Decentralized Network for Medical Records Sharing",
                           posts=posts,
                           node_address=CONNECTED_NODE_ADDRESS,
                           readable_time=timestamp_to_string)

# Creates a new endpoint, and binds the function to the URL.


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
    return redirect("/")

# Converts a timestamp (in UNIX time) to a string.


def timestamp_to_string(unix_time):
    return datetime.datetime.fromtimestamp(unix_time).strftime("%H:%M")
