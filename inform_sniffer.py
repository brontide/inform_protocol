import base64
import json
import struct

import zlib
from Crypto.Cipher import AES
from binascii import a2b_hex
from flask import Flask, request, Response

from inform import *

from time import time

import requests
import sys

app = Flask(__name__)

real_url = 'http://unifi:8080/inform'
dev_key='F'*32

@app.route("/inform", methods=['POST'])
def inform():
    global dummy
    data = request.get_data()

    inform = Packet(from_packet=data, key=dev_key)
    print("FROM DEVICE: ", inform)
    #print(inform.payload_decoded)
    foo = json.loads(inform.payload_decoded)
    json.dump(foo,open('sniff-{}.json'.format(time()),'wt'),indent=4)

    out = requests.post(real_url, data=data)
    raw_reply = out.content
    #print(type(raw_reply))

    reply = Packet(from_packet=raw_reply, key=dev_key)

    print("REPLY: ", reply.payload_decoded)

    return raw_reply



#mca-ctrl -t connect -s "http://10.0.8.2:8080/inform" 

def print_help():
    print('''
python inform_sniffer.py <real_inform_url> <management_key>

  Replace <real_inform_url> with your controller address
  Replace <management_key> with the 32 character pairing key
''')

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print_help()
        exit(-1)
    
    real_url = sys.argv[1]
    dev_key = sys.argv[2]

    if len(dev_key) != 32:
        print(f"{dev_key} doesn't looks like a proper key, should be 32 characters long")
        exit(-1)

    print(f"Decoding with KEY: {dev_key} and forwarding to {real_url}")

    app.run(debug=False, port=18080, host='0.0.0.0')
