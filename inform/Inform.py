# coding: utf-8
from struct import pack, unpack
from binascii import a2b_hex, b2a_hex

import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import pysnappy
import zlib

import requests


'''
Inform packet header: Big endian
    Magic string ( TNBU )
    packet_version ( 0 )
    MAC Address
    Flags
        bit 1 - is encrypted
        bit 2 - is zlib compressed
        bit 3 - is snappy compressed ( no longer used? )
        but 4 - encryption is GCM with the 40 byte header being AAD and the
                last 16 bytes the valudation tag
    IV/NONCE for encryption
    payload_version
    payload_length
'''
HEADER_FORMAT = "!4s I 6s H 16s I I"
MAGIC_STRING = b'TNBU'

''' Key that is used before they are fully managed '''
adopt_key = 'ba86f2bbe107c7c57eb5f2690775c712'

''' converts 6 bytes into string mac '''
def b2a_mac(mac_addr):
    if mac_addr == None: raise ValueError('Cannot convert Null to mac address')
    mac = unpack('!BBBBBB', mac_addr)
    mac_hex = [ "{:02x}".format(x) for x in mac ]
    return ':'.join(mac_hex)

''' converts string mac into 6 bytes '''
def a2b_mac(mac_addr):
    if mac_addr == None: return None
    mac = [ int(x,16) for x in mac_addr.split(':') ]
    return pack("!BBBBBB", *mac)

class Packet:
    raw_packet = None
    packet_version = 0
    mac_address = None
    flags = 0
    iv_nonce = None
    payload_version = 1
    payload_length = 0
    payload_encoded = None
    payload_decoded = None
    key = None
    try_adopt = True

    def __repr__(self):
        pr = "None"
        if self.raw_packet:
            pr = repr(self.raw_packet[:10])
        pe = "None"
        if self.payload_encoded:
            pe = repr(self.payload_encoded[:10])
        pd = "None"
        if self.payload_decoded:
            pd = repr(self.payload_decoded[:10])
        return f"""Inform packet {pr}: mac {self.mac_address}: flags {self.flags}: encoded: {pe} decode: {pd}""" 

    def __init__(self, **kwargs):
        self.key = kwargs.get('key', None)
        # Try the adoption key id none set
        self.try_adopt = kwargs.get('try_adopt', self.key==None)
        if "from_packet" in kwargs:
            self.raw_packet = kwargs['from_packet']
            self.decode(errors_fatal=kwargs.get('errors_fatal', False))
            return
        self.mac_address = kwargs.get('mac_address', None)
        self.flags = kwargs.get('flags', 0)
        self.payload_decoded = kwargs.get('payload_decoded', None)

    def encode(self):
        # convert to a bytestring
        payloadtemp = self.payload_decoded.encode('utf-8')

        if self.is_zlib:
            payloadtemp = zlib.compress(payloadtemp)
        if self.is_snappy:
            payloadtemp = pysnappy.compress(payloadtemp)

        len_payload = len(payloadtemp)

        self.iv_nonce = get_random_bytes(16)
        # prep the cipher and get the nonce/iv
        if self.is_gcm:
            cipher = AES.new(a2b_hex(self.key), AES.MODE_GCM, nonce=self.iv_nonce)
            len_payload = len(payloadtemp) + 16 # room for tag
        if self.is_encrypted and not self.is_gcm:
            payloadtemp = pad(payloadtemp,16)
            cipher = AES.new(a2b_hex(self.key), AES.MODE_CBC, iv=self.iv_nonce)
            len_payload = len(payloadtemp) 

        #build the header
        header = pack(HEADER_FORMAT, MAGIC_STRING, self.packet_version, 
                        a2b_mac(self.mac_address), self.flags, self.iv_nonce,
                        self.payload_version, len_payload)

        # apply encryption
        if self.is_gcm:
            cipher.update(header)
            payloadtemp, tag = cipher.encrypt_and_digest(payloadtemp)
            payloadtemp += tag
        if self.is_encrypted and not self.is_gcm:
            payloadtemp = cipher.encrypt(payloadtemp)
        
        # save and return
        self.payload_encoded = payloadtemp
        self.raw_packet = header+payloadtemp
        return self.raw_packet

    def decode(self, errors_fatal=True):
        len_raw = len(self.raw_packet)
        if len_raw < 40:
            raise ValueError("raw_packet is smaller than 40 bytes, cannot decode")
        (magic, version, hwAddr, flags, iv, payload_version, payload_length) = unpack(HEADER_FORMAT, self.raw_packet[:40])
        if magic != MAGIC_STRING:
            raise ValueError(f"Magic string expected {MAGIC_STRING}: received {magic}")
        if len_raw != 40+payload_length:
            raise ValueError(f"raw_packet length {len_raw} != 40 + {payload_len}")
        if version != 0:
            raise ValueError(f"I don't know how to handle version {version}")
        if payload_version != 1:
            raise ValueError(f"I don't know how to handle payload version {payload_version}")
        #
        # Okay, assign to self
        #
        self.packet_version = version
        self.mac_address = b2a_mac(hwAddr)
        self.flags = flags
        self.iv_nonce = iv
        self.payload_version = payload_version
        self.payload_length = payload_length
        self.payload_encoded = self.raw_packet[40:]
        inprogress = self.payload_encoded

        try:
            key = self.key
            if not key and self.try_adopt:
                key = adopt_key
            key = a2b_hex(key) # as binary
            if self.is_encrypted:
                # decode the paylaod
                if self.is_gcm:
                    cipher = AES.new(key, AES.MODE_GCM, nonce=self.iv_nonce)
                    cipher.update(self.raw_packet[:40]) # validate header too
                    inprogress = cipher.decrypt_and_verify(
                            self.payload_encoded[:-16],self.payload_encoded[-16:])
                else:
                    cipher = AES.new(key, AES.MODE_CBC, iv=self.iv_nonce)
                    inprogress = cipher.decrypt(self.payload_encoded)

            if self.is_zlib:
                inprogress = zlib.decompress(inprogress)
            
            if self.is_snappy:
                inprogress = pysnappy.uncompress(inprogress)

            self.payload_decoded = inprogress.decode('utf-8')
        except Exception as e:
            if errors_fatal:
                raise
            else:
                return False
        return True

    def send(self, url):
        if not self.payload_encoded or not self.raw_packet:
            self.encode()
        out = requests.post(url, data=self.raw_packet)
        try:
            out.raise_for_status()
        except:
            return None

        return Packet(key=self.key, from_packet=out.content)

    ''' Is AES_CBC '''
    @property
    def is_encrypted(self):
        return ( self.flags & 1 ) != 0

    ''' Is zlib '''
    @property
    def is_zlib(self):
        return (self.flags & 2 ) != 0 

    ''' Is Snappy: this compression seems to be depricated '''
    @property
    def is_snappy(self):
        return (self.flags & 4 ) != 0

    ''' Is GCM encrtpyed, this can validate the whole packet not just the payload '''
    @property
    def is_gcm(self):
        return (self.flags & 8 ) != 0

