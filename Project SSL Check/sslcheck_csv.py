# Python3 SSL certificate checker ver 1.0
# created by Kevin Tan
# Automate your job means more free time!
#!usr/bin/env python3
from OpenSSL import SSL 
from cryptography import x509
from cryptography.x509.oid import NameOID
from socket import socket
from collections import namedtuple
from datetime import datetime
import concurrent.futures
import csv
import idna
import os


#important vars
HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')
ssl_port = 443
host_list=[]
today = datetime.now().date()
filecsv = '201905-SSL.csv'

#open and read host file
host_file = open("host_list.txt")

with host_file as host_object:
    for hosts in host_object:
        host_list.append([hosts.rstrip("\n"),ssl_port])

def cert_verify(host, port):
    cert.has_expired()

def cert_get(host, port):
    host_idna = idna.encode(host)
    sock = socket()

    try:
        sock.settimeout(5)
        sock.connect((host, port))
        sock.settimeout(None)

        peername = sock.getpeername()
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        ctx.check_hostname = False
        ctx.verify_mode = SSL.VERIFY_NONE
    
        sock_ssl = SSL.Connection(ctx, sock)
        sock_ssl.set_connect_state()
        sock_ssl.set_tlsext_host_name(host_idna)
        sock_ssl.do_handshake()
        cert = sock_ssl.get_peer_certificate()
        crypto_cert = cert.to_cryptography()
        sock_ssl.close()
        sock.close()

        return HostInfo(cert=crypto_cert, peername=peername, hostname=host)
    except:
        if(os.path.isfile(filecsv)):
            file_csv = open(filecsv, 'a')
        else:
            file_csv = open(filecsv, 'w')
            row = "hostname" + "," + "Valid until" +"," + "Status" + '\n'
            file_csv.write(row)
     
        try:
            row = hostinfo.hostname + ","+ "N/A "+"," + "DISCONNECTED" + '\n'
            file_csv.write(row)
            file_csv.close()
        except:
            return None
        return None

def get_alt_names(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return None

def get_common_name(cert):
    try:
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None

def get_issuer(cert):
    try:
        names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value
    except x509.ExtensionNotFound:
        return None


def save_to_csv(hostinfo):

    #check file exist
    if(os.path.isfile(filecsv)):
        file_csv = open(filecsv, 'a')
    else:
        file_csv = open(filecsv, 'w')
        row = "hostname" + "," + "Valid until" +"," + "Status" + '\n'
        file_csv.write(row)
     
    try:
        row = hostinfo.hostname + "," + str(hostinfo.cert.not_valid_after) +"," + "OK" + '\n'
        file_csv.write(row)
        file_csv.close()
    except:
        return None

if __name__ == '__main__':
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e: 
        for hostinfo in e.map(lambda x: cert_get(x[0], x[1]), host_list):
            save_to_csv(hostinfo)
                     