# Python3 SSL certificate checker ver 1.0
# created by Kevin Tan
# Automate your job means more free time!
#!usr/bin/env python3
from OpenSSL import SSL 
from cryptography import x509
from cryptography.x509.oid import NameOID
import idna
from socket import socket
import concurrent.futures
from collections import namedtuple
from datetime import datetime
from colorama import Fore, Style

#important vars
HostInfo = namedtuple(field_names='cert hostname peername', typename='HostInfo')
ssl_port = 443
host_list=[]
today = datetime.now().date()

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
        ctx = SSL.Context(SSL.SSLv23_METHOD) # most compatible
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
        print(Style.BRIGHT)
        print(Fore.MAGENTA+"\n» connection error for hostname: " + host + "\n")
        print(Style.RESET_ALL)
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


def print_basic_info(hostinfo):
    try:
        s = '''» {hostname} « … {peername}
        \tcommonName: {commonname}
        \tSAN: {SAN}
        \tissuer: {issuer}
        \tCertificationStarted: {notbefore}
        \tCertificationEnd:  {notafter}
        '''.format(
                hostname=hostinfo.hostname,
                peername=hostinfo.peername,
                commonname=get_common_name(hostinfo.cert),
                SAN=get_alt_names(hostinfo.cert),
                issuer=get_issuer(hostinfo.cert),
                notbefore=hostinfo.cert.not_valid_before,
                notafter=hostinfo.cert.not_valid_after
        )
        time_delta = hostinfo.cert.not_valid_after.date() - today
        time_text = "Days Left : " + str(time_delta.days) + "days"
        
        if time_delta.days < 0:
            print(Style.BRIGHT)
            print(Fore.RED + "\n" + s + "\t" + time_text + "\n")
            print(Style.RESET_ALL)
        elif time_delta.days < 60:
            print(Style.BRIGHT)
            print(Fore.YELLOW + "\n" + s + "\t" + time_text + "\n")
            print(Style.RESET_ALL)
        else:
            print("\n" + s + "\t" + time_text + "\n")

    except:
        return None

def check_it_out(hostname, port):
    hostinfo = get_certificate(hostname, port)
    print_basic_info(hostinfo)


if __name__ == '__main__':
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as e: 
        for hostinfo in e.map(lambda x: cert_get(x[0], x[1]), host_list):
            print_basic_info(hostinfo)