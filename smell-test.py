#!/usr/bin/env python

from scapy.all import *
import socket
import os
import time

# change this to whatever interface you are interested in
interface = 'eno1'
filter_bpf = 'udp and port 53'
cache = []

# TODO: this caching could be more robust...
def add_cname_to_cache(cname):
    cache.append(cname)

def in_cache(cname):
    return cname in cache


def valid_ip(address):
    try: 
        socket.inet_aton(address)
        return True
    except:
        return False

def generate_testssl_report(host):
    """Prepare the bash command and
    execute with $host as the target.
    Creates a .json file in the directory
    """
    severity = 'HIGH'
    log_dir = 'results/'
    # dir/www.example.com_20180307-164136.json
    log_path = log_dir + host + '_' + time.strftime("%Y%m%d-%H%M%S") + '.json'
    print ('[**] Evaluating ' + host)
    # TODO: Add --nodns flag when host is an IPv4 address
    flags = ' '.join([
            '--vulnerable',
            '--severity ' + severity,
            '--quiet',
            '--sneaky',
            '-oJ ' + log_path
    ])
    script_path = './testssl.sh/testssl.sh'
    cmd = " ".join([script_path, flags, host])
    print ("[DEBUG] Executing " + cmd)
    #TODO: Add threading(?) so that we don't wait on this command
    os.system(cmd)
    return log_path

def grade_https(name, answer):
    # sometimes DNS responses come with a trailing period :(
    if name.endswith('.'): name = name[:-1]
    # generate report and get the path
    report = generate_testssl_report(name)
    print ("[**] Report generated: " + report)

# this function gets called on all packets that match the sniffer filter
def select_DNS(pkt):
    try:
        if DNSRR in pkt and pkt.sport == 53:
            name = pkt[DNSQR].qname # user asked for this
            answer = pkt[DNSRR].rdata # corresponding IP

            print ('[*] User asked for "{}" DNS responded "{}"'.format(name, answer))
            if in_cache(name): 
                print ('[-] {} is in the cache. Grading will be skipped'.format(name))
            elif 'in-addr' in name:
                print ('[-] Ignoring reverse DNS query')
            else:
                # print response body, for now
                grade_https(name, answer)

                add_cname_to_cache(name)
    except Exception, e:
        print(e)

print ('[**] Beginning smell test')
sniff(iface=interface, filter=filter_bpf, store=0,  prn=select_DNS)
