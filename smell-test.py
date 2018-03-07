#!/usr/bin/env python

from scapy.all import *
import os

# change this to whatever interface you are interested in
interface = 'eno1'
filter_bpf = 'udp and port 53'
cache = []

# TODO: this caching could be more robust...
def add_cname_to_cache(cname):
    cache.append(cname)

def in_cache(cname):
    return cname in cache

def grade_https(name):
    # sometimes DNS responses come with a trailing period :(
    if name.endswith('.'): name = name[:-1]
    severity = 'HIGH'
    log_dir = 'results/'
    print ('[**] Evaluating ' + name)
    flags = ' '.join([
            '--vulnerable',
            '--severity ' + severity,
            '--quiet',
            '--sneaky',
            '--json-pretty',
    ])
    script_path = './testssl.sh/testssl.sh'
    cmd = " ".join([script_path, flags, name])
    #TODO: Add threading(?) so that we don't wait on this command
    os.system(cmd)

# this function gets called on all packets that match the sniffer filter
def select_DNS(pkt):
    try:
        if DNSRR in pkt and pkt.sport == 53:
            name = pkt[DNSQR].qname # user asked for this
            ip = pkt[DNSRR].rdata # corresponding IP

            print ('[*] User asked for "{}" DNS responded "{}"'.format(name, ip))
            if in_cache(name): 
                print ('[-] {} is in the cache. Grading will be skipped'.format(name))
            elif 'in-addr' in name:
                print ('[-] Ignoring reverse DNS query')
            else:
                # print response body, for now
                grade_https(name)
                add_cname_to_cache(name)
    except Exception, e:
        print(e)

print ('[**] Beginning smell test')
sniff(iface=interface, filter=filter_bpf, store=0,  prn=select_DNS)
