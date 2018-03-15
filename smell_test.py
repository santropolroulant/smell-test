#!/usr/bin/env python3

import subprocess
import socket
import os
import platform
import time
import json
import glob
from sys import exit
from functools import lru_cache
from multiprocessing import Pool

# TODO: the below doensn't actually work on Debian. Needs fixing
# look for the Debian package name
try:
    import scapy3k as scapy
except ImportError:
    import scapy
#TODO only import what we need: `sniff` (what else?)
from scapy.all import *
import xdg.BaseDirectory
import click

# Change this to whatever interface you are interested in
# TODO: Change this to a command line argument to the script
interface = ''
filter_bpf = 'udp and port 53'

# Max size value chosen here is arbitrary. Change it if you want.
@lru_cache(maxsize=100)
def in_cache(cname):
    """Search `cache_path` for JSON files with names containing `cname`
    If found, return True. Otherwise, return False.
    """
    path_to_cache = cache_path()
    reports = glob(path_to_cache + '*.json')
    for r in reports:
        if cname in r:
            return True
    return False

def valid_ip(address):
    """Validate whether `address` is in valid IPv4 by calling the C class
    and checking its return value
    """
    try: 
        socket.inet_aton(address)
        return True
    except:
        return False

def cache_path():
    """Return the cache path according to what OS this script is run on.
    This script follows the XDG spec (i.e. the path is `~/.cache/smell-test/`):
    (https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html)
    For OS X the path is `~/Library/Application Support/smell-test/`.
    Windows is not supported for now but the equivalent is APPDATA, I believe
    """
    this_os = platform.system()
    if this_os == 'Linux':
        # thie function checks that $XDG_CACHE_HOME exists and returns the path
        path = xdg.BaseDirectory.save_cache_path('smell-test/')
    elif this_os == 'Darwin':
        # resolve user's home directory
        home = os.path.expanduser('~')
        path = home + '/Library/Application Support/smell-test/'
        if not os.path.exists(path): 
            try:
                os.makedirs(path)
            except IOError as e:
                if e.errno == errno.EACCES:
                    print("Cannot create {} due to insufficient permissions.".format(path))
                    return None
                # Not a permission error.
                raise
    else:
        return None
    return path

def generate_report(name, ip_addr):
    """Prepare the flags/arguments for testssl and create a subprocess
       calling the testssl.sh executable. Results are written
       to an output file. Format `dir/www.example.com_20180307-164136.json`
       Returns the path to the json file created.
    """
    # Prepare array of arguments to be passed to subprocess
    args = []

    # change this value if you move testssl for whatever reason
    path_to_executable = './testssl.sh/testssl.sh'

    # make sure we have no troubles writing to files
    log_dir = cache_path()
    log_path = log_dir + name + '_' + time.strftime("%Y%m%d-%H%M%S") + '.json'

    # adjust this according to your level of paranoia
    # good values are HIGH and CRITICAL
    severity = 'HIGH' 

    # This must be a string because it's a command line argument
    timeout_in_seconds = '20'

    # subprocess expects a flat array; flags with arguments 
    #       must be separated into their own elements
    flags = [
            '--vulnerable', # check for vulnerabilties
            '--warnings', # testssl.sh will still warn you if there will be a "drastic impact"
            'off',
            '--openssl-timeout', # TODO: instead of timeout, don't run this on HTTP w/out TLS
            timeout_in_seconds,
            '--severity',
            severity,
            '--quiet', # leave fewer traces
            '--sneaky',
            '--nodns', # we are already doing a DNS lookup in the first place
            '-oJ', # outputs results to a .json file in log_path
            log_path
    ]
    args.append(path_to_executable)
    for f in flags: args.append(f)
    args.append(ip_addr)

    # Create testssl fork using subprocess and capture the output
    # The execept statement will catch and display errors from testssl
    try:
        output = subprocess.check_output(args)
        return log_path
    except subprocess.CalledProcessError as e:
        output = e.output
        print("[-] ERROR: TestSSL did not execute successfully: " + output)
        return None

    print(output)

# TODO: Create more granular grading criteria
def grade_https(name, ip):
    """Takes as input a website name and its IP and returns a grading.
    The grade represents a simplified evaluation of SSL/TLS security
    based on the output of testssl.sh
    Exact criteria will be decided later. For now we will give sites with
    vulnerabilties ranking HIGH|CRITICAL a "Fail" and others a "Pass"
    """
    # generate report and get the path
    print ('[+] Evaluating ' + name)
    report_path = generate_report(name, ip)
    if report_path is None: return  

    # parse json report file for grade info
    summary = {}
    with open(report_path, 'r') as fh:
        data = json.load(fh)
    for vuln in data['scanResult'][0]['vulnerabilities']:
        if vuln['severity'] in summary:
            summary[vuln['severity']] += 1
        else:
            summary[vuln['severity']] = 1

    # If the summary contains anything (and therefore evaluates to True),
    # a vulnerability of at least severity `severity` has been found.
    # Anything else will have been ignored by testssl and not written into the JSON
    # (For now this value is hard-coded as 'HIGH')
    if summary:
        print("[!] {} is vulnerable. testssl found:".format(name))
        for key in summary:
            print("\t{} vulnerabilities of {} severity".format(summary[key], key))
        print("\tCheck {} for further details".format(report_path))

# this function gets called on all packets that match the sniffer filter
def select_DNS(pkt):
    # we're only interested in DNS response records
    if not (DNSRR in pkt and pkt.sport == 53): return

    # assume DNS records will give us ASCII results. look into this later
    name = pkt[DNSQR].qname.decode("ascii").lower() # user asked for this
    answer = pkt[DNSRR].rdata # corresponding response

    # sometimes DNS responses come with a trailing period. normalize the name.
    if name.endswith('.'): name = name[:-1]
    
    # don't evaluate sites when they're in the cache
    if in_cache(name): return

    # ignore reverse DNS 
    if 'in-addr' in name: return

    # only validate the 'ultimate' DNS result i.e. not aliases
    if not valid_ip(answer): return

    timeout = 60  # Change this to a command line or config option
    pool = Pool(processes=4)
    result = pool.apply_async(grade_https, [name, answer])
    #try:
    #    print(result.get(timeout=60))
    #except TimeoutError:
    #    print("[-] The grading process exceeded the time limit")
    #grade_https(name, answer)

@click.command()
def smell_test():
    print ('[**] Beginning "Smell Test"')
    try:
        sniff(iface=interface, filter=filter_bpf, store=0,  prn=select_DNS)
    except OSError as e:
        # note: this works on Linux but OS X segfaults when the interface is wrong lmao
        print('[-] ERROR: "{}". (Make sure `interface` matches your network interface)'.format(e))

if __name__ == '__main__':
    smell_test()


