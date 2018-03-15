"""Smell Test is a script designed to monitor the DNS traffic on a specificied interface and grade
the TLS of the requested domains.  The relative health of each domain is recorded in JSON files
and the user will be warned when a domain is seriously vulnerable to a known attack.  The primary
use envisioned for this software involves sysadmins running this script on their networks and
notifying domain admins with offending configurations.  In this way, sysadmins can politely
notify one another when something is misconfigured.
"""

#!/usr/bin/env python3

import subprocess
import socket
import os
import platform
import time
import json
import glob
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


# Max size value chosen here is arbitrary. Change it if you want.
@lru_cache(maxsize=100)
def in_cache(cname):
    """Search `cache_path` for JSON files with names containing `cname`
    If found, return True. Otherwise, return False.
    """
    path_to_cache = cache_path()
    reports = glob(path_to_cache + '*.json')
    for report in reports:
        if cname in report:
            return True
    return False

def valid_ip(address):
    """Validate whether `address` is valid IPv4"""
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

def generate_report(name, ip_addr, timeout, severity):
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

    # subprocess expects a flat array; flags with arguments
    #       must be separated into their own elements
    flags = [
        '--vulnerable', # check for vulnerabilties
        '--warnings', # testssl.sh will still warn you if there will be a "drastic impact"
        'off',
        '--openssl-timeout', # TODO: instead of timeout, don't run this on HTTP w/out TLS
        str(timeout),   # Must be a string because it's a command-line argument
        '--severity',
        severity,
        '--quiet', # leave fewer traces
        '--sneaky',
        '--nodns', # we are already doing a DNS lookup in the first place
        '-oJ', # outputs results to a .json file in log_path
        log_path
    ]
    args.append(path_to_executable)
    for flag in flags: args.append(flag)
    args.append(ip_addr)

    """Create testssl fork using subprocess and capture the output. The execept statement will
    catch and display errors from testssl
    """
    try:
        output = subprocess.check_output(args)
        return log_path
    except subprocess.CalledProcessError as e:
        output = e.output
        print("[-] ERROR: TestSSL did not execute successfully: " + output)
        return None

    print(output)

# TODO: Create more granular grading criteria
def grade_https(name, ip_addr, timeout, severity):
    """Takes as input a website name and its IP and returns a grading.  The grade represents a
    simplified evaluation of SSL/TLS security based on the output of testssl.sh.  Exact criteria
    will be decided later.
    """
    # Generate report and get its path.
    print('[+] Evaluating {} ({})'.format(name, ip_addr))
    report_path = generate_report(name, ip_addr, timeout, severity)
    if report_path is None: return

    # Parse json report file for grade info.
    summary = {}
    with open(report_path, 'r') as file_handle:
        data = json.load(file_handle)
    for vuln in data['scanResult'][0]['vulnerabilities']:
        if vuln['severity'] in summary:
            summary[vuln['severity']] += 1
        else:
            summary[vuln['severity']] = 1

    """If the summary contains anything (and therefore evaluates to True), a vulnerability of at
    least severity `severity` has been found.  Anything else will have been ignored by testssl and 
    not written into the JSON.
    """
    if summary:
        print("[!] {} is vulnerable. testssl found:".format(name))
        for key in summary:
            print("\t{} vulnerabilities of {} severity".format(summary[key], key))
        print("\tCheck {} for further details".format(report_path))

def custom_action(timeout, severity):
    """Acts as a wrapper around `select_dns`.  This is the only way to pass arguments to custom
    functions using scapy.
    See [https://thepacketgeek.com/scapy-sniffing-with-custom-actions-part-2/] for more details.
    """

    def select_dns(pkt):
        """This is called on every packet sniffed by scapy.  After filtering for valid DNS packets,
        this function extracts the name and IP addr of the DNS requests and passes them along to
        the `grade_https` function.  The multiprocessing library is used for threading so that the
        program doesn't hang during grading individual sites.
        """
        # We're only interested in DNS response records
        if not (DNSRR in pkt and pkt.sport == 53):
            return

        # Assume DNS records will give us ASCII results. Look into this later.
        name = pkt[DNSQR].qname.decode("ascii").lower() # The system requested this CNAME.
        answer = pkt[DNSRR].rdata # Corresponding IPv4 address or alias for the queried name.

        # Sometimes DNS responses come with a trailing period. Normalize the name.
        if name.endswith('.'):
            name = name[:-1]

        # Don't evaluate sites when they're in the cache
        if in_cache(name):
            return

        # Ignore reverse DNS
        if 'in-addr' in name:
            return

        # Only validate the 'ultimate' DNS result i.e. not aliases
        if not valid_ip(answer):
            return

        pool = Pool(processes=4)
        pool.apply_async(grade_https, [name, answer, timeout, severity])
    return select_dns

@click.command()
@click.option(
    '--timeout',
    default=60,
    help="Time (seconds) to wait before giving up on connecting. Default is 60s."
)
# TODO: add validation on the input of severity levels
@click.option(
    '--severity',
    default='HIGH',
    help="Vulnerabilites levels to include in grading. Allowed are <LOW|MEDIUM|HIGH|CRITICAL>."
)
@click.argument('interface')
#@click.options('--interface', help='The network interface to sniff')
def smell_test(timeout, severity, interface):
    """Invokes the scapy sniff function and filters for DNS requests.  Matching packets are passed
    to the `select_dns` function for further validating and eventual grading.
    """
    filter_bpf = 'udp and port 53'
    print('[**] Beginning "Smell Test"')
    try:
        sniff(iface=interface, filter=filter_bpf, store=0, prn=custom_action(timeout,severity))
    except OSError as e:
        # This works on Linux but OS X segfaults when the interface is wrong lmao
        print('[-] ERROR: "{}". (Make sure `interface` matches your network interface)'.format(e))

if __name__ == '__main__':
    smell_test()
