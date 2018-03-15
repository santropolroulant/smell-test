# Smell Test [![Build Status](https://travis-ci.org/santropolroulant/smell-test.svg?branch=master)](https://travis-ci.org/santropolroulant/smell-test)

Basic idea: run this script on a router and sniff DNS requests using scapy3k.

Run testssl.sh on these domains and log the results

Compile a list of the worst offenders for analysis.

Contact domain admins so that they can update their security

## Installation

Clone this repo and then use pip to install each of the libraries from requirements.txt

For now the script must be run using sudo in order to analyse packets. This will be changed in the future (probably by using a designated group). See the [wireshark documentation](https://anonscm.debian.org/viewvc/collab-maint/ext-maint/wireshark/trunk/debian/README.Debian?view=markup) for more information.


