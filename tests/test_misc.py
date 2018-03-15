"""This file contains 'misc" tests for the smell_test.py script. This is a first-pass attempt at
getting some tests up and running; as this project goes, the name of this file should be made more
descriptive -- or, better yet, should be split into multiple test files grouped by function.
"""
import platform
import os

import xdg.BaseDirectory

from smell_test import valid_ip
from smell_test import cache_path

def test_valid_ip():
    """Makes sure that ipv4 addresses are accepted and everything else is rejected."""
    assert valid_ip('192.168.0.1') == True
    assert valid_ip('Random garbage') == False

def test_cache_path():
    """Tests the cache_path on a per-OS basis.  Anything not matchin Linux or Darwin is
    discarded.
    """
    this_os = platform.system()
    if this_os == 'Linux':
        assert cache_path() == xdg.BaseDirectory.save_cache_path('smell-test/')
    elif this_os == 'Darwin':
        home = os.path.expanduser('~')
        path = home + '/Library/Application Support/smell-test/'
        assert cache_path() == path
    else:
        assert cache_path() == None
