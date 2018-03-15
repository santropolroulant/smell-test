import platform
import os
from smell_test import valid_ip
from smell_test import cache_path

def test_valid_ip():
    assert valid_ip('192.168.0.1') == True
    assert valid_ip('Random garbage') == False

def test_cache_path():
    this_os = platform.system()
    if this_os == 'Linux':
        assert cache_path() == '~/.cache/smell-test/'
    elif this_os == 'Darwin':
        home = os.path.expanduser('~')
        path = home + '/Library/Application Support/smell-test/'
        assert cache_path() == path
    else:
        assert cache_path() == None
