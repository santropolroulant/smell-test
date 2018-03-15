from smell_test import valid_ip

def test_valid_ip():
    assert valid_ip('192.168.0.1') == True
    assert valid_ip('Random garbage') == False
