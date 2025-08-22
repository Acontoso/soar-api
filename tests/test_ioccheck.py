import unittest
from application.services.ioccheck import ioc_type_finder

class TestIocTypeFinder(unittest.TestCase):
    def test_sha256(self):
        self.assertEqual(ioc_type_finder('a'*64), 'SHA256')

    def test_md5(self):
        self.assertEqual(ioc_type_finder('a'*32), 'MD5')

    def test_sha1(self):
        self.assertEqual(ioc_type_finder('a'*40), 'SHA1')

    def test_ipv4(self):
        self.assertEqual(ioc_type_finder('8.8.8.8'), 'IPv4')
        self.assertEqual(ioc_type_finder('192.168.1.1'), 'IPv4')

    def test_ipv6(self):
        self.assertEqual(ioc_type_finder('2001:0db8:85a3:0000:0000:8a2e:0370:7334'), 'IPv6')

    def test_domain(self):
        self.assertEqual(ioc_type_finder('example.com'), 'Domain')
        self.assertEqual(ioc_type_finder('sub.example.co.uk'), 'Domain')

    def test_default_domain(self):
        self.assertEqual(ioc_type_finder('notanindicator'), 'Domain')

if __name__ == '__main__':
    unittest.main()
