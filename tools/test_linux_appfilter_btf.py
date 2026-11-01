#!/usr/bin/env python3
"""Synthetic parser tests only: no host BTF reads and no BPF operations."""
from pathlib import Path
import importlib.util
import struct
import unittest
import sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('btf_parser', Path(__file__).with_name('linux-appfilter-btf.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def fixture(bit_offset=0):
    strings = b'\0counter\0atomic_t\0'
    types = struct.pack('<IIII', 0, 1 << 24, 4, 32)
    types += struct.pack('<IIIIII', 0, (4 << 24) | 1, 4, 1, 1, bit_offset)
    types += struct.pack('<III', 9, 8 << 24, 2)
    return struct.pack('<HBBIIIII', 0xeb9f, 1, 0, 24, 0, len(types), len(types), len(strings)) + types + strings

class ParserTests(unittest.TestCase):
    def test_anonymous_typedef_field(self):
        self.assertEqual(module.BTF(fixture()).field('atomic_t', 'counter'), 0)
    def test_every_truncation_is_rejected(self):
        good = fixture()
        for n in range(len(good)):
            with self.assertRaises(ValueError):
                module.BTF(good[:n])
    def test_non_byte_field_and_missing_member(self):
        with self.assertRaises(ValueError):
            module.BTF(fixture(1)).field('atomic_t', 'counter')
        with self.assertRaises(ValueError):
            module.BTF(fixture()).field('atomic_t', 'missing')

if __name__ == '__main__':
    unittest.main()
