#!/usr/bin/env python3
"""Synthetic analyzer unit tests only; never opens SSH, sockets, polkit or BPF."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('reload_vm', Path(__file__).with_name('linux-appfilter-reload-vm.py'))
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class ReceiptChecks(unittest.TestCase):
    def setUp(self):
        self.hashes = [str(i) * 64 for i in range(1, 5)]
        self.rows = [{'event': 'policy_activated', 'gen': n, 'policy': self.hashes[n - 1],
                      'old_policy': self.hashes[n - 2], 'new_policy': self.hashes[n - 1]} for n in range(2, 5)]
        self.rows += [{'event': 'kernel_drop', 'gen': n, 'detail': f'tgid=99 kernel_monotonic_ns={n * 10 + 1}'} for n in range(1, 5)]
        self.windows = [(n, n * 10, n * 10 + 5) for n in range(1, 5)]

    def test_consistent_generations_and_activation_hashes(self):
        vm.validate_activations(self.rows, self.hashes)
        vm.validate_windows(self.rows, self.windows, 99, 4)

    def test_missing_duplicate_and_mismatched_activation(self):
        for rows in [self.rows[1:], self.rows + [self.rows[0]], copy.deepcopy(self.rows)]:
            if len(rows) == len(self.rows): rows[0]['new_policy'] = '0' * 64
            with self.assertRaises(RuntimeError): vm.validate_activations(rows, self.hashes)

    def test_old_events_must_not_be_relabeled_with_current_generation(self):
        self.rows[-1]['gen'] = 1
        with self.assertRaisesRegex(RuntimeError, 'different generation'):
            vm.validate_windows(self.rows, self.windows, 99, 4)

    def test_no_false_pass_without_observations_or_on_loss(self):
        with self.assertRaises(RuntimeError): vm.validate_activations([], self.hashes)
        with self.assertRaises(RuntimeError): vm.validate_windows([], self.windows, 99, 0)
        with self.assertRaises(RuntimeError): vm.validate_windows(self.rows, self.windows, 99, 5)
        self.rows.append({'event': 'receipt_loss', 'dropped': 1})
        with self.assertRaisesRegex(RuntimeError, 'receipt loss'): vm.validate_activations(self.rows, self.hashes)

    def test_state_digest_offset_and_untrusted_bpftool_bytes(self):
        data = bytes(range(48))
        self.assertEqual(vm.state_hash({'value': [f'{x:02x}' for x in data]}), data[16:48].hex())
        for value in [[], ['zz'], [256], 'not a byte array']:
            with self.assertRaises(RuntimeError): vm.state_hash({'value': value})

    def test_https_counts_verdicts_and_policy_generation_pairs(self):
        configs, records, attempts = [], [], []
        for gen in range(1, 5):
            allowed = ['example.com', 'github.com'] if gen == 2 else ['example.com']
            policy = {'version': 'blackice.policy/v0', 'network': {'mode': 'allowlist', 'allow': allowed}}
            digest = hashlib.sha256(json.dumps(policy, separators=(',', ':')).encode()).hexdigest()
            configs.append({'applications': [{'executable': '/launcher', 'policy': policy}]})
            for host in ('example.com', 'github.com'):
                yes = host in allowed
                records.append({'event': 'connect', 'app_id': 1, 'gen': gen, 'policy': digest, 'host': host,
                                'verdict': 'allow' if yes else 'deny', 'reason': 'allowed_domain' if yes else 'no_matching_rule'})
                attempts.append({'http_status': 200 if yes else None})
        result = vm.validate_web(records, attempts, 99, 1, configs, '/launcher')
        self.assertEqual(result['attempts'], 8)
        self.assertEqual(result['http_responses'], 5)
        for mutation in ('missing', 'duplicate', 'wrong_hash', 'wrong_allow', 'allowed_while_paused'):
            rows = copy.deepcopy(records)
            if mutation == 'missing': rows.pop()
            if mutation == 'duplicate': rows.append(rows[0])
            if mutation == 'wrong_hash': rows[0]['policy'] = '0' * 64
            if mutation == 'wrong_allow': rows[-1]['verdict'] = 'allow'
            if mutation == 'allowed_while_paused': rows[0]['reason'] = 'policy_change_in_progress'
            with self.assertRaises(RuntimeError): vm.validate_web(rows, attempts, 99, 1, configs, '/launcher')

    def test_https_request_during_a_change_is_a_named_refusal(self):
        policy = {'version': 'blackice.policy/v0', 'network': {'mode': 'allowlist', 'allow': ['example.com', 'github.com']}}
        digest = hashlib.sha256(json.dumps(policy, separators=(',', ':')).encode()).hexdigest()
        configs = [{'applications': [{'executable': '/launcher', 'policy': policy}]}] * 4
        records = [{'event': 'connect', 'app_id': 1, 'gen': gen, 'policy': digest, 'host': host, 'verdict': 'allow',
                    'reason': 'allowed_domain'} for gen in range(1, 5) for host in ('example.com', 'github.com')]
        attempts = [{'http_status': 200} for _ in records]
        records.append({'event': 'connect', 'app_id': 1, 'gen': 2, 'policy': digest, 'host': 'example.com',
                        'verdict': 'deny', 'reason': 'policy_change_in_progress'})
        attempts.append({'http_status': None})
        self.assertEqual(vm.validate_web(records, attempts, 99, 1, configs, '/launcher')['proxy_decisions'], 9)


if __name__ == '__main__':
    unittest.main(verbosity=2)
