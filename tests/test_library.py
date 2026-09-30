import json
from pathlib import Path
import tempfile
import unittest
from delivery_evidence_check import EvidenceError, create_manifest, load_manifest, verify_manifest


class LibraryTests(unittest.TestCase):
    def test_create_verify_roundtrip_does_not_mutate_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'notes.txt').write_text('Synthetic notes\n')
            manifest = create_manifest(root, ['notes.txt'])
            original = json.dumps(manifest)
            self.assertTrue(verify_manifest(manifest, root)['ok'])
            self.assertEqual(json.dumps(manifest), original)
            (root / 'notes.txt').write_text('Changed notes\n')
            self.assertFalse(verify_manifest(manifest, root)['ok'])

    def test_bad_json_types_produce_issues_without_reading_files(self):
        candidates = [None, True, 1, '', [], {}]
        base = {'schema_version': 1, 'files': [{'path': 'synthetic.txt', 'sha256': '0' * 64}]}
        for field in ('files', 'local_checks'):
            for value in candidates:
                with self.subTest(field=field, value=value):
                    report = verify_manifest({**base, field: value}, 'not-a-real-root')
                    self.assertFalse(report['ok'])
        for value in candidates:
            report = verify_manifest(value, 'not-a-real-root')
            self.assertFalse(report['ok'])

    def test_claim_schema_rejects_bad_results_duplicate_names_and_empty_proof(self):
        base = {'schema_version': 1, 'files': [{'path': 'synthetic.txt', 'sha256': '0' * 64}]}
        claims = [None, {}, {'name': 'review', 'result': [], 'evidence': []},
                  {'name': 'review', 'result': 'passed', 'evidence': []},
                  {'name': 'review', 'result': 'failed', 'evidence': [None]},
                  {'name': 'review', 'result': 'passed', 'evidence': ['synthetic.txt', 'synthetic.txt']}]
        for claim in claims:
            report = verify_manifest({**base, 'local_checks': [claim]}, 'not-a-real-root')
            self.assertFalse(report['ok'])
            self.assertEqual(report['files_checked'], 0)
        claim = {'name': 'review', 'result': 'not_run', 'evidence': []}
        self.assertFalse(verify_manifest({**base, 'local_checks': [claim, claim]}, '.')['ok'])

    def test_bad_file_json_raises_documented_exception(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'invalid.json'
            path.write_bytes(b'\xff')
            with self.assertRaises(EvidenceError):
                load_manifest(path)

    def test_create_rejects_empty_paths(self):
        with self.assertRaises(EvidenceError):
            create_manifest('.', [])
