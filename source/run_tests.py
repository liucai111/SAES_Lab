"""Run meaningful unittest checks and save machine-readable evidence."""
import io
import json
import platform
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent


class RecordingResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []

    def startTest(self, test):
        self.started = time.perf_counter()
        super().startTest(test)

    def stopTest(self, test):
        failed_ids = {item.id() for item, _ in self.failures + self.errors}
        self.records.append({'id': test.id(), 'status': 'failed' if test.id() in failed_ids else 'passed',
                             'elapsed_seconds': round(time.perf_counter() - self.started, 6)})
        super().stopTest(test)


def main():
    results = ROOT.parent / 'test_results'
    results.mkdir(exist_ok=True)
    started = time.perf_counter()
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), top_level_dir=str(ROOT))
    stream = io.StringIO()
    run = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=RecordingResult).run(suite)
    log = stream.getvalue()
    (results / 'unittest.log').write_text(log, encoding='utf-8')
    result = {'generated_at_utc': datetime.now(timezone.utc).isoformat(), 'python': sys.version,
              'platform': platform.platform(), 'tests_run': run.testsRun,
              'failures': len(run.failures), 'errors': len(run.errors), 'skipped': len(run.skipped),
              'elapsed_seconds': round(time.perf_counter() - started, 6), 'tests': run.records,
              'native_windows_manual': 'pending: run on the submission computer; live Tk regression is recorded separately',
              'external_group_cross_test': 'pending: requires a different group implementation'}
    (results / 'test_results.json').write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(log)
    return 0 if run.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
