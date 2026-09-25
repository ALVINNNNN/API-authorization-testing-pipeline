"""Run live HTTP tests and write redacted JSON plus JUnit evidence."""
import argparse
import json
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from tests.test_authorization import EVIDENCE


class Result(unittest.TextTestResult):
    def startTest(self, test):
        super().startTest(test)
        self.rows = getattr(self, 'rows', [])
        self.rows.append({'test': test.id(), 'status': 'passed'})

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.rows[-1]['status'] = 'failed'
        self.rows[-1].setdefault('failure_http', []).append(EVIDENCE[-1] if EVIDENCE else {})

    def addError(self, test, err):
        super().addError(test, err)
        self.rows[-1]['status'] = 'error'

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err:
            self.rows[-1]['status'] = 'failed' if issubclass(err[0], test.failureException) else 'error'
            self.rows[-1].setdefault('failure_http', []).append(EVIDENCE[-1] if EVIDENCE else {})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    parser.add_argument('--test')
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.loadTestsFromName(
        'tests.test_authorization.AuthorizationTests' + ('.' + args.test if args.test else ''))
    result = unittest.TextTestRunner(verbosity=2, resultclass=Result).run(suite)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    report = {'tests': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors),
              'successful': result.wasSuccessful(), 'cases': getattr(result, 'rows', []),
              'http': EVIDENCE}
    (out / 'results.json').write_text(json.dumps(report, indent=2))
    root = ET.Element('testsuite', name='API authorization', tests=str(result.testsRun),
                      failures=str(len(result.failures)), errors=str(len(result.errors)))
    for row in report['cases']:
        node = ET.SubElement(root, 'testcase', name=row['test'])
        if row['status'] != 'passed':
            ET.SubElement(node, 'failure' if row['status'] == 'failed' else 'error',
                          message='See redacted HTTP evidence in results.json')
    ET.ElementTree(root).write(out / 'junit.xml', encoding='utf-8', xml_declaration=True)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
