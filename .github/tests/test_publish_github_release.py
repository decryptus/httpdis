"""Release repair must use artifacts from the immutable published tag."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'publish-github-release.sh'
FAKE_GH = '''#!/usr/bin/env python3
import json,os,pathlib,sys
args=sys.argv[1:]
with open(os.environ['CALLS'],'a') as stream:stream.write(json.dumps(args)+'\\n')
if args[:2]==['release','view']:sys.exit(0 if os.environ.get('EXISTS')=='1' else 1)
if args[:2]==['release','create']:sys.exit(0)
if args[:2]==['run','download']:
 root=pathlib.Path(args[args.index('--dir')+1])
 (root/'httpdis-0.3.59.whl').write_text('original wheel')
 (root/'httpdis-0.3.59.tar.gz').write_text('original source')
 sys.exit(0)
if args[0]=='api':
 url=args[1]
 if 'workflows' in url:print('42')
 elif '/jobs?' in url:print(os.environ.get('PUBLISHED','1'))
 else:print(os.environ['TAG_SHA'])
 sys.exit(0)
sys.exit(2)
'''


class GitHubReleaseTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.git('init','-q');self.git('config','user.email','tests@example.invalid');self.git('config','user.name','Tests')
        (self.root/'source').write_text('original')
        self.git('add','source');self.git('commit','-qm','Original package')
        self.tag_sha=self.git('rev-parse','HEAD').strip();self.git('tag','v0.3.59')
        self.git('commit','--allow-empty','-qm','Docs repair')
        (self.root/'docs').mkdir();(self.root/'docs/release-0.3.59.md').write_text('Release notes')
        binary=self.root/'bin';binary.mkdir();(binary/'gh').write_text(FAKE_GH);(binary/'gh').chmod(0o755)
        self.calls=self.root/'calls'
        self.env=dict(os.environ,PATH=str(binary)+os.pathsep+os.environ['PATH'],TAG='v0.3.59',
                      GITHUB_REPOSITORY='test/project',GITHUB_SHA=self.git('rev-parse','HEAD').strip(),
                      GITHUB_RUN_ID='99',TAG_SHA=self.tag_sha,CALLS=str(self.calls))

    def git(self,*args):
        return subprocess.check_output(['git',*args],cwd=self.root,text=True)

    def run_script(self,**changes):
        return subprocess.run(['bash',str(SCRIPT)],cwd=self.root,env=dict(self.env,**changes),capture_output=True,text=True)

    def commands(self):
        return [json.loads(line) for line in self.calls.read_text().splitlines()] if self.calls.exists() else []

    def test_repair_downloads_original_published_run_not_current_build(self):
        result=self.run_script();self.assertEqual(result.returncode,0,result.stderr)
        downloads=[x for x in self.commands() if x[:2]==['run','download']]
        self.assertEqual(downloads[0][2],'42')
        self.assertTrue(any(x[:2]==['release','create'] and '--verify-tag' in x for x in self.commands()))

    def test_existing_release_is_never_overwritten(self):
        self.assertEqual(self.run_script(EXISTS='1').returncode,0)
        self.assertEqual(len(self.commands()),1)

    def test_missing_notes_fail_before_network_or_publication(self):
        (self.root/'docs/release-0.3.59.md').unlink()
        self.assertNotEqual(self.run_script().returncode,0)
        self.assertEqual(self.commands(),[])

    def test_failed_or_unrelated_publication_cannot_supply_artifacts(self):
        for changes in ({'PUBLISHED':'0'},{'TAG_SHA':'0'*40}):
            with self.subTest(changes=changes):
                if self.calls.exists():self.calls.unlink()
                self.assertNotEqual(self.run_script(**changes).returncode,0)
                self.assertFalse(any(x[0] in ('run','release') and x[1]!='view' for x in self.commands()))
