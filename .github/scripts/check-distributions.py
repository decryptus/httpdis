"""Validate metadata and package completeness before release (Python 3)."""
from pathlib import Path
from email.parser import Parser
import tarfile
import zipfile
import yaml

root = Path(__file__).resolve().parents[2]
config = yaml.safe_load((root / 'setup.yml').read_text())
name, version = config['name'], config['version']
assert version == config['release'] == (root/'VERSION').read_text().strip() == (root/'RELEASE').read_text().strip()
assert len(list((root/'dist').iterdir())) == 2
wheel, = (root/'dist').glob('*.whl')
sdist, = (root/'dist').glob('*.tar.gz')
with zipfile.ZipFile(str(wheel)) as archive:
    metadata, = [p for p in archive.namelist() if p.endswith('.dist-info/METADATA')]
    parsed = Parser().parsestr(archive.read(metadata).decode())
    assert parsed['Name'] == name and parsed['Version'] == version
    assert '>=2.7' in parsed['Requires-Python']
    for path in (root/name).rglob('*.py'):
        relative = path.relative_to(root).as_posix()
        assert archive.read(relative) == path.read_bytes(), relative
with tarfile.open(str(sdist)) as archive:
    paths = set(member.name.split('/', 1)[-1] for member in archive.getmembers())
    assert {'setup.py', 'setup.yml', 'requirements.txt', 'README.md', 'VERSION', 'RELEASE', 'pyproject.toml'} <= paths
print('Validated', name, version)
