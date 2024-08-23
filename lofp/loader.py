
from pathlib import Path
from typing import Optional

import json
import pytoml
import yaml

from .rule import ElasticRule, SigmaRule, SplunkRule, RuleTypes


CURRENT_DIR = Path(__file__).parent
ROOT_DIR = CURRENT_DIR.parent
ETC_DIR = CURRENT_DIR / 'etc'

ATTACK_URL_BASE = 'https://attack.mitre.org/techniques'
GH_URL_BASE = 'https://github.com'
RULE_MAP = {
    f'{GH_URL_BASE}/elastic/detection-rules': ElasticRule,
    f'{GH_URL_BASE}/splunk/security_content': SplunkRule,
    f'{GH_URL_BASE}/SigmaHQ/sigma': SigmaRule
}


class Loader:

    def __init__(self, repo: str, branch: str, rule_glob_pattern: str, *path: Path):
        self.repo_url = f'{GH_URL_BASE}/{repo}'
        self.branch = branch
        self.rule_glob_pattern = rule_glob_pattern
        self.rule_type = RULE_MAP[self.repo_url]
        self.repo_name = repo.split('/')[-1]
        self.rules = self.from_paths(*path)

    def relative_to_repo(self, path: Path) -> Path:
        parts = path.parts
        index = parts.index(self.repo_name)
        return Path(*parts[index + 1:])

    def from_path(self, path: Path) -> Optional[RuleTypes]:
        """Load a single file."""
        raw = path.read_text()
        try:
            if path.suffix == '.json':
                contents = json.loads(raw)
            elif path.suffix == '.toml':
                contents = pytoml.loads(raw)
            elif path.suffix in ('.yaml', '.yml'):
                contents = yaml.safe_load(raw)
            else:
                return
        except yaml.YAMLError as e:
            print(f'error loading: {path} - {e}:\n{raw}')
            return

        relative_path = self.relative_to_repo(path)
        rule = self.rule_type(path=relative_path, contents=contents, repo_url=self.repo_url,
                              branch=self.branch)
        return rule

    def from_paths(self, *paths: Path) -> list[RuleTypes]:
        """Load multiple files."""
        rules = []
        for path in paths:
            rules.extend(self.from_path(p) for p in path.rglob(self.rule_glob_pattern))
        return [r for r in rules if r]
