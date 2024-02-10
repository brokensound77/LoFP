
from collections import defaultdict
from pathlib import Path
from typing import Optional, Union

import json
import pytoml
import yaml

from .rule import ElasticRule, SigmaRule, SplunkRule


RuleTypes = Union[ElasticRule, SigmaRule, SplunkRule]
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
        if path.suffix == '.json':
            contents = json.loads(path.read_text())
        elif path.suffix == '.toml':
            contents = pytoml.loads(path.read_text())
        elif path.suffix == '.yaml':
            contents = yaml.safe_load(path.read_text())
        else:
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
        return rules


class RuleBundle:

    def __init__(self, loader: Loader):
        self.loader = loader

    def page_data(self) -> dict[str, dict]:
        output = defaultdict(dict)
        for rule in self.loader.rules:
            for fp in rule.false_positives:
                output[fp].setdefault('techniques', set())
                output[fp].setdefault('rules', {})
                output[fp]['techniques'].update(rule.techniques)
                output[fp]['rules'][rule.id] = rule

        for fp, entry in output.items():
            entry['techniques'] = sorted(entry['techniques'])
            entry['rules'] = list(entry['rules'].values())

        return output

    def page_format(self, false_psoitive: str, data: dict) -> str:
        techniques: list[str] = data['techniques']
        rules: list[RuleTypes] = data['rules']
        contents = [
            '---',
            f'title: "{false_psoitive}"',
            f'description: ""',
            'tags:'
            ]
        contents += [f'  - {t}' for t in techniques]
        contents += [
            '---',
            '',
            '## Techniques',
            '']
        contents += [f'- [{t}]({ATTACK_URL_BASE}/{t}/)' for t in techniques]
        contents += [
            '',
            '## Sample rules',
            '']
        contents += [r.to_markdown() for r in rules]

        return '\n'.join(contents)

    def write_page(self, false_positive: str, data: dict, directory: Path):
        formatted = self.page_format(false_positive, data)
        print(formatted)
        return formatted

    def write_pages(self, directory: Path):
        for fp, data in self.page_data().items():
            self.write_page(fp, data, directory)

