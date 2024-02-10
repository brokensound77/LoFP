
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml


CURRENT_DIR = Path(__file__).parent.resolve()
ETC_DIR = CURRENT_DIR / 'etc'
ICON_DIR = ETC_DIR / 'icons'


@dataclass
class Rule:
    path: Path
    contents: dict
    repo_url: str
    branch: str

    @property
    def link(self) -> str:
        return f'{self.repo_url}/blob/{self.branch}/{self.path}'

    @property
    def rule_source(self) -> str:
        return self.__class__.__name__[:-4].lower()

    @property
    def icon_path(self) -> Path:
        raise NotImplementedError()

    @property
    def icon_link(self) -> str:
        return f'<img src="{self.path}" alt="{self.rule_source}" title="{self.rule_source}" width="20" />'

    @property
    def code_escape(self) -> str:
        raise NotImplementedError()

    @property
    def id(self) -> str:
        raise NotImplementedError()

    @property
    def name(self) -> str:
        raise NotImplementedError()

    @property
    def description(self) -> str:
        raise NotImplementedError()

    @property
    def techniques(self) -> list[str]:
        raise NotImplementedError()

    @property
    def false_positives(self) -> list[str]:
        raise NotImplementedError()

    @property
    def logic(self) -> str:
        raise NotImplementedError()

    def to_markdown(self) -> str:
        contents = [
            f'### {self.name}',
            '',
            self.icon_link,
            f'* **source**: [{self.rule_source}]({self.link})',
            '* **technicques**:']
        contents += [f'  - {t}' for t in self.techniques]
        contents += [
            '',
            '',
            f'#### Description',
            self.description,
            '',
            '#### Detection logic',
            f'```{self.code_escape}',
            self.logic,
            '```',
            ''
        ]
        return '\n'.join(contents)


class ElasticRule(Rule):
    """Elastic."""

    @property
    def code_escape(self) -> str:
        return 'sql'

    @property
    def icon_path(self) -> Path:
        return ETC_DIR / 'elastic.jpeg'

    @property
    def id(self) -> str:
        return self.contents['rule']['rule_id']

    @property
    def name(self) -> str:
        return self.contents['rule']['name']

    @property
    def description(self) -> str:
        return self.contents['rule']['description']

    @property
    def techniques(self) -> list[Optional[str]]:
        techniques = set()
        for entry in self.contents['rule'].get('threat', []):
            for technique in entry.get('technique', []):
                techniques.add(technique['id'])
                for sub in technique.get('subtechniques', []):
                    techniques.add(sub['id'])
        return sorted(techniques)

    @property
    def false_positives(self) -> list[Optional[str]]:
        return [' '.join(fp.strip().split()) for fp in self.contents['rule'].get('false_positives', [])]

    @property
    def logic(self) -> str:
        return self.contents['rule']['query']


class SigmaRule(Rule):
    """Sigma."""

    @property
    def code_escape(self) -> str:
        return 'yaml'

    @property
    def icon_path(self) -> Path:
        return ICON_DIR / 'sigma.png'

    @property
    def id(self) -> str:
        return self.contents.get('id', '')

    @property
    def name(self) -> str:
        return self.contents.get('title', '')

    @property
    def description(self) -> str:
        return self.contents.get('description', '')

    @property
    def techniques(self) -> list[Optional[str]]:
        techniques = set([t.split('.', 1)[1] for t in self.contents.get('tags', []) if t.startswith('attack.t')])
        for technique in techniques:
            # add technique from sub technique
            if '.' in technique:
                techniques.add(technique.split('.', 1)[0])
        return sorted(techniques)

    @property
    def false_positives(self) -> list[Optional[str]]:
        return [' '.join(fp.strip().split()) for fp in self.contents.get('falsepositives', [])]

    @property
    def logic(self) -> str:
        return yaml.safe_dump(self.contents.get('detection', {}))


class SplunkRule(Rule):
    """Splunk."""

    @property
    def code_escape(self) -> str:
        return 'sql'

    @property
    def icon_path(self) -> Path:
        return ICON_DIR / 'splunk.png'

    @property
    def id(self) -> str:
        return self.contents.get('id', '')

    @property
    def name(self) -> str:
        return self.contents.get('name', '')

    @property
    def description(self) -> str:
        return self.contents.get('description', '')

    @property
    def techniques(self) -> list[Optional[str]]:
        return self.contents.get('mitre_attack_id', [])

    @property
    def false_positives(self) -> list[Optional[str]]:
        return [' '.join(fp.strip().split()) for fp in self.contents.get('falsepositives', [])]

    @property
    def logic(self) -> str:
        return self.contents.get('search', '')

