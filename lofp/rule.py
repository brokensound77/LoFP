
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

import yaml


CURRENT_DIR = Path(__file__).parent.resolve()
ETC_DIR = CURRENT_DIR / 'etc'


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

    @property
    def data_source(self) -> str:
        raise NotImplementedError()

    def to_markdown(self) -> str:
        contents = [
            f'### {self.name}',
            '',
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
        return [' '.join(fp.strip().split()).lower() for fp in self.contents['rule'].get('false_positives', [])]

    @property
    def logic(self) -> str:
        return self.contents['rule'].get('query', '')

    @property
    def data_source(self) -> str:
        return self.path.parent.name.lower()


class SigmaRule(Rule):
    """Sigma."""

    @property
    def code_escape(self) -> str:
        return 'yaml'

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
        subs = set()
        for technique in techniques:
            # add technique from sub technique
            if '.' in technique:
                subs.add(technique.split('.', 1)[0])
        return sorted(techniques | subs)

    @property
    def false_positives(self) -> list[Optional[str]]:
        return [' '.join(fp.strip().split()).lower() for fp in self.contents.get('falsepositives', [])]

    @property
    def logic(self) -> str:
        return yaml.safe_dump(self.contents.get('detection', {}))

    @property
    def data_source(self) -> str:
        return str(self.contents.get('logsource', {}).get('product', '')).lower()


class SplunkRule(Rule):
    """Splunk."""

    @property
    def code_escape(self) -> str:
        return 'sql'

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
        return self.contents.get('tags', {}).get('mitre_attack_id', [])

    @property
    def false_positives(self) -> list[Optional[str]]:
        fp = ' '.join(self.contents.get('known_false_positives', '').lower().strip().split())
        return [] if fp.startswith('unknown') else [fp]

    @property
    def logic(self) -> str:
        return '\n|'.join(self.contents.get('search', '').split('|'))

    @property
    def data_source(self) -> str:
        return str(self.contents.get('tags', {}).get('asset_type', '')).lower()


RuleTypes = Union[ElasticRule, SigmaRule, SplunkRule]
