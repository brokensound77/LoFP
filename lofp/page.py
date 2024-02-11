
import string
from collections import defaultdict
from pathlib import Path

import yaml

from .loader import Loader
from .rule import RuleTypes


ATTACK_URL_BASE = 'https://attack.mitre.org/techniques'


class FpPage:
    """Page object for the lofp FP entry."""

    def __init__(self, false_positive: str, data: dict, directory: Path):
        self.false_positive = false_positive
        self.data = data
        self.directory = directory
        self.path = directory / f'{self._clean_filename(false_positive)}.md'
        self._exists = self.path.exists()

        self.techniques: list[str] = data['techniques']
        self.rules: list[RuleTypes] = data['rules']
        self.data_sources = [r.data_source for r in self.rules if r.data_source]
        self.rule_sources = [r.rule_source for r in self.rules if r.rule_source]

        self.techniques_content = [f'- [{t}]({ATTACK_URL_BASE}/{"/".join(t.split("."))}/)' for t in self.techniques]
        self.rules_content = [r.to_markdown() for r in self.rules]

        if self._exists:
            self.formatted = self.update_format()
        else:
            self.formatted = self.format()

    @staticmethod
    def _clean_filename(name: str) -> str:
        return '-'.join(''.join([c for c in name if c in string.ascii_lowercase + ' '][:75]).split()).replace('\\', '')

    @staticmethod
    def _clean_attack_url(technique: str) -> str:
        return "/".join(technique.split("."))

    @staticmethod
    def _clean_header_name(name: str) -> str:
        return name.replace('"', '\\"')

    def read_existing(self) -> str:
        return self.path.read_text()

    def _get_existing_techniques(self, existing_lines: list[str]) -> list[str]:
        start_index = self._get_start_techniques(existing_lines)
        end_index = self._get_start_rules(existing_lines)
        techniques = [l for l in existing_lines[start_index:end_index] if l.startswith('- t')]
        return [t.split(']')[0][3:] for t in techniques]

    @staticmethod
    def _get_start_techniques(existing_lines: list[str]) -> int:
        for i, line in enumerate(existing_lines):
            if line.startswith('## Techniques'):
                return i

    @staticmethod
    def _get_start_rules(existing_lines: list[str]) -> int:
        for i, line in enumerate(existing_lines):
            if line.startswith('## Sample rules'):
                return i

    def format(self) -> str:
        name = self._clean_header_name(self.false_positive)
        tags = self.techniques + self.data_sources + self.rule_sources
        dumped = yaml.safe_dump(dict(title=name, description='', tags=tags))
        contents = ['---'] + dumped.splitlines() + ['---']
        contents += [
            '',
            '## Techniques',
            '']
        contents += self.techniques_content
        contents += [
            '',
            '## Sample rules',
            '']
        contents += self.rules_content

        return '\n'.join(contents)

    def update_format(self) -> str:
        existing_contents = self.path.read_text()
        existing_lines = existing_contents.splitlines()
        unique_techniques = sorted(set(self.techniques) | set(self._get_existing_techniques(existing_lines)))
        techniques_content = [f'- [{t}]({ATTACK_URL_BASE}/{"/".join(t.split("."))}/)' for t in unique_techniques]
        start_index = self._get_start_techniques(existing_lines)
        end_index = self._get_start_rules(existing_lines)
        pre_lines = existing_lines[:start_index]
        post_lines = existing_lines[end_index:]
        contents = pre_lines + [''] + techniques_content + [''] + post_lines + [''] + self.rules_content
        return '\n'.join(contents)

    def write(self):
        self.path.write_text(self.formatted)


class TagPage:
    """Page object for the lofp Tag entry."""

    def __init__(self, name: str, formatted: str):
        self.name = name
        self.formatted = formatted

    @staticmethod
    def page_header(name: str) -> str:
        return f'---\ntitle: "{name}"\n---\n'

    @classmethod
    def from_technique(cls, technique: str) -> 'TagPage':
        contents = f'{cls.page_header(technique)}\n> [{technique}]({ATTACK_URL_BASE}/{technique}/)'
        return cls(name=technique, formatted=contents)

    @classmethod
    def from_rule_source(cls, rule: RuleTypes) -> 'TagPage':
        contents = f'{cls.page_header(rule.rule_source)}\n> [{rule.rule_source}]({rule.repo_url})'
        return cls(name=rule.rule_source, formatted=contents)

    @classmethod
    def from_data_source(cls, rule: RuleTypes) -> 'TagPage':
        contents = f'{cls.page_header(rule.data_source)}\n> {rule.data_source} rule'
        return cls(name=rule.data_source, formatted=contents)

    def write(self, directory: Path):
        path = directory / 'tags' / self.name / '_index.md'
        path.parent.mkdir(exist_ok=True, parents=True)
        path.write_text(self.formatted)


class PageWriter:

    def __init__(self, loader: Loader):
        self.loader = loader

    def page_data(self) -> (dict[str, dict], list[str]):
        output = defaultdict(dict)
        techniques = set()
        for rule in self.loader.rules:
            for fp in rule.false_positives:
                output[fp].setdefault('techniques', set())
                output[fp].setdefault('rules', {})
                output[fp]['techniques'].update(rule.techniques)
                output[fp]['rules'][rule.id] = rule
                techniques.update(rule.techniques)

        for fp, entry in output.items():
            entry['techniques'] = sorted(entry['techniques'])
            entry['rules'] = list(entry['rules'].values())

        return output, sorted(techniques)

    def write_pages(self, directory: Path):
        entries, techniques = self.page_data()
        for fp, data in entries.items():
            fp_page = FpPage(fp, data, directory)
            fp_page.write()

            rules: list[RuleTypes] = data['rules']
            for rule in rules:
                rule_source_tag = TagPage.from_rule_source(rule)
                rule_source_tag.write(directory)

                data_source_tag = TagPage.from_data_source(rule)
                data_source_tag.write(directory)

        for technique in techniques:
            technique_tag = TagPage.from_technique(technique)
            technique_tag.write(directory)
