
from dataclasses import dataclass
from pathlib import Path

import yaml


CURRENT_DIR = Path(__file__).parent
ROOT_DIR = CURRENT_DIR.parent
ETC_DIR = CURRENT_DIR / 'etc'
CONFIG_FILE = ETC_DIR / 'config.yaml'


@dataclass
class ConfigEntry:
    directories: list[str]
    recursive_directories: bool
    rule_glob_pattern: str


@dataclass
class Config:
    splunk: ConfigEntry
    elastic: ConfigEntry
    sigma: ConfigEntry

    @classmethod
    def from_file(cls, path: Path) -> 'Config':
        contents = yaml.safe_load(path.read_text())
        return cls(**{k: ConfigEntry(**v) for k, v in contents.items()})
