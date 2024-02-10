
from pathlib import Path

import click

from .config import Config
from .loaders import Loader, RuleBundle


CURRENT_DIR = Path(__file__).parent
ROOT_DIR = CURRENT_DIR.parent
DOCS_DIR = ROOT_DIR / 'docs'
DOCS_CONTENT_DIR = DOCS_DIR / 'content'
ETC_DIR = CURRENT_DIR / 'etc'
CONFIG_FILE = ETC_DIR / 'config.yml'


@click.group('lofp', context_settings={'help_option_names': ['-h', '--help']})
@click.pass_context
def root(ctx: click.Context):
    """Commands for detection-rules repository."""
    ctx.obj = {'config': Config.from_file(CONFIG_FILE)}


@root.group('process')
def process():
    """Process the rules repos."""


@process.command('elastic')
@click.argument('repo')
@click.argument('branch')
@click.option('--directories', '-d', multiple=True, type=Path, help='list of rule directories (Default in config).')
@click.option('--write-dir', '-w', type=Path, help='directory to write the pages to.')
@click.pass_context
def process_elastic(ctx: click.Context, repo: str, branch: str, directories: tuple[str], write_dir: Path):
    """Process the rules for Elastic."""
    config = ctx.obj['config'].elastic
    directories = directories or config.directories
    loader = Loader(repo, branch, config.rule_glob_pattern, *directories)
    bundle = RuleBundle(loader)
    bundle.write_pages(write_dir or DOCS_CONTENT_DIR)


@process.command('sigma')
@click.pass_context
def process_sigma(ctx: click.Context):
    """Process the rules for Sigma."""


@process.command('splunk')
@click.pass_context
def process_splunk(ctx: click.Context):
    """Process the rules for Splunk."""
