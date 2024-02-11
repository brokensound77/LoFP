
from pathlib import Path

import click

from .config import Config
from .loader import Loader
from .page import PageWriter


CURRENT_DIR = Path(__file__).parent
ROOT_DIR = CURRENT_DIR.parent
DOCS_DIR = ROOT_DIR / 'docs'
DOCS_CONTENT_DIR = DOCS_DIR / 'content'
ETC_DIR = CURRENT_DIR / 'etc'
CONFIG_FILE = ETC_DIR / 'config.yml'

CONFIG_CHOICES = ['elastic', 'sigma', 'splunk']


@click.group('lofp', context_settings={'help_option_names': ['-h', '--help']})
@click.pass_context
def root(ctx: click.Context):
    """Commands for detection-rules repository."""
    ctx.obj = {'config': Config.from_file(CONFIG_FILE)}


@root.group('generate')
def generate():
    """Process the rules repos."""


@generate.command('build')
@click.argument('repo')
@click.argument('branch')
@click.option('--config-name', '-c', type=click.Choice(CONFIG_CHOICES), help='Config options to use')
@click.option('--directories', '-d', multiple=True, type=Path, help='list of rule directories (Default in config).')
@click.option('--write-dir', '-w', type=Path, help='directory to write the pages to.')
@click.pass_context
def process_elastic(ctx: click.Context, repo: str, branch: str, config_name: str, directories: tuple[str], write_dir: Path):
    """Process the rules for Elastic."""
    full_config = ctx.obj['config']
    config = getattr(full_config, config_name, None)
    assert config, f'Config not found for {config}!'
    directories = directories or config.directories
    loader = Loader(repo, branch, config.rule_glob_pattern, *directories)
    click.echo(f'{len(loader.rules)} rules loaded for {config_name} from {" ".join(str(d) for d in directories)}.')
    bundle = PageWriter(loader)
    bundle.write_pages(write_dir or DOCS_CONTENT_DIR)
