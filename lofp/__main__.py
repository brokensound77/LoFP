
import click

from .main import root


BANNER = r"""
LoFP - Living off the False Positives
"""


def main():
    click.echo(BANNER)
    root(prog_name="lofp")


main()
