import logging
import os
import re
import yaml

from logging.config import dictConfig

CONFIG_FILE = 'config.yaml'


def contents(file_name=CONFIG_FILE):
    """Returns contents of text file as string"""
    try:
        with open(file_name, 'r') as f:
            return f.read()
    except IOError as e:
        return ''


def yaml_extended(yaml_contents):
    """Returns dictionary of yaml contents. Supports BASH style environment variable expansion with <default_value> option"""
    regex_str = r'\$\{([^}^{^:]+)(:([^}^{^:]+))?\}' # Matches on pattern ${VAR_NAME:<default_value>}
    pattern = re.compile(regex_str)
    yaml.add_implicit_resolver('!pathex', pattern)
    regex_empty = r'(\'\')|("")|(None)|(none)'
    empty_pattern = re.compile(regex_empty)
    def pathex_constructor(loader, node):
        var_name = ''
        value = loader.construct_scalar(node)
        m = pattern.match(value)
        if m:
            var_name, default_option, default_val = m.groups()
        var_val = os.environ.get(var_name)
        if var_val:
            return var_val
        elif empty_pattern.match(default_val):
            return ''
        else:
            return default_val

    yaml.add_constructor('!pathex', pathex_constructor)

    try:
        return yaml.load(yaml_contents)
    except:
        return {}


def main():
    c = contents()
    if not c: return
    cfg = yaml_extended(c)
    dictConfig(cfg['logging'])
    logger = logging.getLogger(__name__)
    logger.debug(cfg['app'])
    logger.debug(cfg['azure'])
    return


if __name__ == '__main__':
    main()
