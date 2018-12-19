import hashlib
import azure.functions as func
import json
import logging, logging.config
import os
import re
import requests
import yaml

from azure.keyvault import KeyVaultClient, KeyVaultAuthentication

CONFIG_YAML = """
---
app:
    log_level: ${LOG_LEVEL:<default_value>}
    opsview_fqdn: ${OPSVIEW_FQDN:<default_value>}
    opsview_username: ${OPSVIEW_USERNAME:<default_value>}
    opsview_password: ${OPSVIEW_PASSWORD:<default_value>}

azure:
    subscription_name: ${AZURE_SUBSCRIPTION_NAME:<default_value>}
    subscription_id: ${AZURE_SUBSCRIPTION_ID:<default_value>}
    tenant_id: ${AZURE_TENANT_ID:<default_value>}
    location: ${AZURE_LOCATION:<default_value>}
    group_name: ${AZURE_GROUP_NAME:<default_value>}
    app_name: ${AZURE_APP_NAME:<default>}
    serviceprincipal_name: ${AZURE_SERVICEPRINCIPAL_NAME:<default>}
    client_id: ${AZURE_CLIENT_ID:<default_value>}
    client_secret: ${AZURE_CLIENT_SECRET:<default_value>}
    keyvault_name: ${AZURE_KEYVAULT_NAME:<default_value>}
    keyvault_secret_name: ${AZURE_KEYVAULT_SECRET_NAME:<default_value>}
    keyvault_secret_value: ${AZURE_KEYVAULT_SECRET_VALUE:<default_value>}
    keyvault_secret_version: ${AZURE_KEYVAULT_SECRET_VERSION:''}

logging:
    version: 1
    disable_existing_loggers: False
    formatters:
        default:
            format: '%(asctime)s [%(levelname)s] %(name)s %(message)s'
    handlers:
        console:
            class: logging.StreamHandler
            formatter: default
            level: ${LOG_LEVEL:INFO}
    loggers:
        "":
            handlers: [console]
            level: ${LOG_LEVEL:INFO}
...
"""


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


CFG = yaml_extended(CONFIG_YAML)

OPSVIEW_HTTP_HEADER = { 
    'Content-Type': 'application/JSON',
    'X-Opsview-Username': CFG['azure']['keyvault_secret_name'],
    'X-Opsview-Token': CFG['azure']['keyvault_secret_value']}

logging.config.dictConfig(CFG['logging'])


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    logging.info(CFG)

    name = req.params.get('name')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('name')

    if name:
        return func.HttpResponse(f"Hello {name}!")
    else:
        return func.HttpResponse(
             "Please pass a name on the query string or in the request body",
             status_code=400
        )
