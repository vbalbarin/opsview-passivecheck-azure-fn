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
    opsview_token: ${OPSVIEW_TOKEN:<default_value_from_keyvault>}

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
    keyvault_secret_name: ${AZURE_KEYVAULT_SECRET_NAME:<default_value_from_keyvault>}
    keyvault_secret_value: ${AZURE_KEYVAULT_SECRET_VALUE:<default_value>_from_keyvault}
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

#OPSVIEW_HTTP_HEADER = { 
#    'Content-Type': 'application/JSON',
#    'X-Opsview-Username': CFG['azure']['keyvault_secret_name'],
#    'X-Opsview-Token': CFG['azure']['keyvault_secret_value']}

logging.config.dictConfig(CFG['logging'])


def adal_callback(server, resource, scope):
    """Use ADAL to return access token for KV"""
    import adal
    auth_context = adal.AuthenticationContext(
        f"https://login.microsoftonline.com/{CFG['azure']['tenant_id']}")
    token = auth_context.acquire_token_with_client_credentials(
        resource='https://vault.azure.net',
        client_id=CFG['azure']['client_id'],
        client_secret=CFG['azure']['client_secret'])
    return token['tokenType'], token['accessToken']


def opsview_api_credentials(opsview_host, opsview_username, opsview_password):
    """ Return dictionary of username and token """
    opsview_api_uri = f'https://{opsview_host}/rest/login'
    r = requests.post(
        opsview_api_uri,
        headers={
            'Content-Type': 'application/JSON',
            'username': opsview_username,
            'password': opsview_password
        })
    if r.status_code == 200:
        opsview_api_token = r.json()['token']
        return {'X-Opsview-Username': opsview_username, 'X-Opsview-Token': opsview_api_token}
    elif r.status_code == 401:
        return {'message': 'Authorization required.'}
    else:
        return {'message': ''}


def opsview_api_info(opsview_host,
    opsview_api_credentials={'X-Opsview-Username': '', 'X-Opsview-Token': ''}):
    """ Return dictionary of opsview host info """
    opsview_api_uri=f'https://{opsview_host}/rest/info'
    opsview_header = {'Content-Type': 'application/JSON'}
    opsview_header.update(opsview_api_credentials)
    r = requests.get(
        opsview_api_uri,
        headers = opsview_header)
    return r.json()


def main(req: func.HttpRequest) -> func.HttpResponse:
    logger = logging.getLogger(__name__)
    logger.info('Python HTTP trigger function processed a request.')
    logger.debug(CFG)

    kv_client = KeyVaultClient(KeyVaultAuthentication(adal_callback))
    CFG['azure']['keyvault_secret_value'] = kv_client.get_secret(
        vault_base_url=f"https://{CFG['azure']['keyvault_name']}.vault.azure.net/",
        secret_name=CFG['azure']['keyvault_secret_name'],
        secret_version=CFG['azure']['keyvault_secret_version']).value
    opsview_credentials = {
        'X-Opsview-Username': CFG['azure']['keyvault_secret_name'],
        'X-Opsview-Token': CFG['azure']['keyvault_secret_value']}
    logger.debug(opsview_credentials)
    #opsview_info = opsview_api_info(
    #    opsview_host=CFG['app']['opsview_fqdn'],
    #    opsview_api_credentials=opsview_credentials)
    #logger.debug(opsview_info)

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
