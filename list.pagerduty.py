#!/usr/bin/env python3
"""Is this a client to list all users in pagerduty"""

# http://python-future.org/compatible_idioms.html
from __future__ import print_function
from builtins import input  # pip install future --upgrade
import pypd
import logging
import sys
import os
import yaml
import argparse
import gc
import json
import lib.VaultClient as vc
import requests # Needed to handle connection timeout

def getApiKey(vault_url,secret,debug):
    """Connect to Vault and grab api key"""
    vault = vc.VaultClient(vault_url=vault_url, debug=debug, timeout=10)

    try:
        vault.setup()
    except KeyboardInterrupt:
        raise Exception('Exiting with KeyboardInterrupt from Control-C')
    except requests.exceptions.ConnectTimeout as err: #
        print("Timed out connecting to '{0}'".format(vault_url))
        sys.exit(1)

    if not vault.check_status():
        print('Something is wrong!')

    data = None
    try:
        data = vault.get_secret(secret)
    except LookupError as err:
        print('Failed to find secret in Vault')
    except Exception as err:
        print('Failed with error: {0}'.format(err))
        sys.exit(1)

    apiKeyName = 'api-key'
    if apiKeyName not in data:
        print('Error: Failed to find key: {0}'.format(apiKeyName))
        sys.exit(1)

    return data[apiKeyName] # return the apiKey value


def main():
    """Read cmd line options and return secrets from Vault"""
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    log = logging.getLogger(__name__)

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--debug', help="increase debug output", action="store_true")
    parser.add_argument('-u', '--url', dest='url', help="Override URL path", required=False)
    parser.parse_args()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # Config file so there is no hardcoding in python
    scriptPath = os.path.dirname(os.path.abspath(__file__))
    configFile = scriptPath + '/config.yaml'
    config = None
    if os.path.exists(configFile):
        with open(configFile, 'r') as stream:
            config = yaml.load(stream)

    # Pull some default values from the configs or the command line
    if args.url is not None:
        vault_url = args.url
    elif config is not None and 'vault' in config and 'url' in config['vault']:
        vault_url = config['vault']['url']
    elif config is None or 'vault' not in config or 'url' not in config['vaul']:
        raise ValueError('No Vault URL set in the configuration')

    if config is not None and 'vault' in config and 'secret' in config['vault']:
        secret = config['vault']['secret']
    elif config is None or 'vault' not in config or 'url' not in config['vaul']:
        raise ValueError('No Vault secret set in the configuration')

    pypd.api_key = getApiKey(vault_url,secret,args.debug)

    # # https://github.com/PagerDuty/pagerduty-api-python-client/blob/5cca53cce9e9553e6c17c294c71cae33322c170b/examples/all.py
    users = pypd.User.find()

    # Simple example of getting some data with the API
    import pprint
    pprint.pprint(users)

if __name__ == "__main__":
    main()
