#!/usr/bin/env python3

# http://python-future.org/compatible_idioms.html
from __future__ import print_function
from builtins import input  # pip install future --upgrade
import logging
import os
import sys
import argparse
import gc
import re
import socket
import getpass
import hvac # https://github.com/ianunruh/hvac
from urllib.parse import urlparse
import requests # Needed to handle connection timeout

class VaultClient(object):
    """Prompts for LDAP Linux passwords as an interface for the hvac module"""
    def __init__(self, vault_url=None, set_token=None, no_prompt=None, debug=None, quiet=None, timeout=10):
        logging.basicConfig(level=logging.debug, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
        self.__log = logging.getLogger(__name__)

        self.__timeout = timeout      # This is used in hvac > requests -> urllib3 -> ConnectTimeoutError
        self.__set_token = set_token  # If you already have a Vault token
        self.__no_prompt = no_prompt  # To disable user/pass prompt and error if not given token
        self.__debug = debug          # To get more info, when things are no working
        self.__quiet = quiet          # When you want to disable output

        del set_token # no need to keep this variable
        gc.collect()  # Run the garbage collector to clean up vars

        self.__log.debug('{0} Initializing'.format(self.__class__.__name__))
        self.__token_file = os.path.expanduser("~") + '/.vault-token'
        self.__hvac = None

        self.find_token() # Get the token from the environment, else no token is set

        self.vault_url = None
        if vault_url:
            self.vault_url = self._sanitize(vault_url)
        else:
            raise ValueError('No Vault URL given')

        # Make sure DNS is working for the given Vault domain name
        hostname = urlparse(self.vault_url).hostname
        if not hostname:
            raise ValueError('Cannot get hostname from: "{0}"'.format(self.vault_url))

        if self.__set_token:
            self.__log.debug('Token\'s last two characters : {0}'.format(self.__set_token[-2:]))
        self.__log.debug('Vault URL: {0}'.format(self.vault_url))

    def __del__(self):
        """Clean up a few things when the class gets closed"""
        del self.__set_token
        gc.collect()  # Run the garbage collector to clean up vars

        if self.__hvac:
            self.__hvac.logout()
            self.__log.debug('{0} destroyed'.format(self.__class__.__name__))


    def find_token(self):
        """See if the user already has a token set in their environment"""
        if os.environ.get('VAULT_TOKEN') is not None:
            self.__log.debug('Using environment variable token for authentication.')
            self.__set_token = os.environ['VAULT_TOKEN']
        elif os.path.isfile(self.__token_file):
            self.__log.debug('Using local authentication file for token')
            file = open(self.__token_file, 'r')
            self.__set_token = file.read()
            file.close()
        # Error as soon as possible: Make sure any given token is in the right format.
        if self.__set_token:
            self.test_token(self.__set_token)

    def check_status(self):
        """Return True if Vault is good and user is connected with auth"""
        initialized = self.__hvac.is_initialized()
        sealed = self.__hvac.is_sealed()
        authenticated = self.__hvac.is_authenticated()

        if self.__debug:
            self.__log.debug('Vault is initialized:  {0}'.format(initialized))
            self.__log.debug('Vault is sealed:       {0}'.format(sealed))
            self.__log.debug('User is authenticated: {0}'.format(authenticated))
        if initialized == True and sealed == False and authenticated == True:
            return True
        else:
            return False

    def setup(self):
        """Setup hvac client handle with given token or LDAP user/password"""
        write_auth_file = 0
        re_authenticate = 0
        if self.__set_token:  # If we already have a token
            self.__hvac = hvac.Client(url=self.vault_url, token=self.__set_token, timeout=10)
            try:
                self.__set_token = self.__hvac.lookup_token()['data']['id']
            except requests.exceptions.ConnectTimeout as err:
                raise err
            except Exception as err:
                if not self.__quiet:
                    self.__log.warn('Failed to authenticate: {0}'.format(err))
                re_authenticate = 1
            else: # if we have a good given token, we can return. Don't save token.
                return

        if self.__set_token == 1:
            raise ValueError('No set token and no_prompt=1')
        else:  # Use a prompt and ask for LDAP authentication
            if re_authenticate == 1 and not self.__quiet:
                self._eprint('')
                self._eprint('Need to authenticate again')
            self.authenticate_user()
            write_auth_file = 1

        # lets make sure we can talk to the Vault server
        # This could raise an exception, but we will let the calling code handle that problem
        self.__set_token = self.__hvac.lookup_token()['data']['id']

        if write_auth_file == 1: # Only write the auth file if we can talk to Vault and we asked the user for a user/pass
            # Now update/create the vault auth file
            self.__log.debug('Writing to the authentication file')
            with os.fdopen(os.open(self.__token_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as file:
                file.write(self.__set_token)

        if not self.__hvac.is_authenticated():
            raise PermissionError('User is NOT authenticated.')

    def authenticate_user(self):
        """Prompt user for user/pass in a loop until they are successfully authenticated"""
        for _ in range(10): # If the user gives a bad password, try again.
            # https://pymotw.com/3/getpass/
            print('Vault needs your LDAP Linux user/pass.')
            username = getpass.getuser()
            given_username = input('username ({0}): '.format(username))
            if given_username:
                username = given_username
            password = getpass.getpass(stream=sys.stderr)

            self.__hvac = hvac.Client(url = self.vault_url)
            try:
                self.__hvac.auth_ldap(username, password)
            except hvac.exceptions.InvalidRequest as err:
                if 'LDAP groups found in group' in str(err):
                    raise Exception('User not apart of any group in LDAP: {0}'.format(err))
                if 'user is not a member of any authorized group' in str(err):
                    raise Exception('User not apart of any group in Vault: {0}'.format(err))
                else:
                    if 'binddn 0 or not unique' in str(err):
                        self.__log.warn('Failed. Bad username: {0}'.format(err))
                    elif 'LDAP Result Code 49' in str(err):
                        self.__log.warn('Failed. Bad password: {0}'.format(err))
                    else:
                        # Maybe try to login again with a unknown error.
                        # Might have to change this later if users find any unrecoverable
                        self.__log.warn('Failed. Unknown error: {0}'.format(err))
                    self._eprint('')
                    self._eprint('Try again, you entered a bad username or password!')
            except Exception as err: # any other error die!
                raise Exception('Failed with error: {0}'.format(err))
            else:
                break

        del given_username, username, password
        gc.collect()  # Run the garbage collector to clean up username/password
        # There is no great solution for password removal. This is just one step.


    def get_secret(self, given_secret_path):
        """Search for the given secret name and return the value"""
        if given_secret_path is None:
            raise ValueError('Vault URL path is required')

        # Get the user secret name. Add the secret header if needed
        secret_path = self._sanitize(given_secret_path)
        if not secret_path.startswith('secret/') and not secret_path.startswith('/secret/'):
            secret_path = 'secret/' + secret_path

        # This could raise an exception, but we will let the calling code handle that problem
        vault_data = self.__hvac.read(secret_path)

        found_data = None
        message = None
        if vault_data is None:
            # https://docs.python.org/3/library/exceptions.html#exception-hierarchy
            raise LookupError('Secret(s) not found in Vault')
        else:
            found_data = vault_data['data']
        return found_data


    def set_secret(self, given_secret_path, **kwargs):
        """Set the given name and value in Vault """
        if given_secret_path is None:
            raise ValueError('Vault URL path is required')

        if kwargs is None:
            raise ValueError('Vault secret is required')

        # Get the user secret name. Add the secret header if needed
        secret_path = self._sanitize(given_secret_path)
        if not secret_path.startswith('secret/') and not secret_path.startswith('/secret/'):
            secret_path = 'secret/' + secret_path

        self.__hvac.write(secret_path, **kwargs)


    def test_token(self, given_token=None):
        """Error if the given token is not valid"""
        if not given_token: # if no token is given assume it is the main one
            given_token = self.__set_token

        if given_token:
            regex = r'^\w{8}-\w{4}-\w{4}-\w{4}-\w{12}$'
            if not re.search(regex, given_token):
                raise SyntaxError('Given Token does not look valid')
            else:
                return
        else:
            self.__log.debug('No token given to test.')
            return


    def _eprint(self, *args, **kwargs):
        """Print to standard error. (For error messages)"""
        print(*args, file=sys.stderr, **kwargs)


    def _sanitize(self, line):
        """Remove control characters from given input"""
        return ''.join(char for char in line if ord(char) >= 32)
