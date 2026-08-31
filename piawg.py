import json
import os
import subprocess
import urllib.parse

import requests
import urllib3
from requests_toolbelt.adapters import host_header_ssl

# PIA name their server certificates with the CN attribute only, so connecting
# by IP triggers hostname warnings from urllib3 even though the certificate is
# verified properly against the pinned CA below.
urllib3.disable_warnings()

SERVER_LIST_URL = 'https://serverlist.piaservers.net/vpninfo/servers/v6'
TOKEN_URL = 'https://www.privateinternetaccess.com/api/client/v2/token'
WG_PORT = 1337

# PIA's own CA, used to verify the WireGuard servers. Resolved against this
# file's location so the app does not depend on the working directory it is
# started from.
CA_CERT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ca.rsa.4096.crt')

# (connect, read) timeouts in seconds. Without them an unresponsive server
# holds the request open until nginx times out the whole page.
TIMEOUT = (5, 15)


class PIAError(Exception):
    """PIA could not be reached, or answered with something unusable."""


class piawg:
    def __init__(self):
        self.server_list = {}
        self.get_server_list()
        self.region = None
        self.token = None
        self.publickey = None
        self.privatekey = None
        self.connection = None

    def get_server_list(self):
        """Fetch the current list of PIA regions and their servers."""
        try:
            r = requests.get(SERVER_LIST_URL, timeout=TIMEOUT)
            r.raise_for_status()
        except requests.RequestException as e:
            raise PIAError("Could not fetch the PIA server list: {}".format(e))

        # The response carries a base64 signature after the JSON body, so only
        # the first line is parsed.
        try:
            data = json.loads(r.text.splitlines()[0])
        except (ValueError, IndexError):
            raise PIAError("The PIA server list could not be parsed")

        for server in data['regions']:
            self.server_list[server['name']] = server

    def set_region(self, region_name):
        self.region = region_name

    def _pinned_session(self):
        """Build a session that verifies PIA's certificate when connecting by IP.

        The host header adapter sends the server's CN as the Host header so the
        certificate validates against the pinned CA despite the URL being an IP.
        """
        session = requests.Session()
        session.mount('https://', host_header_ssl.HostHeaderSSLAdapter())
        session.verify = CA_CERT
        return session

    def get_token(self, username, password):
        """Exchange PIA credentials for an access token.

        Returns True on success and False if PIA rejects the credentials.
        Raises PIAError when PIA cannot be reached or replies unexpectedly, so
        that a wrong password stays distinguishable from an outage.
        """
        try:
            r = requests.post(
                TOKEN_URL,
                data={'username': username, 'password': password},
                timeout=TIMEOUT,
            )
        except requests.RequestException as e:
            raise PIAError("Could not reach the PIA authentication API: {}".format(e))

        if r.status_code in (401, 403):
            return False
        if r.status_code != 200:
            raise PIAError(
                "The PIA authentication API returned HTTP {}".format(r.status_code)
            )

        try:
            token = r.json().get('token')
        except ValueError:
            raise PIAError("The PIA authentication API returned a malformed response")

        if not token:
            return False

        self.token = token
        return True

    def generate_keys(self):
        """Generate a WireGuard key pair using the wg command line tool."""
        self.privatekey = subprocess.run(
            ['wg', 'genkey'],
            stdout=subprocess.PIPE,
            check=True,
            encoding='utf-8',
        ).stdout.strip()

        self.publickey = subprocess.run(
            ['wg', 'pubkey'],
            input=self.privatekey,
            stdout=subprocess.PIPE,
            check=True,
            encoding='utf-8',
        ).stdout.strip()

    def addkey(self):
        """Register the public key with a WireGuard server in the selected region.

        A region is a small pool of servers rather than a single machine, and an
        individual server can be down or mid-rebuild, so each one is tried in
        turn. Returns (True, response) from the first server that accepts the
        key, or (False, last response seen) if none of them do.
        """
        servers = self.server_list[self.region]['servers']['wg']
        if not servers:
            return False, b'No WireGuard servers are listed for this region'

        session = self._pinned_session()
        last_response = None

        for server in servers:
            url = "https://{}:{}/addKey?pt={}&pubkey={}".format(
                server['ip'],
                WG_PORT,
                urllib.parse.quote(self.token),
                urllib.parse.quote(self.publickey),
            )

            try:
                r = session.get(url, headers={"Host": server['cn']}, timeout=TIMEOUT)
            except requests.RequestException as e:
                last_response = str(e).encode()
                continue

            last_response = r.content

            try:
                data = r.json()
            except ValueError:
                continue

            if r.status_code == 200 and data.get('status') == 'OK':
                self.connection = data
                return True, r.content

        return False, last_response
