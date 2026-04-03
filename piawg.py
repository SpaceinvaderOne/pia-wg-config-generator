import requests
import json
from requests_toolbelt.adapters import host_header_ssl
import urllib3
import subprocess
import urllib.parse

# Suppress warning (still needed for WG endpoint cert handling)
urllib3.disable_warnings(urllib3.exceptions.SubjectAltNameWarning)


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
        r = requests.get('https://serverlist.piaservers.net/vpninfo/servers/v7')
        data = json.loads(r.text.splitlines()[0])
        for server in data['regions']:
            self.server_list[server['name']] = server

    def set_region(self, region_name):
        self.region = region_name

    # ✅ UPDATED FUNCTION
    def get_token(self, username, password, verbose=False):
        token_url = "https://www.privateinternetaccess.com/api/client/v2/token"

        if verbose:
            print("Requesting token from central PIA API")

        try:
            r = requests.post(
                token_url,
                data={
                    "username": username,
                    "password": password
                }
            )
        except requests.RequestException as e:
            raise Exception(f"Error requesting token from PIA API: {e}")

        if r.status_code != 200:
            raise Exception(f"Token request failed with status {r.status_code}: {r.text}")

        try:
            data = r.json()
        except json.JSONDecodeError:
            raise Exception("Error decoding token response")

        token = data.get("token")
        if not token:
            raise Exception("Received empty token from PIA API")

        if verbose:
            print(f"Got token: {token}")

        self.token = token
        return True

    def generate_keys(self):
        self.privatekey = subprocess.run(
            ['wg', 'genkey'],
            stdout=subprocess.PIPE,
            encoding="utf-8"
        ).stdout.strip()

        self.publickey = subprocess.run(
            ['wg', 'pubkey'],
            input=self.privatekey,
            stdout=subprocess.PIPE,
            encoding="utf-8"
        ).stdout.strip()

    def addkey(self):
        cn = self.server_list[self.region]['servers']['wg'][0]['cn']
        ip = self.server_list[self.region]['servers']['wg'][0]['ip']

        s = requests.Session()
        s.mount('https://', host_header_ssl.HostHeaderSSLAdapter())
        s.verify = 'ca.rsa.4096.crt'

        url = "https://{}:1337/addKey?pt={}&pubkey={}".format(
            ip,
            urllib.parse.quote(self.token),
            urllib.parse.quote(self.publickey)
        )

        r = s.get(url, headers={"Host": cn})

        if r.status_code == 200 and r.json()['status'] == 'OK':
            self.connection = r.json()
            return True, r.content
        else:
            return False, r.content
