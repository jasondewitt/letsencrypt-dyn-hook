#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from builtins import str

from future import standard_library
standard_library.install_aliases()

import dns.exception
import dns.resolver
import logging
import os
import requests
import sys
import time
import re

from tld import get_tld

# Enable verified HTTPS requests on older Pythons
# http://urllib3.readthedocs.org/en/latest/security.html
if sys.version_info[0] == 2:
    try:
        requests.packages.urllib3.contrib.pyopenssl.inject_into_urllib3()
    except AttributeError:
        # see https://github.com/certbot/certbot/issues/1883
        import urllib3.contrib.pyopenssl
        urllib3.contrib.pyopenssl.inject_into_urllib3()

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())

if os.environ.get('DYN_DEBUG'):
    logger.setLevel(logging.DEBUG)
else:
    logger.setLevel(logging.INFO)

try:
    DYN_CREDS = {
        'customer_name': os.environ['DYN_CUSTOMER'],
        'username'  : os.environ['DYN_USERNAME'],
        'password'  : os.environ['DYN_PASSWORD'],
    }
except KeyError:
    logger.error(" + Unable to locate DYN credentials in environment!")
    sys.exit(1)

try:
    dns_servers = os.environ['DYN_DNS_SERVERS']
    dns_servers = dns_servers.split()
except KeyError:
    dns_servers = False

dynApiBase = "https://api.dynect.net"
dynAuthToken = None


def _dyn_auth():
    data = '{"customer_name":"%s","user_name":"%s","password":"%s"}'%(DYN_CREDS['customer_name'],DYN_CREDS['username'],DYN_CREDS['password'])
    headers={"Content-Type": "application/json"}

    r=requests.post(dynApiBase+'/REST/Session/', data=data, headers=headers)
    r.raise_for_status()
    return r.json()['data']['token']

def _dyn_auth_headers():
    return {"Content-Type": "application/json", "Auth-Token": dynAuthToken}


def _has_dns_propagated(name, token):
    try:
        if dns_servers:
            custom_resolver = dns.resolver.Resolver()
            custom_resolver.nameservers = dns_servers
            dns_response = custom_resolver.query(name, 'TXT')
        else:
            dns_response = dns.resolver.query(name, 'TXT')

        for rdata in dns_response:
            if token in [b.decode('utf-8') for b in rdata.strings]:
                print("found token: {0}".format(token))
                return True

    except dns.exception.DNSException as e:
        logger.debug(" + {0}. Retrying query...".format(e))

    return False


def _get_zone(domain):

    logger.debug(" + Finding parent zone on Dyn API")
    while True:
        logger.debug(" + checking for {0}".format(domain))
        r = requests.get(dynApiBase+"/REST/Zone/{0}/".format(domain), headers=_dyn_auth_headers())
        if r.status_code == 200:
            # found a zone for this domain
            logger.debug(" + found zone {0}".format(domain))
            return domain
        # if the original domain wasn't found, strip off the first bit of the domain
        # and check for that as a zone
        domain = re.sub("^[\w-]+\.", "", domain)
        if len(domain.split('.')) == 1:
            logger.error(" + Unable to locate suitable zone on Dyn API!")
            sys.exit(1)


def _get_txt_record_id(zone, name, token):
    url = dynApiBase+"/REST/TXTRecord/{0}/{1}/".format(zone,name)
    try:
        r = requests.get(url, headers=_dyn_auth_headers())
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.debug(" + Unable to locate record named {0}".format(name))
        return

    return True

def _publish_zone_changes(zone):
    data = {"publish":"true","notes":"change made via API for LetsEncrypt dns-01 challenge"}
    try:
        r = requests.put(dynApiBase+"/REST/Zone/%s/"%(zone), headers=_dyn_auth_headers(), json=data)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.debug(" - unable to publish changes for zone {0}".format(zone))

# https://api.cloudflare.com/#dns-records-for-a-zone-create-dns-record
def create_txt_record(args):
    domain, challenge, token = args
    logger.debug(' + Creating TXT record: {0} => {1}'.format(domain, token))
    logger.debug(' + Challenge: {0}'.format(challenge))

    zone = _get_zone(domain)
    name = "{0}.{1}".format('_acme-challenge', domain)

    record_id = _get_txt_record_id(zone, name, token)
    if record_id:
        logger.debug(" + TXT record exists, skipping creation.")
        return

    url = dynApiBase+"/REST/TXTRecord/{0}/{1}/".format(zone,name)
    payload={
        "rdata":{
            "txtdata": token
        },
        "ttl":60,
    }

    print(url)
    r = requests.post(url, headers=_dyn_auth_headers(), json=payload)
    r.raise_for_status()
    print(r.text)
    if r.json()['status'] == "success":
        fqdn = r.json()['data']['fqdn']
        logger.debug(" + TXT record created for fqdn: {0}".format(fqdn))
        _publish_zone_changes(zone)
    else:
        logger.debug(" + TXT record creation failed")
        sys.exit(1)


def delete_txt_record(args):
    domain, token = args[0], args[2]
    if not domain:
        logger.info(" + http_request() error in letsencrypt.sh?")
        return

    zone = _get_zone(domain)
    name = "{0}.{1}".format('_acme-challenge', domain)
    record_id = _get_txt_record_id(zone, name, token)

    if record_id:
        url = dynApiBase+"/REST/TXTRecord/{0}/{1}/".format(zone, name)
        r = requests.delete(url, headers=_dyn_auth_headers())
        r.raise_for_status()
        logger.debug(" + Deleted TXT {0}".format(name))
        _publish_zone_changes(zone)
    else:
        logger.debug(" + No TXT {0} with token {1}".format(name, token))


def deploy_cert(args):
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem, timestamp = args
    print(domain)
    logger.debug('deploy cert hook running...')
    logger.debug(' + ssl_certificate: {0}'.format(fullchain_pem))
    logger.debug(' + ssl_certificate_key: {0}'.format(privkey_pem))
    return


def unchanged_cert(args):
    return


def invalid_challenge(args):
    domain, result = args
    logger.debug(' + invalid_challenge for {0}'.format(domain))
    logger.debug(' + Full error: {0}'.format(result))
    return


def create_all_txt_records(args):
    X = 3
    for i in range(0, len(args), X):
        create_txt_record(args[i:i+X])
    # give it 10 seconds to settle down and avoid nxdomain caching
    logger.info(" + Settling down for 10s...")
    time.sleep(10)
    for i in range(0, len(args), X):
        domain, token = args[i], args[i+2]
        name = "{0}.{1}".format('_acme-challenge', domain)
        print("checking DNS for {0}".format(name))
        while(_has_dns_propagated(name, token) == False):
            logger.info(" + DNS not propagated, waiting 30s...")
            time.sleep(30)


def delete_all_txt_records(args):
    X = 3
    for i in range(0, len(args), X):
        delete_txt_record(args[i:i+X])


def exit_hook(args):
    return


def main(argv):
    global dynAuthToken
    ops = {
        'deploy_challenge': create_all_txt_records,
        'clean_challenge' : delete_all_txt_records,
        'deploy_cert'     : deploy_cert,
        'unchanged_cert'  : unchanged_cert,
        'invalid_challenge': invalid_challenge,
        'exit_hook': exit_hook
    }
    if not dynAuthToken:
        logger.info(" + Authenticating to DYN API")
        dynAuthToken = _dyn_auth()
    logger.info(" + DYN hook executing: {0}".format(argv[0]))
    ops[argv[0]](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
