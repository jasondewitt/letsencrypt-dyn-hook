# Dyn hook for `dehydrated`

This is a hook for the [Let's Encrypt](https://letsencrypt.org/) ACME client [dehydrated](https://github.com/lukas2511/dehydrated) (previously known as `letsencrypt.sh`) that allows you to use [Dyn](https://dyn.com/) DNS records to respond to `dns-01` challenges. Requires Python and your Dyn account customer name, username and password being in the environment.

This is heavily based on [kappataumu's CloudFlare hook](https://github.com/kappataumu/letsencrypt-cloudflare-hook), and when I say based on, I mean I kept most of his structure and modified to to work with Dyn api calls and the differences in how their API functions vs CloudFlare's.

## Installation

```
$ cd ~
$ git clone https://github.com/lukas2511/dehydrated
$ cd dehydrated
$ mkdir hooks
$ git clone https://github.com/jasondewitt/letsencrypt-dyn-hook.git hooks/dyn
```

If you are using Python 3:
```
$ pip install -r hooks/cloudflare/requirements.txt
```

Otherwise, if you are using Python 2 (make sure to also check the [urllib3 documentation](http://urllib3.readthedocs.org/en/latest/security.html#installing-urllib3-with-sni-support-and-certificates) for possible caveats):

```
$ pip install -r hooks/dyn/requirements-python-2.txt
```


## Configuration

Your Dyn account info is expected to be in the environment, so make sure to:

```
$ export DYN_CUSTOMER='customer_name'
$ export DYN_USERNAME='your dyn username'
$ export DYN_PASSWORD='your dyn password'
```

Optionally, you can specify the DNS servers to be used for propagation checking via the `DYN_DNS_SERVERS` environment variable (props [bennettp123](https://github.com/bennettp123)):

```
$ export DYN_DNS_SERVERS='8.8.8.8 8.8.4.4'
```

If you want more information about what is going on while the hook is running:

```
$ export DYN_DEBUG='true'
```

Alternatively, these statements can be placed in `dehydrated/config`, which is automatically sourced by `dehydrated` on startup:

```
echo "export DYN_CUSTOMER=customer_name" >> config
echo "export DYN_USERNAME=username" >> config
echo "export DYN_PASSWORD=Ub68B9OKWIIDXrxLu65l"
echo "export DYN_DEBUG=true" >> config
```


## Usage

```
$ ./dehydrated -c -d example.com -t dns-01 -k 'hooks/dyn/hook.py'
#
# !! WARNING !! No main config file found, using default config!
#
Processing example.com
 + Signing domains...
 + Creating new directory /home/user/dehydrated/certs/example.com ...
 + Generating private key...
 + Generating signing request...
 + Requesting challenge for example.com...
 + DYN hook executing: deploy_challenge
 + DNS not propagated, waiting 30s...
 + DNS not propagated, waiting 30s...
 + Responding to challenge for example.com...
 + DYN hook executing: clean_challenge
 + Challenge is valid!
 + Requesting certificate...
 + Checking certificate...
 + Done!
 + Creating fullchain.pem...
 + DYN hook executing: deploy_cert
 + ssl_certificate: /home/user/dehydrated/certs/example.com/fullchain.pem
 + ssl_certificate_key: /home/user/dehydrated/certs/example.com/privkey.pem
 + Done!
```
