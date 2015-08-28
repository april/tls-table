#!/usr/bin/env python

from __future__ import print_function

from bs4 import BeautifulSoup as bs
from collections import OrderedDict
import json
import requests
import subprocess
import sys

GNUTLS_URL = 'https://gitlab.com/gnutls/gnutls/raw/master/lib/algorithms/ciphersuites.c'
IANA_URL = 'http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml'
MOZILLA_SERVER_SIDE_TLS_URL = 'https://raw.githubusercontent.com/mozilla/server-side-tls/gh-pages/Server_Side_TLS.mediawiki'
NSS_URL = 'https://hg.mozilla.org/projects/nss/raw-file/tip/lib/ssl/sslproto.h'
OPENSSL_URL = 'https://raw.githubusercontent.com/openssl/openssl/master/include/openssl/tls1.h'

LIBRARY_ORDER = ['IANA', 'GnuTLS', 'NSS', 'OpenSSL']
COMPAT_ORDER = ['Old', 'Intermediate', 'Modern']

# Styles for the table
COMPAT_STYLE_NO_MATCH = 'background-color: white;'
COMPAT_STYLE = {
    'Modern': 'background-color: #9EDB58; font-weight: bold;',
    'Intermediate': 'background-color: #DBC158; font-weight: bold;',
    'Old': 'background-color: #CCCCCC; font-weight: bold;'
}

__colorize_lists = {
    'Modern': [],
    'Intermediate': [],
    'Old': []
}

def usage():
    print("""Generate a table of cipher names from all the major library makers.

Usage: {0} <output-format> [--colorize]

Valid output formats are: json, mediawiki""".format(sys.argv[0]))
    sys.exit(1)


# Parse the command line
def parse_args():
    colorize = False

    if len(sys.argv) < 2 or len(sys.argv) > 3:
        usage()
    if 'json' not in sys.argv[1] and 'mediawiki' not in sys.argv[1]:
        usage()

    if '--colorize' in sys.argv:
        colorize = True

    return [sys.argv[1], colorize]

def get_colorize_chart():
    print('Retrieving cipher suites from Mozilla Server Side TLS page', file=sys.stderr)

    # Grab the cipher suites from the Mozilla page
    r = requests.get(MOZILLA_SERVER_SIDE_TLS_URL)

    # Try to grab the ciphersuites out the ugly mess that is a wiki page
    recommendations = [line.split("'''")[1] for line in r.text.split('\n') if "* Ciphersuite: '''" in line]

    __colorize_lists.update({
        'Modern': get_colorize_chart_openssl_ciphers(recommendations[0]),
        'Intermediate': get_colorize_chart_openssl_ciphers(recommendations[1]),
        'Old': get_colorize_chart_openssl_ciphers(recommendations[2])
    })

def get_colorize_chart_openssl_ciphers(ciphersuites):
    try:
        code_points = []
        output = subprocess.check_output(['openssl', 'ciphers', '-V', ciphersuites])

        for line in output.split('\n'):
            if '0x' in line:
                code_points.append(line.split()[0])

        return code_points
    except:
        print('Unable to run openssl ciphers', file=sys.stderr)
        sys.exit()

def get_hex_values():
    # Grab the list from the IANA
    print('Retrieving IANA cipher List', file=sys.stderr)
    try:
        r = requests.get(IANA_URL)
        soup = bs(r.text, 'html.parser')\
            .select('table[id="table-tls-parameters-4"]')[0]\
            .find_all('tbody')[0]

        # Store all the ciphers away
        cipher_hex_values = OrderedDict()

        for row in soup.find_all('tr'):
            columns = [ x.string for x in row.find_all('td') ]

            # For now, we can ignore any IANA entries with '-' or '*' in them
            if '-' not in columns[0] and '*' not in columns[0]:
                cipher_hex_values[ columns[0] ] = {
                    'GnuTLS': '',
                    'IANA': columns[1],
                    'NSS': '',
                    'OpenSSL': ''
                }

    except:
        print('Unable to retrieve or parse IANA cipher list', file=sys.stderr)

    # Grab the list from NSS (Mozilla)
    print('Retrieving NSS cipher list', file=sys.stderr)
    try:
        r = requests.get(NSS_URL)
        for line in r.text.split('\n'):
            # A typical line would look like: #define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256   0xC02F
            if '#define TLS' in line and '0x' in line:
                cipher = line.split()[1]

                hex = line.split()[2].upper()
                code_point = '0x' + hex[2:4] + ',0x' + hex[4:6]

                if code_point in cipher_hex_values:
                    cipher_hex_values[code_point]['NSS'] = cipher
                else:
                    print('  Warning: code point {code_point} ({cipher}) not in IANA registry'.format(
                        code_point=code_point, cipher=cipher
                    ), file=sys.stderr)

    except:
        print('Unable to retrieve or parse NSS cipher list', file=sys.stderr)

    # Grab the list from OpenSSL
    print('Retrieving OpenSSL cipher list', file=sys.stderr)
    try:
        # OpenSSL splits up their code points and their text names for them
        openssl_hex_values = {}
        openssl_txt_values = {}

        r = requests.get(OPENSSL_URL)
        for line in r.text.split('\n'):
            if line.startswith('# define TLS1_CK'):
                cipher = line.split()[2].split('TLS1_CK_')[-1]
                hex = line.split()[3]
                code_point = '0x' + hex[6:8] + ',0x' + hex[8:10]

                # e.g., ECDHE_RSA_WITH_AES_128_GCM_SHA256 -> 0x0C,0x2F
                openssl_hex_values[cipher] = code_point
            elif line.startswith('# define TLS1_TXT'):
                cipher = line.split()[2].split('TLS1_TXT_')[-1]
                text = line.split()[3][1:-1]

                # e.g., ECDHE_RSA_WITH_AES_128_GCM_SHA256 -> ECDHE-RSA-AES128-GCM-SHA256
                openssl_txt_values[cipher] = text

        for key in openssl_hex_values.iterkeys():
            if openssl_hex_values[key] in cipher_hex_values:
                cipher_hex_values[openssl_hex_values[key]]['OpenSSL'] = openssl_txt_values[key]
            else:
                print('  Warning: code point {code_point} ({cipher}) not in IANA registry'.format(
                    code_point=openssl_hex_values[key], cipher=key
                ), file=sys.stderr)
    except:
        print('Unable to retrieve or parse OpenSSL cipher list', file=sys.stderr)

    # Grab the list from GnuTLS
    print('Retrieving GnuTLS cipher list', file=sys.stderr)
    try:
        r = requests.get(GNUTLS_URL)

        # Some lines look like: #define GNUTLS_DH_ANON_3DES_EDE_CBC_SHA1 { 0x00, 0x1B }
        # Other look like:      #define GNUTLS_ECDHE_ECDSA_CAMELLIA_128_CBC_SHA256 { 0xC0,0x72 }
        for line in r.text.split('\n'):
            if line.startswith('#define GNUTLS_'):
                cipher = line.split()[1][3:]
                code_point = line.split('{')[-1].replace(' ', '').replace('}', '')

                if code_point in cipher_hex_values:
                    cipher_hex_values[code_point]['GnuTLS'] = cipher
                else:
                    print('  Warning: code point {code_point} ({cipher}) not in IANA registry'.format(
                        code_point=code_point, cipher=cipher
                    ), file=sys.stderr)
    except:
        print('Unable to retrieve or parse GnuTLS cipher list', file=sys.stderr)

    print('\n', file=sys.stderr)
    return cipher_hex_values

def __print_wiki_entry(code_point, ciphers):
    print('|-')

    # Determine the style to use; use COMPAT_STYLE_NO_MATCH by default
    style = '| style="{style}" '.format(style=COMPAT_STYLE_NO_MATCH)

    # Now print all the columns for the various libraries
    for order in COMPAT_ORDER:
        if code_point in __colorize_lists[order]:
            style = '| style="{style}" '.format(style=COMPAT_STYLE[order])
            centered_style = '| style="{style} text-align: center;" '.format(style=COMPAT_STYLE[order])

    # Print the Hex column
    print('! scope=row | {code_point}'.format(code_point=code_point))

    # Determine the priority
    if code_point in __colorize_lists.get('Old'):
        priority = __colorize_lists.get('Old').index(code_point) + 1
    else:
        priority = None

    # Print the columns by priority
    if priority:
        print('{style}| {priority}'.format(style=centered_style, priority=priority))
    else:
        print('{style}data-sort-value="1000" | '.format(style=style))


    for library in LIBRARY_ORDER:
        print('{style}| {cipher}'.format(style=style, cipher=ciphers.get(library, '')))


# Print everything out
def print_output(cipher_hex_values, output_format):
    # JSON output is super easy
    if output_format == 'json':
        print(json.dumps(cipher_hex_values, indent=2))

    elif output_format == 'mediawiki':
        # Table header
        print('{| class="wikitable sortable"')
        print('|-')
        print('\n'.join(
            ['! scope="col" | ' + x for x in ['Hex', 'Priority'] + LIBRARY_ORDER]
        ))

        # Determine the order to go by: first let's go by priority
        for code_point in __colorize_lists.get('Old'):
            __print_wiki_entry(code_point, cipher_hex_values[code_point])
            del(cipher_hex_values[code_point])

        # If they don't have a priority, then go by hex value
        for code_point, ciphers in cipher_hex_values.iteritems():
            __print_wiki_entry(code_point, ciphers)


        # Table footer
        print('|}')


if __name__ == '__main__':
    output_format = parse_args()

    output = get_hex_values()

    if output_format[1]:
        get_colorize_chart()

    print_output(output, output_format[0])