#!/usr/bin/python

#Importing base modules
import re, requests, argparse, os, time
#Beautify
from termcolor import colored

#Importing OTX modules
from OTXv2 import OTXv2
import IndicatorTypes

#Create the parser of arguments, add those and parse them
parser = argparse.ArgumentParser(description='Tool for checking "things" against the OSINT tools that I usually use')

parser.add_argument('-r', action='store_true', dest='relations', help='Show the relations in VirusTotal')
parser.add_argument('-p', action='store_true', dest='pulses', help='Show the pulses in OTX')
parser.add_argument(dest='thing', help='The "thing" to be scanned. As is recognized by regex there is no need to specify what it actually is. IP follow the format \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}')

args = parser.parse_args()

#Define color variables

def check_vt(ip):
    url = 'https://www.virustotal.com/api/v3/ip_addresses/' + ip
    header ={
        'x-apikey': 'ddf4a72abf1d9be0400af0843350d8a47098462edc2cea77fe77e56073a75e16'
    }

    r = requests.get(url, headers=header)
    vt_res = r.text

    mali_re = re.search(r'"malicious": \d{1,2}',vt_res)
    susp_re = re.search(r'\"suspicious\": \d{1,2}',vt_res)
    country_re = re.search(r'"country": "\w{2}"',vt_res)
    net_re = re.search(r'"network": ".*?"',vt_res)
    asOwn_re = re.search(r'"as_owner": ".*?"',vt_res)

    mali = mali_re.group(0).split(':')
    print('[*] Malicious Detections: ' + mali[1])
    susp = susp_re.group(0).split(':')
    print('[*] Suspicious Detections: ' + susp[1])
    if net_re:
        net = net_re.group(0).split(':')
        print('[*] Network: ' + net[1])
    if asOwn_re:
        asOwner = asOwn_re.group(0).split(':')
        print('[*] Provider: ' + asOwner[1])
    if country_re:
        country = country_re.group(0).split(':')
        print('[*] Country Code: ' + country[1])
    print('\n')


def check_otx(ip):
#Def api + otx
    API_KEY = "c2a8dbf589101b5d128f426be67d35bd42ed64c4bbea56ee58d3fd2a1328aade"
    otx = OTXv2(API_KEY)

#Extraemos los resultados de OTX, y convertimos a string
    alert = str((otx.get_indicator_details_full(IndicatorTypes.IPv4,ip)))

#Creamos las expresiones regex para extraer los datos correspondientes
    pulse_re = re.search(r'count\': \d{1,3}',alert)
    country_re = re.search(r'country_name\': \'\w{1,15}\'',alert)
    owner_re = re.search(r'asn\': \'.*?\'',alert)
    pulses_desc_re = re.findall(r'description\': \'.*?\'',alert)

#Extraemos los datos y les hacemos el split en el ': '
    pulses_n = pulse_re.group(0).split(': ')
#pulses_desc = pulses_desc_re.group(0)
    country = country_re.group(0).split(': ')
    owner = owner_re.group(0).split(': ')

#Mostramos solo los datos
    print('[*] Country: ' + country[1])
    print('[*] ASN/Owner: ' + owner[1])
    print('[*] Nº Pulses: ' + pulses_n[1])
    if args.pulses:
        if int(pulses_n[1]) > 0:
            print('[*] Examples:')
            for x in range(0,min(3,int(pulses_n[1]))):
                desc_re = pulses_desc_re[x].split(": ")
            print('    ' + desc_re[1])
    print('\n')


def check_abuse(ip):
#Definimos el api endpoint
    url = "https://api.abuseipdb.com/api/v2/check"

#Definimos parametros que van a la url
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

#Definimos headers custom
    headers = {
        'Accept': 'application/json',
        'Key': '7236fb058533f9e416f3529e93f6d29d770edeb5ba4574228cff7bbf0c1dbafd7a0dd1da85a6de5f'
    }

#Extraemos respuesta
    response = requests.get(url, headers=headers, params=params)
    resp = response.text

#Extraemos campos que nos interesan
    score_re = re.search(r'\"abuseConfidenceScore\":\d{1,3}',resp)
    country_re = re.search(r'countryCode":"\w{2}"',resp)
    usage_re = re.search(r'"usageType":".*?"',resp)
    isp_re = re.search(r'"isp":".*?"',resp)
    domain_re = re.search(r'"domain":".*?"',resp)
    last_re = re.search(r'"lastReportedAt":".*?"',resp)

#Extraemos solo los datos y le damos formato
    score = score_re.group(0).split(':')
    print('[*] Abuse Confidence: ' + score[1])
    country = country_re.group(0).split(':')
    print('[*] Country: ' + country[1])
    usage = usage_re.group(0).split(':')
    print('[*] Usage: ' + usage[1])
    isp = isp_re.group(0).split(':')
    print('[*] Provider: ' + isp[1])
    domain = domain_re.group(0).split(':')
    print('[*] Domain: ' + domain[1])
    last = last_re.group(0).split(':')
    print('[*] Last Report: ' + last[1] + ':' + last[2])
    print('\n')


def check_tor(ip):
#Creamos las variables de tiempo para ver si habria que actualizar el tor_list
    last_mod = int(os.path.getmtime("tor_list"))
    now = int(time.time())

#Comparamos los valores y actualizamos en caso de ser necesario.
    if (now-last_mod) >= (30*60):
        mod_tor = open("tor_list","w+")
        r = requests.get('https://www.dan.me.uk/torlist/')
        print("Updating TOR list...")
        mod_tor.write(r.text)
        mod_tor.close()

#Comparamos la IP con la lista actualizada
    tor_file = open("tor_list")
    tor_list = tor_file.read()
    if ip in tor_list:
        print("\033[1;32;40m [*] TOR Node\n")
    else:
        print("\033[;1;31;40m [-] Not TOR\n")


def check_shodan(ip):
    api_key = 'JfeOaGZRQYXntyd4PXVQjG6pF0CfGuNU'

    url = 'https://api.shodan.io/shodan/host/%s?key=%s' % (ip,api_key)

    r = requests.get(url)

    country_re = re.search(r'"country_name": ".*?"', r.text)
    org_re = re.search(r'"org": ".*?"', r.text)
    ports_re = re.search(r'ports": \[.*?\]', r.text)

    country = country_re.group(0).split(': ')[1]
    org = org_re.group(0).split(': ')[1]
    ports = ports_re.group(0).split(': ')[1]

    print(country)
    print(org)
    print(ports)


def check_ip(ip):
    print('[VirusTotal]')
    check_vt(ip)
    print('[OTX]')
    check_otx(ip)
    print('[AbuseIPDB]')
    check_abuse(ip)
    print('[TOR]')
    check_tor(ip)
    print('[Shodan]')
    check_shodan(ip)

def main():
    ip_re = re.search(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}',args.thing)
    hash_re = re.search(r'[a-fA-F0-9]{32}',args.thing)
    dom_re = re.search(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}',args.thing)
    if ip_re:
        print('Comprobando IP...\n')
        check_ip(args.thing)
main()
