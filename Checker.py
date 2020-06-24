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
parser.add_argument(dest='thing', help='The "thing" to be scanned. As is recognized by regex there is no need to specify what it actually is. IP follow the format \d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}. Hash matches against [a-fA-F0-9]{32}')

args = parser.parse_args()

#Define API_KEY vars
vt_api = os.getenv('VT_API')
abuse_api = os.getenv('ABUSE_API')
otx_api = os.getenv('OTX_API')
shodan_api = os.getenv('SHODAN_API')

def check_vt_ip(ip):
    url = 'https://www.virustotal.com/api/v3/ip_addresses/' + ip
    header ={
        'x-apikey': vt_api
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


def check_otx_ip(ip):
#Def api + otx
    otx = OTXv2(otx_api)

#Extraemos los resultados de OTX, y convertimos a string
    alert = str((otx.get_indicator_details_full(IndicatorTypes.IPv4,ip)))

#Creamos las expresiones regex para extraer los datos correspondientes
    pulse_re = re.search(r'count\': \d{1,3}',alert)
    country_re = re.search(r'country_name\': \'.*?\'',alert)
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


def check_abuse_ip(ip):
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
        'Key': abuse_api
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
    if last_re:
        last = last_re.group(0).split(':')
        print('[*] Last Report: ' + last[1] + ':' + last[2])
    print('\n')


def check_tor_ip(ip):
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
        print(colored("[*] TOR Node\n",'green'))
    else:
        print(colored("[-] Not TOR node\n",'red'))


def check_shodan_ip(ip):
    url = 'https://api.shodan.io/shodan/host/%s?key=%s' % (ip,shodan_api)

    r = requests.get(url)

    if r.text != '{"error": "No information available for that IP."}':
        country_re = re.search(r'"country_name": ".*?"', r.text)
        org_re = re.search(r'"org": ".*?"', r.text)
        ports_re = re.search(r'ports": \[.*?\]', r.text)

        country = country_re.group(0).split(': ')[1]
        org = org_re.group(0).split(': ')[1]
        ports = ports_re.group(0).split(': ')[1]

        print("[*] Country: " + country)
        print("[*] Organization: " + org)
        print("[*] Ports: " + ports)
    else:
        print(colored('[-] No information available for that IP.','red'))


def check_ip(ip):
    print('[VirusTotal]')
    check_vt_ip(ip)
    print('[OTX]')
    check_otx_ip(ip)
    print('[AbuseIPDB]')
    check_abuse_ip(ip)
    print('[TOR]')
    check_tor_ip(ip)
    print('[Shodan]')
    check_shodan_ip(ip)


def check_vt_hash(f_hash):
    url = 'https://www.virustotal.com/api/v3/files/' + f_hash

    header ={
        'x-apikey': vt_api
    }

    r = requests.get(url, headers=header)

    vt_res = r.text

    fType_re = re.search(r'"FileType": ".*?"',vt_res)
    ext_re = re.search(r'"FileTypeExtension": ".*?"',vt_res)
    mali_re = re.search(r'"malicious": \d{1,2}',vt_res)
    susp_re = re.search(r'"suspicious": \d{1,2}',vt_res)
    rep_re = re.search(r'"reputation": .*?,',vt_res)
    names_re = re.search(r'"names": .*?\]',vt_res,re.DOTALL)
    names = str(names_re.group(0))
    name_re = re.findall(r'".*?\..*?"',names)

    mali = mali_re.group(0).split(':')
    print('[*] Malicious Detections: ' + mali[1])
    susp = susp_re.group(0).split(':')
    print('[*] Suspicious Detections: ' + susp[1])
    fType = fType_re.group(0).split(':')
    print('[*] File Type: ' + fType[1])
    ext = ext_re.group(0).split(':')
    print('[*] Extension: ' + ext[1])
    rep = rep_re.group(0).split(':')
    print('[*] Reputation: ' + rep[1])
    print('[*] Names: ')
    for x in range(0,min(5,len(name_re))):
        print(name_re[x])
    print('\n')


def check_otx_hash(f_hash):
    otx = OTXv2(otx_api)

#Extraemos los resultados de OTX, y convertimos a string
    alert = str((otx.get_indicator_details_full(IndicatorTypes.FILE_HASH_MD5,f_hash)))

#Creamos las expresiones regex para extraer los datos correspondientes
    pulse_re = re.search(r'\{\'count\': \d{1,3}',alert)
    names_re = re.findall(r'\'name\': \'.*?\'',alert)

#Extraemos los datos y les hacemos el split en el ': '
    pulses_n = pulse_re.group(0).split(': ')

#Mostramos solo los datos
    print('[*] Nº Pulses: ' + pulses_n[1])
    if int(pulses_n[1]) > 0:    
        print('[*] Examples:')
        for x in range(0,min(4,int(pulses_n[1]))):
            name = names_re[x].split(": ")
            print(name[1])
    print('\n')


def check_hash(f_hash):
    print('[VirusTotal]')
    check_vt_hash(f_hash)
    print('[OTX]')
    check_otx_hash(f_hash)


def main():
    ip_re = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',args.thing)
    hash_re = re.search(r'[a-fA-F0-9]{32}',args.thing)
    dom_re = re.search(r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}',args.thing)
    if ip_re:
        print('Checking IP...\n')
        check_ip(args.thing)
    elif hash_re:
        print('Checking HASH...\n')
        check_hash(args.thing)
main()
