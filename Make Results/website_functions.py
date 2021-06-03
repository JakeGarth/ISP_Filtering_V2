import requests
from bs4 import BeautifulSoup
from bs4.element import Comment
import socket
from scapy.all import *
import dns.resolver
from nslookup import Nslookup
import ipaddress
from detect_blockpages import *
import speedtest
import geoip2.webservice
import geocoder



def tag_visible(element):
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
        return False
    if isinstance(element, Comment):
        return False
    return True


def text_from_html(body):
    soup = BeautifulSoup(body, 'html.parser')
    texts = soup.findAll(text=True)
    visible_texts = filter(tag_visible, texts)
    return u" ".join(t.strip() for t in visible_texts)


def speed_test():
    st = speedtest.Speedtest()

    All_Results = st.results.dict()
    print("All results")
    print(All_Results)
    Download = st.download()
    Upload = st.upload()

    ISP_name = All_Results.get('client').get('isp')
    print("st.results.dict()")
    print(st.results.dict())
    ping = st.results.dict().get('ping')
    client_ip = st.results.dict().get('client').get('ip')
    return {'download':Download, 'upload':Upload, 'isp_name': ISP_name, 'ping': ping, 'client_ip': client_ip}


def number_script_tags(html):
    soup = BeautifulSoup(html, 'html.parser')
    count = 0
    for tag in soup.findAll():
        if (tag.name == 'script'):
            count += 1

    return count


def requestWebsite(websiteURL, http, https):

    protocol = "This is broken"
    if(https == True):
        protocol = "https"
    if(http == True):
        protocol = "http"

    print("requesting: "+protocol+"://"+websiteURL)
    print("DO WE GET IN HERE IN LINE 55 of REQUEST WEBSITE")
    r = requests.get(protocol+"://"+websiteURL, auth=('user', 'pass'))
    print("DO WE GET IN HERE IN LINE 57 of REQUEST WEBSITE")
    print("SCRIPT NUMBER ----------------------------------------------")
    print(type(number_script_tags(r.text)))
    print(number_script_tags(r.text))
    results = {}

    #If response code isnt a number, just insert error in to database
    if str(r.status_code).isnumeric() == False:
        print("status code isnt numeric...")
        results['ResponseCode'] = "ERROR"
    else:
        print("status code is numeric...")
        results['ResponseCode'] = str(r.status_code)

    results['BlockPage'] = detectBlockPage(text_from_html(r.text))
    results['CloudflareBlockPage'] = detectCloudFlare(text_from_html(r.text))
    results['Number_of_Script_Tags'] = number_script_tags(r.text)

    print("RESULTS_---------------____________")
    print(results)

    return results

def listOfDNSs():
    MyDNS = getMyDNS()
    AARNet = "10.127.5.17"
    OptusDNS = "192.168.43.202"
    GoogleDNS = "8.8.8.8"
    Cloudflare = "1.1.1.1"


    DNSList = [MyDNS, AARNet, OptusDNS, GoogleDNS, Cloudflare]
    DNSDict = {'MyDNS':MyDNS, 'AARNet':AARNet, 'OptusDNS':OptusDNS, 'GoogleDNS':GoogleDNS, 'Cloudflare':Cloudflare}
    DNS_IP_Dict = {MyDNS:'MyDNS', AARNet:'AARC', OptusDNS:'Optus', GoogleDNS:'Google', Cloudflare:'Cloudflare'}
    return DNSList, DNSDict, DNS_IP_Dict

def resolveIPFromDNS(hostname, DNSList):
    print("hostname")
    print("DNSList:--------------")
    print(DNSList)
    domain = hostname
    compiledList = []
    # set optional Cloudflare public DNS server
    for DNSIP in DNSList:
        dns_query = Nslookup(dns_servers=[DNSIP])

        ips_record = dns_query.dns_lookup(domain)

        soa_record = dns_query.soa_lookup(domain)

        tuple = (DNSIP, ips_record.answer)
        compiledList.append(tuple)
        tuple = ()


    print("COMPILED LIST: ")
    print(compiledList)
    return compiledList

def scapyTracerouteWithSR(domain):
    print("DO WE BREAK IN HERE")
    try:
        ans, unans = sr(IP(dst=domain, ttl=(1,25),id=RandShort())/TCP(flags=0x2), timeout = 2)
    except Exception as e:
        return [str(e).replace(',',";")]
    hops = []

    print("DO WE GET HERE")
    for snd,rcv in ans:


        if len(hops) > 0:
            if not isinstance(rcv.payload, TCP) or hops[-1] != rcv.src:
                hops.append(rcv.src)
        else:
            if not isinstance(rcv.payload, TCP):
                hops.append(rcv.src)

    return hops

def IPResponseCodesAndText(IPList):
    responseCodeList = []
    blockPageList = []
    cloudFlareBlockPageList = []
    number_of_script_tags = []


    for IP in IPList:
        response = getIPResponseCodeAndText(IP)

        responseCodeList.append(response.get('Response_Code'))
        blockPageList.append(detectBlockPage(response.get('Visible_Text')))
        cloudFlareBlockPageList.append(detectCloudFlare(response.get('Visible_Text')))
        number_of_script_tags.append(response.get('number_of_script_tags'))

    return {'responseCodeList':responseCodeList, 'blockPageList':blockPageList, 'cloudFlareBlockPageList':cloudFlareBlockPageList, 'number_of_script_tags':number_of_script_tags}


def getIPResponseCodeAndText(IPAddress):


    if IPAddress == '' or IPAddress == None:
        return "NaN"

    try:
        #If requests takes longer than 5 seconds to connect, just return Error. Clearly some kind of failed connection
        r = requests.get('http://'+IPAddress, timeout=5)
        return {'Response_Code': r.status_code, 'Visible_Text': text_from_html(r.text), 'number_of_script_tags':number_script_tags(r.text)}

    except Exception as e:

        exce = str(e).replace(',',";")

        return {'Response_Code': "ERROR", 'Visible_Text': "N/A", 'number_of_script_tags': "N/A"}

def getIPAddressOfDomain(websiteURL):

    try:
        result = socket.gethostbyname_ex(websiteURL)

        IPAddressList = result[2]
        IPaddressString = str(result[2]).replace(',',";")


    except Exception as e:
        IPaddressString = str(e)
        IPaddressString.replace(',',";")
        IPAddressList = ['NaN', 'NaN']

    return IPaddressString, IPAddressList


def getMyDNS():
    dns_resolver = dns.resolver.Resolver()
    return dns_resolver.nameservers[0]

def stripDomainName(domainName):
    #Returns different ways of represeting a domain name as a dictionary.
    positionofWWW = domainName.find('://')

    if "http" in domainName:
        WebsiteNOHttp = domainName[positionofWWW+3:]
    else:
    #If http in domain name, change to + 3, if no http, change to +1
        WebsiteNOHttp = domainName[positionofWWW+1:]


    WebsiteNOHttpNoSlash = WebsiteNOHttp.replace('/',"")

    if 'www.' == WebsiteNOHttp[0:4]:

        WebsiteNoWWWNoSlash = WebsiteNOHttp[4:]
    else:
        WebsiteNoWWWNoSlash = WebsiteNOHttp
    if '/' == WebsiteNoWWWNoSlash[-1]:
        WebsiteNoWWWNoSlash = WebsiteNoWWWNoSlash[0:-1]


    return {'WebsiteNOHttp': WebsiteNOHttp,  'WebsiteNOHttpNoSlash': WebsiteNOHttpNoSlash, 'WebsiteNoHttpNoWWWNoSlash': WebsiteNoWWWNoSlash}

def getIPAddress():
    #Returns IP address of the user
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    return IPAddr


def convert_list_to_dict(this_list):
    return_dict = {}
    for DNS_Resolved_IPs in this_list:
        DNS_IP = DNS_Resolved_IPs[0]
        Resolved_IPs = DNS_Resolved_IPs[1]
        return_dict[DNS_IP] = Resolved_IPs
    return return_dict

'''
OBSOLETE CODE
def get_location_from_IP(ip):
    maxmind_account_id = 559831
    maxmind_liscence_key = '90CgLcF2UBUsWmKS'
    with geoip2.webservice.Client(maxmind_account_id, maxmind_liscence_key) as client:
        response = client.city(ip)
        return {'Country': response.country.name,'City':response.city.name, 'Latitude':response.location.latitude, 'Longitude':response.location.longitude}
'''

def get_my_location_from_IP():
    g = geocoder.ip('me')
    print(type(g.latlng))
    print(g.latlng)
    return {'latitude':g.latlng[0], 'longitude':g.latlng[1]}
