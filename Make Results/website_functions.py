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

    Download = st.download()
    Upload = st.upload()
    return {'download':Download, 'upload':Upload}


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
    r = requests.get(protocol+"://"+websiteURL, auth=('user', 'pass'))
    print("WHY DO WE NOT GET HERE?-----------------------------------------------")
    print("r: ")
    print(r.text)
    print(number_script_tags(r.text))
    print("SCRIPT NUMBER ----------------------------------------------")
    results = {}
    results['RespondeCode'] = str(r.status_code)
    results['BlockPage'] = detectBlockPage(text_from_html(r.text))
    results['CloudflareBlockPage'] = detectCloudFlare(text_from_html(r.text))
    return results

def listOfDNSs():
    MyDNS = getMyDNS()
    AARNet = "10.127.5.17"
    OptusDNS = "192.168.43.202"
    GoogleDNS = "8.8.8.8"
    Cloudflare = "1.1.1.1"


    DNSList = [MyDNS, AARNet, OptusDNS, GoogleDNS, Cloudflare]
    return DNSList

def resolveIPFromDNS(hostname, DNSList):
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


    return compiledList

def scapyTracerouteWithSR(domain):
    try:
        ans, unans = sr(IP(dst=domain, ttl=(1,25),id=RandShort())/TCP(flags=0x2), timeout = 2)
    except Exception as e:
        return [str(e).replace(',',";")]
    hops = []
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

    print(IPList)
    for IP in IPList:
        response = getIPResponseCodeAndText(IP)

        responseCodeList.append(response.get('Response_Code'))
        blockPageList.append(detectBlockPage(response.get('Visible_Text')))
        cloudFlareBlockPageList.append(detectCloudFlare(response.get('Visible_Text')))

    return {'responseCodeList':responseCodeList, 'blockPageList':blockPageList, 'cloudFlareBlockPageList':cloudFlareBlockPageList}


def getIPResponseCodeAndText(IPAddress):
    if IPAddress == '' or IPAddress == None:
        return "NaN"

    try:

        r = requests.get('http://'+IPAddress)

        return {'Response_Code': r.status_code, 'Visible_Text': text_from_html(r.text)}
    except Exception as e:
        exce = str(e).replace(',',";")

        return {'Response_Code': exce, 'Visible_Text': "N/A"}

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
