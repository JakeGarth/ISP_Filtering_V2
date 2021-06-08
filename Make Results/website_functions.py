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



#Returns whether a tag is visible text in html
def tag_visible(element):
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
        return False
    if isinstance(element, Comment):
        return False
    return True

#returns all visible text from html
def text_from_html(body):
    soup = BeautifulSoup(body, 'html.parser')
    texts = soup.findAll(text=True)
    visible_texts = filter(tag_visible, texts)
    return u" ".join(t.strip() for t in visible_texts)


#returns the key results from a speedtest, such as download/upload, isp name, ping
def speed_test():

    try:
        st = speedtest.Speedtest()

    except:
        return {'download':-1, 'upload':-1, 'isp_name': -1, 'ping': -1, 'client_ip': -1}
    All_Results = st.results.dict()
    print("All results")
    print(All_Results)

    try:
        Download = st.download()
    except:
        Download = -1

    try:
        Upload = st.upload()
    except:
        Upload = -1

    try:
        ISP_name = All_Results.get('client').get('isp')
    except:
        ISP_name = "ERROR In Speedtest"

    try:
        ping = st.results.dict().get('ping')
    except:
        ping = -1

    try:
        client_ip = st.results.dict().get('client').get('ip')
    except:
        client_ip = '-1'

    print("st.results.dict()")
    print(st.results.dict())
    return {'download':Download, 'upload':Upload, 'isp_name': ISP_name, 'ping': ping, 'client_ip': client_ip}


#returns number of script tags in html
def number_script_tags(html):
    soup = BeautifulSoup(html, 'html.parser')
    count = 0
    for tag in soup.findAll():
        if (tag.name == 'script'):
            count += 1
    return count


#Returns the response code, blockpages and number script tags for the domain checked by the ISP
#and default DNS
def requestWebsite(websiteURL, http, https):
    protocol = "This is broken"
    if(https == True):
        protocol = "https"
    if(http == True):
        protocol = "http"

    print("requesting: "+protocol+"://"+websiteURL)
    r = requests.get(protocol+"://"+websiteURL, auth=('user', 'pass'))
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
    results['html'] = r.text


    return results

#This is the list of DNS's we are checking
def listOfDNSs():
    MyDNS = getMyDNS()
    AARNet = "10.127.5.17"
    OptusDNS = "192.168.43.202"
    GoogleDNS = "8.8.8.8"
    Cloudflare = "1.1.1.1"
    DNSList = [MyDNS, AARNet, OptusDNS, GoogleDNS, Cloudflare]
    DNSDict = {'MyDNS':MyDNS, 'AARNet':AARNet, 'OptusDNS':OptusDNS, 'GoogleDNS':GoogleDNS, 'Cloudflare':Cloudflare}
    DNS_IP_Dict = {MyDNS:'MyDNS', AARNet:'AARC', OptusDNS:'Optus', GoogleDNS:'Google', Cloudflare:'Cloudflare'}
    DNS_IP_Dict_Default_and_Public_Only = {MyDNS:'MyDNS', GoogleDNS:'Google', Cloudflare:'Cloudflare'}
    return DNSList, DNSDict, DNS_IP_Dict, DNS_IP_Dict_Default_and_Public_Only

#Return the IP's resolved by every DNS
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

    print("CompiledList-----------------------------")
    print(compiledList)
    return compiledList


#Returns the traceroute from local machine to domain via ISP
def scapyTracerouteWithSR(domain):

    try:
        ans, unans = sr(IP(dst=domain, ttl=(1,25),id=RandShort())/TCP(flags=0x2), timeout = 2)
    except Exception as e:
        #maybe I should just make it return "error", that way there is no risk of weird SQL insertions breaking my results
        return [str(str(e).replace(',',";").replace("'","" ))]
    hops = []


    for snd,rcv in ans:


        if len(hops) > 0:
            if not isinstance(rcv.payload, TCP) or hops[-1] != rcv.src:
                hops.append(rcv.src)
        else:
            if not isinstance(rcv.payload, TCP):
                hops.append(rcv.src)

    return hops

#Given a list of IP addresses
#return the response code, blockpage detection and number of script tags (and maybe html)
def IPResponseCodesAndText(IPList):
    print("IPList: "+str(IPList))
    responseCodeList = []
    blockPageList = []
    cloudFlareBlockPageList = []
    number_of_script_tags = []
    html = []


    for IP in IPList:
        response = getIPResponseCodeAndText(IP)

        responseCodeList.append(response.get('Response_Code'))
        blockPageList.append(detectBlockPage(response.get('Visible_Text')))
        cloudFlareBlockPageList.append(detectCloudFlare(response.get('Visible_Text')))
        number_of_script_tags.append(response.get('number_of_script_tags'))

        html.append(response.get('html'))

    return {'responseCodeList':responseCodeList, 'blockPageList':blockPageList, 'cloudFlareBlockPageList':cloudFlareBlockPageList, 'number_of_script_tags':number_of_script_tags, 'html':html}


#Given an individual IP address, return the response code, visible text and number of script tags
def getIPResponseCodeAndText(IPAddress):
    if IPAddress == '' or IPAddress == None:
        return "NaN"
    try:
        #If requests takes longer than 5 seconds to connect, just return Error. Clearly some kind of failed connection
        print("IP ADDRESS----------------------------------: "+str(IPAddress))
        r = requests.get('http://'+IPAddress, timeout=5)
        return {'Response_Code': r.status_code, 'Visible_Text': text_from_html(r.text), 'number_of_script_tags':number_script_tags(r.text), 'html':r.text}

    except Exception as e:
        exce = str(e).replace(',',";")
        return {'Response_Code': "ERROR", 'Visible_Text': "N/A", 'number_of_script_tags': "N/A", 'html': "N/A"}


#Returns the IP Address IP list
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


#Returns the IP of the DNS I am connected too - doesn't work sometimes. Speedtest tells me the name of my ISP anyway.
def getMyDNS():
    dns_resolver = dns.resolver.Resolver()
    return dns_resolver.nameservers[0]


#Returns different ways to represent a domain name as a stirng
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

#Returns IP address of the user - not necesarily the public facing IP address. Speedtest tells me the public facing IP address.
def getIPAddress():
    #Returns IP address of the user
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    return IPAddr


#Returns a list of tuples to a dictionary
def convert_list_to_dict(this_list):
    return_dict = {}
    for DNS_Resolved_IPs in this_list:
        DNS_IP = DNS_Resolved_IPs[0]
        Resolved_IPs = DNS_Resolved_IPs[1]
        return_dict[DNS_IP] = Resolved_IPs
    return return_dict



#Returns latitude and longitude based off users IP address
def get_my_location_from_IP():
    g = geocoder.ip('me')
    return {'latitude':g.latlng[0], 'longitude':g.latlng[1], 'country':g.country}

'''
OBSOLETE CODE
def get_location_from_IP(ip):
    maxmind_account_id = 559831
    maxmind_liscence_key = '90CgLcF2UBUsWmKS'
    with geoip2.webservice.Client(maxmind_account_id, maxmind_liscence_key) as client:
        response = client.city(ip)
        return {'Country': response.country.name,'City':response.city.name, 'Latitude':response.location.latitude, 'Longitude':response.location.longitude}
'''
