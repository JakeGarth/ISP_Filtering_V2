from website_functions import *
from domain import *
from CSV_Methods import *
from AWS_MySQL import convert_domain_to_database
import geocoder



#OBSOLETE CODE
'''
def writeObjectToCSV(obj, writeFile):
    resultsList = [obj.domain, obj.responseCode, obj.ISP_DNS, obj.ISP_DNS_IPS, obj.ISP_IP_Response_Code ,obj.Traceroute , obj.Hops_to_Domain ,  obj.AARC_DNS_IPs, obj.Optus_DNS_IPs, obj.Google_DNS, obj.Cloudflare_DNS, obj.AARC_DNS_Response_Code, obj.Optus_DNS_Response_Code, obj.Google_DNS_Response_Code, obj.Cloudflare_DNS_Response_Code,
    obj.domainBlockPage, obj.AARC_DNS_Block_Page, obj.Optus_DNS_Block_Page, obj.Google_DNS_Block_Page, obj.Cloudflare_DNS_Block_Page, obj.domainCloudFlareBlockPage, obj.AARC_DNS_Cloudflare_Block_Page, obj.Optus_DNS_Cloudflare_Block_Page, obj.Google_DNS_Cloudflare_Block_Page, obj.Cloudflare_DNS_Cloudflare_Block_Page, obj.Default_DNS_Block_Page, obj.Default_DNS_Cloudflare_Block_Page]

    writeToCSVMethod(resultsList, writeFile)
'''

#This function gets all the results for each domain and saves results in a domain object.
#The list of domain objects is parsed to 'convert_domain_to_database' to store in AWS.
def CalculateListOfDomains(openFile):
    #Iterates through the domains from 'openFile' and writes results to CSV
    websiteList = []
    with open(openFile) as fp:
        Lines = fp.readlines()
    for line in Lines:
        websiteList.append(line.strip('\n'))

    list_of_domain_objects = []


    for item in websiteList:
        #Just calculating different representations of the domain name.
        domain = item
        domainStripped = stripDomainName(domain)
        WebsiteNOHttp = domainStripped.get('WebsiteNOHttp')
        WebsiteNOHttpNoSlash  = domainStripped.get('WebsiteNOHttpNoSlash')
        WebsiteNoHttpNoWWWNoSlash  = domainStripped.get('WebsiteNoHttpNoWWWNoSlash')

        #Makes the objects. Each object then calculates its results
        obj = Domain(domain = domain,domainNoHTTP = WebsiteNOHttp,domainNoHTTPNoSlash = WebsiteNOHttpNoSlash, domainNoHTTPNoSlashNoWWW =  WebsiteNoHttpNoWWWNoSlash)

        #Stores each object in the list_of_domain_objects
        list_of_domain_objects.append(obj)

        #Writes domain object to AWS RDS
    convert_domain_to_database(list_of_domain_objects = list_of_domain_objects, isp_name = "TEST_25_May")




def main():
    #print("connect to online mysql")
    #print(get_my_location_from_IP())
    #print(speed_test())
    CalculateListOfDomains("List_of_Domains.txt")

if __name__ == "__main__":

    main()
