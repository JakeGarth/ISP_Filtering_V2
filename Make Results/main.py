from website_functions import *
from domain import *
from CSV_Methods import *
from AWS_MySQL import *
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

    #get user details
    user_ISP = input("What ISP are you using?")
    user_fullname = input("What is your name?")
    user_email = input("What is your email? ")
    time_now = time.strftime('%Y-%m-%d %H:%M:%S')

    #connect to database here
    connection_dictionary = connect_to_database()
    db = connection_dictionary.get('db')
    cursor = connection_dictionary.get('cursor')
    #Make and insert ISP here
    insert_ISP(db = db, cursor = cursor, isp_name = user_ISP, user_fullname = user_fullname, user_email = user_email, time_now = time_now)
    #get most recently insert ISP id
    ispID = get_most_recent_ISP_id(cursor = cursor, isp_name = user_ISP, time_now = time_now)

    print(ispID)
    #Make and Insert DNS servers here
    insert_DNSs(db = db, cursor = cursor, ispID = ispID)

    DNS_dict = get_most_recent_DNS_ids(cursor = cursor)
    DNS_names = DNS_dict.keys()


    #collect the dnsID's here, and don't change them, this will hopefully stop any concurrency issues


    #Iterates through the domains from 'openFile' and writes results to CSV


    websiteList = []
    with open(openFile) as fp:
        Lines = fp.readlines()
    for line in Lines:
        websiteList.append(line.strip('\n'))

    list_of_domain_objects = []


    for item in websiteList:
        #Just calculating different representations of the domain name.
        domain_string = item
        domainStripped = stripDomainName(domain_string)
        WebsiteNOHttp = domainStripped.get('WebsiteNOHttp')
        WebsiteNOHttpNoSlash  = domainStripped.get('WebsiteNOHttpNoSlash')
        WebsiteNoHttpNoWWWNoSlash  = domainStripped.get('WebsiteNoHttpNoWWWNoSlash')

        #Makes the objects. Each object then calculates its results
        domain = Domain(domain = domain_string, domainNoHTTP = WebsiteNOHttp,domainNoHTTPNoSlash = WebsiteNOHttpNoSlash, domainNoHTTPNoSlashNoWWW =  WebsiteNoHttpNoWWWNoSlash)
        DNS_ID_List_In_Database = insert_domain(db = db, cursor = cursor, domain = domain, dns_ips = DNS_names)
        print(DNS_ID_List_In_Database)
        insert_IPs(db = db, cursor = cursor, domain = domain, DNS_ID_List_In_Database = DNS_ID_List_In_Database)
    db.close()


    '''
        #Stores each object in the list_of_domain_objects
        list_of_domain_objects.append(obj)
    '''
        #instead of append to list, just insert to database

        #Writes domain object to AWS RDS

    #convert_domain_to_database(list_of_domain_objects = list_of_domain_objects, isp_name = user_ISP, user_fullname = user_fullname, user_email = user_email)




def main():
    #print("connect to online mysql")
    #print(get_my_location_from_IP())
    #print(speed_test())
    CalculateListOfDomains("List_of_Domains.txt")

if __name__ == "__main__":

    main()
