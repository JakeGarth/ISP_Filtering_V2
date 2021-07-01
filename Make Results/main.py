from website_functions import *
from domain import *
from CSV_Methods import *
from AWS_MySQL import *
import geocoder
import sys
import logging


#This function gets all the results for each domain and saves results in a domain object.



def CalculateListOfDomains(openFile):

    #get user details
    user_ISP = input("What ISP are you using?")
    user_fullname = input("What is your name?")
    user_email = input("What is your email? ")
    time_now = time.strftime('%Y-%m-%d %H:%M:%S')

    '''
    old_stdout = sys.stdout
    log_file = open("message.log","w")
    sys.stdout = log_file
    '''

    level    = logging.INFO
    format   = '  %(message)s'
    handlers = [logging.FileHandler('filename.log'), logging.StreamHandler()]

    logging.basicConfig(level = level, format = format, handlers = handlers)
    logging.info('Starting Data Collection!')
    #connect to database here

    connection_dictionary = connect_to_database()
    db = connection_dictionary.get('db')
    cursor = connection_dictionary.get('cursor')
    logging.info("Connected to Database Successfully")
    #Make and insert ISP here
    insert_ISP(db = db, cursor = cursor, isp_name = user_ISP, user_fullname = user_fullname, user_email = user_email, time_now = time_now)
    logging.info("Inserted ISP details in to Database")
    #get most recently insert ISP id
    ispID = get_most_recent_ISP_id(cursor = cursor, isp_name = user_ISP, time_now = time_now)


    #Make and Insert DNS servers here
    insert_DNSs(db = db, cursor = cursor, ispID = ispID)
    logging.info("Inserted Default and Public DNS Details in to Database")

    DNS_dict = get_most_recent_DNS_ids(cursor = cursor)
    DNS_names = DNS_dict.keys()

    websiteList = []
    with open(openFile) as fp:
        Lines = fp.readlines()
    for line in Lines:
        websiteList.append(line.strip('\n'))

    list_of_domain_objects = []

    logging.info("Now starting the data collection of domains...")
    for item in websiteList:

        #Just calculating different representations of the domain name.
        try:
            logging.info("Domain being checked: "+str(item))
            domain_string = item
            domainStripped = stripDomainName(domain_string)
            WebsiteNOHttp = domainStripped.get('WebsiteNOHttp')
            WebsiteNOHttpNoSlash  = domainStripped.get('WebsiteNOHttpNoSlash')
            WebsiteNoHttpNoWWWNoSlash  = domainStripped.get('WebsiteNoHttpNoWWWNoSlash')

            #Makes the objects. Each object then calculates its results
            domain = Domain(domain = domain_string, domainNoHTTP = WebsiteNOHttp,domainNoHTTPNoSlash = WebsiteNOHttpNoSlash, domainNoHTTPNoSlashNoWWW =  WebsiteNoHttpNoWWWNoSlash)
            DNS_ID_List_In_Database = insert_domain(db = db, cursor = cursor, domain = domain, dns_ips = DNS_names)
            insert_IPs(db = db, cursor = cursor, domain = domain, DNS_ID_List_In_Database = DNS_ID_List_In_Database)
        except Exception as e:
            logging.info("ERROR!")
            logging.info(str(e))

    db.close()
    '''
    sys.stdout = old_stdout
    log_file.close()
    '''
    '''
        #Stores each object in the list_of_domain_objects
        list_of_domain_objects.append(obj)
    '''
        #instead of append to list, just insert to database

        #Writes domain object to AWS RDS

    #convert_domain_to_database(list_of_domain_objects = list_of_domain_objects, isp_name = user_ISP, user_fullname = user_fullname, user_email = user_email)




def main():
    CalculateListOfDomains("List_of_Domains.txt")

if __name__ == "__main__":

    main()
