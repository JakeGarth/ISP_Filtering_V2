
import sys
import boto3
import mysql.connector
import os
import pymysql
import time
import socket
from website_functions import listOfDNSs, convert_list_to_dict, getIPAddress, get_my_location_from_IP, speed_test
import geoip2.webservice



def convert_domain_to_database(list_of_domain_objects, isp_name):
    print("Converting Data to Database")
    print("connecting to online mysql")

    #Login to database
    ENDPOINT="database-2.cuzgntwsj1dy.us-east-2.rds.amazonaws.com"
    PORT="3306"
    USR="admin"
    PW = "Cyberhub"
    REGION="us-east-2a"
    DBNAME="database-2"
    db = pymysql.connect(host = ENDPOINT, user = USR, password = PW, use_unicode = True)
    cursor = db.cursor()
    # Enforce UTF-8 for the connection.
    cursor.execute('SET NAMES utf8mb4')
    cursor.execute("SET CHARACTER SET utf8mb4")
    cursor.execute("SET character_set_connection=utf8mb4")

    cursor.execute("select version()")
    print("cursor: "+str(cursor))

    data = cursor.fetchone()
    print(str(data))

    sql = '''use ISP'''
    cursor.execute(sql)

    sql = '''show tables'''
    print(cursor.execute(sql))

    tables = cursor.fetchall()

    print(tables)

    time_now = time.strftime('%Y-%m-%d %H:%M:%S')
    print(type(time_now))
    print(time_now)



    #MAKE A ISP Object in the DB
    user_ip_address = getIPAddress()
    Download_and_Upload = speed_test()
    lat_and_long = get_my_location_from_IP()
    sql = '''
    insert into ISP(isp_name, time_date, user_ip_address, Download_Speed, Upload_Speed, isp_name_speedtest, ping, public_ip_address, latitude, longitude, country) values('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')''' % (isp_name, time_now, user_ip_address,
    Download_and_Upload.get('download'), Download_and_Upload.get('upload'), Download_and_Upload.get('isp_name'), Download_and_Upload.get('ping'), Download_and_Upload.get('client_ip'),lat_and_long.get('latitude') , lat_and_long.get('longitude'), lat_and_long.get('country'))
    cursor.execute(sql)
    db.commit()

    print("INSERTED ISP OBJECT^")
    #Retrieve the ISP that was just inserted
    sql = '''
    (SELECT id FROM ISP WHERE (isp_name = '%s' AND time_date = '%s'))''' % (isp_name, time_now)
    cursor.execute(sql)
    ispID = cursor.fetchone()[0]



    #3 is for default and public DNS's only
    dns_ips = listOfDNSs()[1]
    print("DNS IPS------------------------------------")
    print(dns_ips)
    #this takes care of adding all the DNS's to the database
    for DNS in dns_ips:
        dns_address = dns_ips.get(DNS)
        dns_name = DNS
        if dns_name == 'MyDNS':
            dns_public = 0
            default_dns = 1
        else:
            dns_public = 1
            default_dns = 0
        sql = '''
        insert into DNS(dns_address, dns_name, dns_public, ispID, default_dns) values('%s', '%s', '%s', '%s', '%s')''' % (dns_address, dns_name, dns_public, ispID, default_dns)
        cursor.execute(sql)
        db.commit()

    #Adds 5 instances of the domain to the databse, one for each DNS
    for domain in list_of_domain_objects:

        domain_name = domain.domain
        response_code = domain.responseCode
        Traceroute = ' '.join([str(addr) for addr in domain.Traceroute])
        Number_of_Hops = domain.Hops_to_Domain
        cloudflare_blockpage = 0
        blockpage = 0
        if domain.domainCloudFlareBlockPage == True:
            cloudflare_blockpage = 1
        if domain.domainBlockPage == True:
            blockpage = 1
        number_script_tags = domain.Number_of_Script_Tags
        domain_html = db.escape(domain.domain_html.encode(encoding = "utf-8"))

        print("DOMAINS DEFAULT DNS IPS-------------------------------------------------------JAKE HERE 2")
        print(domain.ISP_DNS_IPS)



        DNS_ID_List_In_Database = {}
        for DNS in dns_ips:

            #Gets most recently added DNS servers
            sql = '''
            (SELECT id FROM DNS WHERE (dns_name = '%s'))''' % (DNS)
            cursor.execute(sql)

            DNS_IDs = cursor.fetchall()
            #Get most recent DNS Inserted, might need to change this to do some kind of lock, maybe need to select the one with the same ISP id?
            DNS_ID = DNS_IDs[-1][0]

            #Inserts the domains each associated with each DNS


            sql = '''
            insert into Domain(domain_name, response_code, Traceroute , Number_of_Hops, cloudflare_blockpage, blockpage, dnsID, number_of_script_tags, html_returned)
            values('%s', '%s', '%s', '%s', '%s','%s', '%s', '%s', %s)''' % (domain_name, response_code, Traceroute, Number_of_Hops, cloudflare_blockpage, blockpage, DNS_ID, number_script_tags, domain_html)

            cursor.execute(sql)
            domainID = cursor.lastrowid
            DNS_ID_List_In_Database[DNS] = domainID
            db.commit()


        #list of all IPs returned by all the DNSs
        print("domain.Resolved_IPs")
        print(domain.Resolved_IPs)
        All_IPs_From_All_DNS = domain.Resolved_IPs
        #2 is all DNS's in list
        #ip_to_dns_dict = listOfDNSs()[2]
        #3 is only default DNS and Google and Cloudlfare, i.e. public
        ip_to_dns_dict = listOfDNSs()[3]

        print("All_IPs_From_All_DNS---------------")
        print(All_IPs_From_All_DNS)



        #This code inserts the IP requests in to the database
        for dns_ip in All_IPs_From_All_DNS:
            #gathers all the results for each DNS
            dns_ip = dns_ip
            dns_name = ip_to_dns_dict.get(dns_ip)

            response_code_list = domain.Response_Code_Different_DNS_List().get(dns_name)
            ip_blockpage_list = domain.IPBlockPageList().get(dns_name)
            ip_cloudflare_blockpage_list = domain.IPCloudFlareBlockPageList().get(dns_name)
            ip_html_list = domain.IPHTMLPageList().get(dns_name)
            Number_of_Scripts_List = domain.Number_of_Scripts_Different_DNS_List.get(dns_name)

            print("All_IPs_From_All_DNS")
            print(All_IPs_From_All_DNS)
            print("response_code_list")
            print(response_code_list)
            print("ip_blockpage_list")
            print(ip_blockpage_list)

            print("DNS NAME")
            print(dns_name)


            count_position_of_ip = 0
            #iterates through all IP's for a given DNS

            print("List of all IPS")
            print(str(len(All_IPs_From_All_DNS.get(dns_ip))))
            print(str(All_IPs_From_All_DNS.get(dns_ip)))
            for ip in All_IPs_From_All_DNS.get(dns_ip):
                print("dns_ip")
                print(dns_ip)
                print("Ip")
                print(ip)
                #Gathers results for that IP
                response_code = response_code_list[count_position_of_ip] #fix this
                blockpage = ip_blockpage_list[count_position_of_ip]
                cloudflare_blockpage = ip_cloudflare_blockpage_list[count_position_of_ip]
                number_of_script_tags = Number_of_Scripts_List[count_position_of_ip]
                html = ip_html_list[count_position_of_ip]

                count_position_of_ip += 1

                #Fixes some name changes
                if dns_name == 'Google' or dns_name == 'Optus': #should fix this later, this is bad code design
                    dns_name += 'DNS'

                if dns_name == 'AARC':
                    dns_name = 'AARNet'

                domainID = DNS_ID_List_In_Database.get(dns_name)

                #need to rmeove first and last charaacters
                html_safe_for_MySQL = db.escape(html.encode(encoding = "utf-8"))
                #Insert the IP address in to the datbase
                sql = '''
                    insert into Request(address, DNS_DELETELATER, domainID, response_code, blockpage, cloudflare_blockpage, number_of_script_tags, html_returned)
                    values('%s', '%s', '%s', '%s', '%s', '%s', '%s', %s)''' % (ip, dns_name, domainID, response_code, blockpage, cloudflare_blockpage, number_of_script_tags, html_safe_for_MySQL)

                print("Inserted :"+str(ip))
                cursor.execute(sql)
                db.commit()
    db.close()

def main():
    convert_domain_to_database(domain_obj = None, isp_name = "TEST_31_May")



if __name__ == "__main__":

    main()
