
import sys
import boto3
import mysql.connector
import os
import pymysql
import time
from website_functions import listOfDNSs, convert_list_to_dict


def convert_domain_to_database(list_of_domain_objects, isp_name):
    print("Converting Data to Database")
    print("connecting to online mysql")
    ENDPOINT="database-2.cuzgntwsj1dy.us-east-2.rds.amazonaws.com"
    PORT="3306"
    USR="admin"
    PW = "Cyberhub"
    REGION="us-east-2a"
    DBNAME="database-2"



    db = pymysql.connect(host = ENDPOINT, user = USR, password = PW)

    cursor = db.cursor()

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



    #MAKE A ISP Object in the DB - Done

    sql = '''
    insert into ISP(isp_name, time_date) values('%s', '%s')''' % (isp_name,time_now)
    cursor.execute(sql)
    db.commit()

    print("INSERTED ISP OBJECT^")
    #MAKE A DNS Object in the DB - nearly done, need to change one of the columns to point to ISP id, not domain
    sql = '''
    (SELECT id FROM ISP WHERE (isp_name = '%s' AND time_date = '%s'))''' % (isp_name, time_now)
    cursor.execute(sql)
    ispID = cursor.fetchone()[0]

    print(type(ispID))
    print(ispID)
    print("THE ID^")





    dns_ips = listOfDNSs()[1]


    print("dns_ips: ------------")
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
            #SOMETIMES DEFAULT DNS CAN BE SAME AS A PUBLIC ONE, MIGHT NEED TO CHANGE


        sql = '''
        insert into DNS(dns_address, dns_name, dns_public, ispID, default_dns) values('%s', '%s', '%s', '%s', '%s')''' % (dns_address, dns_name, dns_public, ispID, default_dns)
        cursor.execute(sql)
        db.commit()




    #Some kind of for loop

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





        DNS_ID_List_In_Database = {}
        for DNS in dns_ips:

            sql = '''
            (SELECT id FROM DNS WHERE (dns_name = '%s'))''' % (DNS)
            cursor.execute(sql)

            DNS_IDs = cursor.fetchall()

            #Get most recent DNS Inserted, might need to change this to do some kind of lock, maybe need to select the one with the same ISP id?
            DNS_ID = DNS_IDs[-1][0]

            sql = '''
            insert into Domain(domain_name, response_code, Traceroute , Number_of_Hops, cloudflare_blockpage, blockpage, dnsID)
            values('%s', '%s', '%s', '%s', '%s','%s', '%s')''' % (domain_name, response_code, Traceroute, Number_of_Hops, cloudflare_blockpage, blockpage, DNS_ID)
            cursor.execute(sql)
            domainID = cursor.lastrowid
            DNS_ID_List_In_Database[DNS] = domainID
            db.commit()


        print("DNS_ID_List_In_Database:---------")
        print(DNS_ID_List_In_Database)

        #list of all IPs returned by all the DNSs

        All_IPs_From_All_DNS = convert_list_to_dict(domain.Resolved_IPs)
        ip_to_dns_dict = listOfDNSs()[2]




        #This code inserts the IP requests in to the database
        print("All_IPs_From_All_DNS:----------")
        print(All_IPs_From_All_DNS)


        print("ip_to_dns_dict:-----------------------")
        print(ip_to_dns_dict)

        print("Response_Code_Different_DNS_List:--------------")
        print(domain.Response_Code_Different_DNS_List())


        for dns_ip in All_IPs_From_All_DNS:
            dns_ip = dns_ip

            dns_name = ip_to_dns_dict.get(dns_ip)


            response_code_list = domain.Response_Code_Different_DNS_List().get(dns_name)

            ip_blockpage_list = domain.IPBlockPageList().get(dns_name)
            ip_cloudflare_blockpage_list = domain.IPCloudFlareBlockPageList().get(dns_name)


            count_position_of_ip = 0
            for ip in All_IPs_From_All_DNS.get(dns_ip):
                print("count: "+str(count_position_of_ip))
                print("ip: "+str(ip))
                print("response_code_list:-----")
                print(response_code_list)
                response_code = response_code_list[count_position_of_ip] #fix this
                blockpage = ip_blockpage_list[count_position_of_ip]
                cloudflare_blockpage = ip_cloudflare_blockpage_list[count_position_of_ip]
                count_position_of_ip += 1



                if dns_name == 'Google' or dns_name == 'Optus': #should fix this later, this is bad code design
                    dns_name += 'DNS'

                if dns_name == 'AARC':
                    dns_name = 'AARNet'

                domainID = DNS_ID_List_In_Database.get(dns_name)

                sql = '''
                    insert into Request(address, DNS_DELETELATER, domainID, response_code, blockpage, cloudflare_blockpage)

                    values('%s', '%s', '%s', '%s', '%s', '%s')''' % (ip, dns_name, domainID, response_code, blockpage, cloudflare_blockpage)
                cursor.execute(sql)
                db.commit()




def show_ips():

    ENDPOINT="database-2.cuzgntwsj1dy.us-east-2.rds.amazonaws.com"
    PORT="3306"
    USR="admin"
    PW = "Cyberhub"
    REGION="us-east-2a"
    DBNAME="database-2"

    db = pymysql.connect(host = ENDPOINT, user = USR, password = PW)

    cursor = db.cursor()

    cursor.execute("select version()")
    print("cursor: "+str(cursor))

    data = cursor.fetchone()
    print(str(data))


    sql = '''use ISP'''
    print(cursor.execute(sql))

    sql = '''show tables'''
    print(cursor.execute(sql))

    sql = '''select * from Domain'''
    cursor.execute(sql)
    print(cursor.fetchall())

def create_table():
    print("CREATING TABLE")


def connect_AWS():
    print("connect to online mysql")
    ENDPOINT="database-2.cuzgntwsj1dy.us-east-2.rds.amazonaws.com"
    PORT="3306"
    USR="admin"
    PW = "Cyberhub"
    REGION="us-east-2a"
    DBNAME="database-2"

    db = pymysql.connect(host = ENDPOINT, user = USR, password = PW)

    cursor = db.cursor()

    cursor.execute("select version()")
    print("cursor: "+str(cursor))

    data = cursor.fetchone()
    print(str(data))


    sql = '''drop database kgptalkie'''
    cursor.execute(sql)

    sql = '''create database kgptalkie'''
    cursor.execute(sql)

    cursor.connection.commit()

    sql = '''use kgptalkie'''
    cursor.execute(sql)

    sql = '''
    create table person (
    id int not null auto_increment,
    fname text,
    lname text,
    primary key (id)
    )
    '''
    cursor.execute(sql)

    sql = '''
    create table test (
    id int not null auto_increment,
    test_one text,
    test_two text,
    primary key (id)
    )
    '''
    cursor.execute(sql)

    sql = '''show tables'''
    print(cursor.execute(sql))
    print(cursor.fetchall())

    sql = '''
    insert into person(fname, lname) values('%s', '%s')''' % ('laxmi', 'kant')
    cursor.execute(sql)
    db.commit()

    sql = '''select * from person'''
    cursor.execute(sql)
    print(cursor.fetchall())

    print("END!")


def main():



    #connect_AWS()
    convert_domain_to_database(domain_obj = None, isp_name = "TEST_20_May")
    #show_ips()

    #connect_AWS()

if __name__ == "__main__":

    main()
