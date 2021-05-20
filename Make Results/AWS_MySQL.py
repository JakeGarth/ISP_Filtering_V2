
import sys
import boto3
import mysql.connector
import os
import pymysql
import time


def convert_domain_to_database(domain_obj, isp_name):
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
    print(time_now)


    #MAKE A ISP Object in the DB - Done
    sql = '''
    insert into ISP(isp_name, time_date) values('%s', '%s')''' % (isp_name,time_now)
    cursor.execute(sql)
    db.commit()

    #MAKE A DNS Object in the DB - nearly done, need to change one of the columns to point to ISP id, not domain
    sql = '''
    insert into DNS(dns_address, dns_name, dns_public) values('%s', '%s', '%s')''' % ("test 3","test should be 1 here ->", 1)
    cursor.execute(sql)
    db.commit()

    #MAKE A Domain Object in the DB



def show_ips():
    print("Sowing IPS")
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
