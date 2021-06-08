import mysql.connector
import pymysql


def connect_to_database():
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

    print(cursor)
    db.close()
    print("Finished closing")


def main():
    print("hi")
    connect_to_database()

if __name__ == "__main__":
    main()


#ANALYSIS Functions

#See if script tag difference between IP's of different DNS's on same DNS
#->Implies DNS Tampering

#See if response code difference between ISP's

#See if Domain returns bad response/blockpage but IP returns legit page
#AND CHECK IF script tags matches at least one other ISP, that way it isn't just a random
#web page


#Retrieving from DB Functions

#Get all domains when domain = x
#Get all IP's when IP = x
