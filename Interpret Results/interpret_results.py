import mysql.connector
import pymysql
import pandas as pd

def get_results_from_CSV():
    return pd.read_csv('data.csv')

def get_list_of_domains(df):
    return df.domain_name.unique()

def is_domain_live_from_domain_name_request(df_row):
    if df_row.response_code != '200' or df_row.blockpage == '0':
        return False
    else:
        return True

def is_domain_live_from_IP_request(df_row):
    if df_row.ip_response_code != '200' or df_row.ip_blockpage == True or df_row.ip_cloudflare_blockpage == True:
        return False
    else:
        return True

def is_domain_cloudflare_blocked(df_row):
    if df_row.ip_cloudflare_blockpage == True:
        return True
    else:
        return False

def insert_if_domain_live_anywhere(domain_string, df):
    domain_rows = get_all_rows_of_domain(domain_string, df)
    print(domain_rows)
    is_domain_live = False

    for row in range(domain_rows.index[0], domain_rows.index[-1]+1):

        if is_domain_live_from_domain_name_request(domain_rows.loc[row]) == True:
            is_domain_live = True
            break
            #isn't going to work because what if is_doman_live is false in first instance, need to make list and return it at the end
    for row in range(domain_rows.index[0], domain_rows.index[-1]+1):
        insert_into_dataframe(column_name = 'domain_is_live_anywhere', row_number = row, data = is_domain_live, df=df)
    #List of results
    #Return array of results for each row
    return is_domain_live

def insert_if_domain_request_works(df):

    #iterate over all rows in dataframe
    for row in range(df.index[-1]):
        if is_domain_live_from_domain_name_request(df.loc[row]):
            insert_into_dataframe('domain_request_works',row,True,df)
        else:
            insert_into_dataframe('domain_request_works',row,False,df)

def insert_if_IP_request_works(df):
    #iterate over all rows in dataframe
    for row in range(df.index[-1]):
        if is_domain_live_from_IP_request(df.loc[row]):
            insert_into_dataframe('ip_request_works',row,True,df)
        else:
            insert_into_dataframe('ip_request_works',row,False,df)


def get_all_rows_of_domain(domain_string, df):
    return df.loc[df['domain_name'] == domain_string]


def prepare_dataframe_for_analysis(df):
    #sorting by domain so analysis is easier. I.e. the same domains are adjacent to eachother
    df.sort_values('domain_name')

    #inserting new columns
    df['domain_is_live_anywhere'] = ""
    df['domain_request_works'] = ""
    df['ip_is_live_anywhere'] = ""
    df['ip_request_works'] = ""


def insert_into_dataframe(column_name,row_number,data,df):
    df[column_name][row_number] = data

def output_data_frame_to_CSV(filename, df):
    df.to_csv(filename, encoding='utf-8', index=False)

def main():
    #Reads dataframe from CSV
    df = get_results_from_CSV()

    #Inserts additional columns in to dataframe
    prepare_dataframe_for_analysis(df)

    #gather list of unique domain names
    list_of_domains = get_list_of_domains(df)

    #inserts in to df whether the domain has been found to be live anywhere within the data
    for domain in list_of_domains:
        is_it_live_anywhere = insert_if_domain_live_anywhere(domain, df)

    #inserts in to df whether the domain request works on that ISP
    does_the_domain_request_work = insert_if_domain_request_works(df)

    #inserts in to df whether the IP request works
    insert_if_IP_request_works(df)

    #puts results to csv
    output_data_frame_to_CSV("analysis_results.csv", df)

if __name__ == "__main__":
    main()


#ANALYSIS Functions
#See if a domain is live in any other ISP_DNS





#See if script tag difference between IP's of different DNS's on same DNS
#->Implies DNS Tampering

#See if response code difference between ISP's

#See if Domain returns bad response/blockpage but IP returns legit page
#AND CHECK IF script tags matches at least one other ISP, that way it isn't just a random
#web page


#Retrieving from DB Functions

#Get all domains when domain = x
#Get all IP's when IP = x

'''
def connect_to_database():


    #Login to database
    ENDPOINT="database-2.cuzgntwsj1dy.us-east-2.rds.amazonaws.com"
    PORT="3306"
    USR="admin"
    PW = "Cyberhub"
    REGION="us-east-2a"
    DBNAME="database-2"
    db = pymysql.connect(host = ENDPOINT, user = USR, password = PW, use_unicode = True)
    cursor = db.cursor()


    db.close()

'''
