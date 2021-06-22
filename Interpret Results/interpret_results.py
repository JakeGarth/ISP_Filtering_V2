import mysql.connector
import pymysql
import pandas as pd
import json

def get_results_from_CSV(filename):
    return pd.read_csv(filename)

def get_list_of_domains(df):
    return df.domain_name.unique()

def get_list_of_IPs(df):
    return df.address.unique()

def get_list_of_ISPs(df):
    return df.isp_name_speedtest.unique()


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

    domain_indexes = df.index[df['domain_name'] == domain_string].tolist()
    for row in domain_indexes:

        if is_domain_live_from_domain_name_request(domain_rows.loc[row]) == True:
            is_domain_live = True
            break
            #isn't going to work because what if is_doman_live is false in first instance, need to make list and return it at the end
    for row in domain_indexes:
        insert_into_dataframe(column_name = 'domain_is_live_anywhere', row_number = row, data = is_domain_live, df=df)
    #List of results
    #Return array of results for each row
    return is_domain_live

def insert_if_domain_request_works(df):
    #iterate over all rows in dataframe
    for row in range(df.index[-1]+1):

        #print(df.index[-1])
        if is_domain_live_from_domain_name_request(df.loc[row]):
            insert_into_dataframe('domain_request_works',row,True,df)
        else:
            insert_into_dataframe('domain_request_works',row,False,df)

#in progress - need to make it so
def insert_if_IP_live_anywhere(IP_string, df):
    IP_rows = get_all_rows_of_IP(IP_string, df)

    is_IP_live = False


    IP_indexes = df.index[df['address'] == IP_string].tolist()


    for row in IP_indexes:
        if is_domain_live_from_IP_request(IP_rows.loc[row]) == True:
            is_IP_live = True
            break
            #isn't going to work because what if is_doman_live is false in first instance, need to make list and return it at the end

    for row in IP_indexes:

        insert_into_dataframe(column_name = 'ip_is_live_anywhere', row_number = row, data = is_IP_live, df=df)
    #List of results
    #Return array of results for each row
    return is_IP_live

def insert_if_IP_request_works(df):
    #iterate over all rows in dataframe
    for row in range(df.index[-1]+1):
        if is_domain_live_from_IP_request(df.loc[row]):
            insert_into_dataframe('ip_request_works',row,True,df)
        else:
            insert_into_dataframe('ip_request_works',row,False,df)


def get_all_rows_of_domain(domain_string, df):
    return df.loc[df['domain_name'] == domain_string]

def get_all_rows_of_IP(IP_string, df):
    return df.loc[df['address'] == IP_string]

def get_all_rows_of_ISP_and_Domain(ISP_string, Domain_string, df):
    sub_df = df.loc[df['domain_name'] == Domain_string].loc[df['isp_name_speedtest'] == ISP_string]
    try:
        return sub_df.index.tolist()
    except:
        return []

def get_list_of_IPs_from_default_dns(indexes_list, df):
    sub_df = df.loc[indexes_list].loc[df['default_dns'] == 1]
    return sub_df['address'].tolist()

def get_list_of_IPs_from_public_dns(indexes_list, df):
    sub_df = df.loc[indexes_list].loc[df['default_dns'] == 0]
    return sub_df['address'].tolist()


def detect_IP_not_in_non_default_DNS(list_of_domains, list_of_ISPs, df):
    for domain in list_of_domains:
        for ISP in list_of_ISPs:
            default_dns_ip_not_in_public_dns = False

            indexes_list = get_all_rows_of_ISP_and_Domain(ISP, domain, df)

            if len(indexes_list) > 0:
                default_dns_ips = get_list_of_IPs_from_default_dns(indexes_list, df)
                public_dns_ips = get_list_of_IPs_from_public_dns(indexes_list, df)
                default_dns_script_tags = 0
                public_dns_script_tags = 0

            for ip in default_dns_ips:

                if ip not in public_dns_ips:
                    default_dns_ip_not_in_public_dns = True

            for index in indexes_list:
                insert_into_dataframe('default_dns_returns_different_ip_addresses',index,default_dns_ip_not_in_public_dns,df)


def insert_if_IP_is_modal(domain_string, modal_ips_list, df):
    domain_indexes = df.index[df['domain_name'] == domain_string].tolist()
    for row in domain_indexes:

        if df.loc[row]['address'] not in modal_ips_list:
            insert_into_dataframe('public_dns_ips_not_mode', row, 'True', df)

        else:
            insert_into_dataframe('public_dns_ips_not_mode', row, 'False', df)

def return_modal_ip_address_returned_by_public_DNSs(domain_string, df):

    #Makes a sub df of all the public dns's that returned an ip for a domain
    sub_df = df.loc[df['domain_name'] == domain_string].loc[df['default_dns'] == 0]

    print("sub_df------------")
    print(sub_df)
    #get the frequency of each ip
    frequency_series = sub_df['address'].value_counts()
    mode = frequency_series[0]
    dict = json.loads(frequency_series.to_json())

    #return the most frequent in a list
    modal_ips = [k for k,v in dict.items() if float(v) == mode]

    print("domain: "+domain_string+" dict: "+str(dict)+" modal_ips: "+str(modal_ips))

    return modal_ips







def prepare_dataframe_for_analysis(df):
    #sorting by domain so analysis is easier. I.e. the same domains are adjacent to eachother
    df.sort_values('domain_name')

    #inserting new columns
    df['domain_is_live_anywhere'] = ""
    df['domain_request_works'] = ""
    df['ip_is_live_anywhere'] = ""
    df['ip_request_works'] = ""
    df['default_dns_returns_different_ip_addresses'] = ""
    df['default_dns_returns_different_script_tags'] = ""
    df['public_dns_ips_not_mode'] = ""


def insert_into_dataframe(column_name,row_number,data,df):

    df[column_name][row_number] = data


def output_data_frame_to_CSV(filename, df):
    df.to_csv(filename, encoding='utf-8', index=False)

def main():
    #Reads dataframe from CSV
    df = get_results_from_CSV('data - test.csv')

    #Inserts additional columns in to dataframe
    prepare_dataframe_for_analysis(df)

    #gather list of unique domain names
    list_of_domains = get_list_of_domains(df)
    #gather list of unique IP addresses
    list_of_IPs = get_list_of_IPs(df)
    #gather list of unique ISPs
    list_of_ISPs = get_list_of_ISPs(df)

    #inserts in to df whether the domain has been found to be live anywhere within the data
    for domain in list_of_domains:
        is_it_live_anywhere = insert_if_domain_live_anywhere(domain, df)

    #inserts in to df whether the domain request works on that ISP
    does_the_domain_request_work = insert_if_domain_request_works(df)

    #Insert in to df whether the IP has been found to be live anywhere within the data
    for IP in list_of_IPs:
        is_IP_live_anywhere = insert_if_IP_live_anywhere(IP, df)

    #inserts in to df whether the IP request works
    insert_if_IP_request_works(df)

    #Detects if DNS is poisoned
    detect_IP_not_in_non_default_DNS(list_of_domains, list_of_ISPs, df)

    #gets list of mode of ip addresses returned by public DNS's across all ISPs
    for domain in list_of_domains:
        modal_ips_list = return_modal_ip_address_returned_by_public_DNSs(domain, df)
        insert_if_IP_is_modal(domain, modal_ips_list, df)


    #puts results to csv
    output_data_frame_to_CSV("analysis_results.csv", df)



if __name__ == "__main__":
    main()


#ANALYSIS Functions
#See if a domain is live in any other ISP_DNS


#See if script tag difference between IP's of different DNS's on same ISP
#->Implies DNS Tampering

#See if response code difference between ISP's

#See if Domain returns bad response/blockpage but IP returns legit page
#AND CHECK IF script tags matches at least one other ISP, that way it isn't just a random
#web page

#see if ip address is found in other ISPs, if so, do the script tags match

#to detect DNS interception/injection, see if public DNS servers differ in their responses from other ISP's

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
