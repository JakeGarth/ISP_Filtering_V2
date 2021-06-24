import mysql.connector
import pymysql
import pandas as pd
import numpy as np
import math
import json
from itertools import product


#Code for penultimate analysis ---------------------------------
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

        if is_domain_live_from_domain_name_request(df.loc[row]):
            insert_into_dataframe('domain_request_works',row,True,df)
        else:
            insert_into_dataframe('domain_request_works',row,False,df)

def get_all_rows_ignoring_ISP(ignored_ISP, df):
    ignored_ISP_df = df.loc[df['isp_name_speedtest'] != ignored_ISP]
    return df.loc[df['isp_name_speedtest'] != ignored_ISP]

def insert_if_IP_live_other_ISP(IP_string, ignored_ISP,df):

    IP_rows = get_all_rows_of_IP(IP_string, df)

    #IP_rows = get_all_rows_ignoring_ISP(ignored_ISP, IP_rows)

    is_IP_live_in_other_ISP = False
    IP_indexes = IP_rows.index.tolist()




    for row in IP_indexes:
        if is_domain_live_from_IP_request(IP_rows.loc[row]) == True and IP_rows.loc[row]['isp_name_speedtest'] != ignored_ISP:

            is_IP_live_in_other_ISP = True
            break
            #isn't going to work because what if is_doman_live is false in first instance, need to make list and return it at the end

    for row in IP_indexes:

        insert_into_dataframe(column_name = 'ip_is_live_in_other_ISPs', row_number = row, data = is_IP_live_in_other_ISP, df=df)
    #List of results
    #Return array of results for each row

    return is_IP_live_in_other_ISP

def insert_if_IP_live_anywhere(IP_string, df):
    IP_rows = get_all_rows_of_IP(IP_string, df)


    is_IP_live = False
    IP_indexes = df.index[df['address'] == IP_string].tolist()

    for row in IP_indexes:

        if is_domain_live_from_IP_request(IP_rows.loc[row]) == True:
            is_IP_live = True
            break
            #isn't going to work because what if is_doman_live is false in first instance, need to make list and return it at the end
        #raise ValueError

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

def get_all_rows_of_ISP(ISP_string, df):
    return df.loc[df['isp_name_speedtest'] == ISP_string]


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

def get_list_of_Script_Tags_from_default_dns(indexes_list, df):
    sub_df = df.loc[indexes_list].loc[df['default_dns'] == 1]
    return sub_df['ip_number_of_script_tags'].tolist()

def get_list_of_Script_Tags_from_public_dns(indexes_list, df):
    sub_df = df.loc[indexes_list].loc[df['default_dns'] == 0]
    return sub_df['ip_number_of_script_tags'].tolist()


def detect_IP_not_in_non_default_DNS(list_of_domains, list_of_ISPs, df):
    for domain in list_of_domains:
        for ISP in list_of_ISPs:
            default_dns_ip_not_in_public_dns = False

            indexes_list = get_all_rows_of_ISP_and_Domain(ISP, domain, df)

            if len(indexes_list) > 0:
                default_dns_ips = get_list_of_IPs_from_default_dns(indexes_list, df)
                public_dns_ips = get_list_of_IPs_from_public_dns(indexes_list, df)

            else:
                default_dns_ips = []
                public_dns_ips = []

            for ip in default_dns_ips:

                if ip not in public_dns_ips:
                    default_dns_ip_not_in_public_dns = True

            for index in indexes_list:
                insert_into_dataframe('default_dns_returns_different_ip_addresses',index,default_dns_ip_not_in_public_dns,df)

def detect_Sript_Tags_not_in_non_default_DNS(list_of_domains, list_of_ISPs, df):
    for domain in list_of_domains:
        for ISP in list_of_ISPs:
            default_dns_script_tags_not_in_public_dns = False

            indexes_list = get_all_rows_of_ISP_and_Domain(ISP, domain, df)

            if len(indexes_list) > 0:
                default_dns_script_tags = get_list_of_Script_Tags_from_default_dns(indexes_list, df)
                public_dns_script_tags = get_list_of_Script_Tags_from_public_dns(indexes_list, df)

            else:
                default_dns_script_tags = []
                public_dns_script_tags = []

            #Converts NaN's to -1 so they can be compared easily
            for i in range(len(default_dns_script_tags)):
                if math.isnan(default_dns_script_tags[i]):
                    default_dns_script_tags[i] = -1

            #Converts NaN's to -1 so they can be compared easily
            for i in range(len(public_dns_script_tags)):
                if math.isnan(public_dns_script_tags[i]):
                    public_dns_script_tags[i] = -1


            for ip in default_dns_script_tags:
                if ip not in public_dns_script_tags:
                    default_dns_script_tags_not_in_public_dns = True

            for index in indexes_list:
                insert_into_dataframe('default_dns_returns_different_script_tags',index,default_dns_script_tags_not_in_public_dns,df)

def detect_if_script_tags_match_other_ISPs():
    pass



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

    #get the frequency of each ip
    frequency_series = sub_df['address'].value_counts()
    mode = frequency_series[0]
    dict = json.loads(frequency_series.to_json())

    #return the most frequent in a list
    modal_ips = [k for k,v in dict.items() if float(v) == mode]

    return modal_ips


def prepare_dataframe_for_analysis(df):
    #sorting by domain so analysis is easier. I.e. the same domains are adjacent to eachother
    df.sort_values('domain_name')

    #inserting new columns
    df['domain_is_live_anywhere'] = ""
    df['domain_request_works'] = ""
    df['ip_is_live_anywhere'] = ""
    df['ip_is_live_in_other_ISPs'] = ""
    df['ip_request_works'] = ""
    df['default_dns_returns_different_ip_addresses'] = ""
    df['default_dns_returns_different_script_tags'] = ""
    df['public_dns_ips_not_mode'] = ""


def insert_into_dataframe(column_name,row_number,data,df):

    df[column_name][row_number] = data


def output_data_frame_to_CSV(filename, df):
    df.to_csv(filename, encoding='utf-8', index=False)

def compares_results(input_file, output_file):
    #Reads dataframe from CSV
    df = get_results_from_CSV(input_file)

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

    #Insert in to df whether the IP has been found to be live in any other ISP
    for IP in list_of_IPs:
        for ISP in list_of_ISPs:

            is_IP_live_anywhere = insert_if_IP_live_other_ISP(IP, ISP, df)



    #inserts in to df whether the IP request works
    insert_if_IP_request_works(df)

    #Detects if DNS is poisoned
    detect_IP_not_in_non_default_DNS(list_of_domains, list_of_ISPs, df)

    #Detects if there is a mismatch between default DNS number of script tags and public DNS
    detect_Sript_Tags_not_in_non_default_DNS(list_of_domains, list_of_ISPs, df)

    #gets list of mode of ip addresses returned by public DNS's across all ISPs
    for domain in list_of_domains:
        modal_ips_list = return_modal_ip_address_returned_by_public_DNSs(domain, df)
        insert_if_IP_is_modal(domain, modal_ips_list, df)

    #outs results to csv
    output_data_frame_to_CSV(output_file, df)

    return df



#Code for final analysis --------------------------------------------------------------

def create_empty_dataframe_for_final_analysis():
    data = {
    'isp': [],
	'domain':[],
    'domain_name_blocking':[],
    'ip_blocking':[],
    'dns_poisoned':[],
    'dns_injection':[]
    }
    #create dataframe
    df = pd.DataFrame(data)



    new_row = {'isp':'Geo', 'domain':87}
    #append row to the dataframe
    df = df.append(new_row, ignore_index=True)
    return df

def get_set_of_combinations_ISP_Domain_from_Intermediate(intermediate_df):
    list_of_all_combinations_analysed_as_tuples = set()
    for index, row in intermediate_df.iterrows():
        isp_domain_tuple = (row['isp_name_speedtest'],row['domain_name'])
        if isp_domain_tuple not in list_of_all_combinations_analysed_as_tuples:
            list_of_all_combinations_analysed_as_tuples.add(isp_domain_tuple)

    return list_of_all_combinations_analysed_as_tuples


def outputs_analysis_for_each_domain_each_ISP(final_analysis_file, intermediate_df):
    df = create_empty_dataframe_for_final_analysis()
    ISP_Domain_set = get_set_of_combinations_ISP_Domain_from_Intermediate(intermediate_df)

    #Iterate through set of combos of ISP x Domain
    for row in ISP_Domain_set:
        isp_name = row[0]
        domain_name = row[1]
        sub_df_indexes = get_all_rows_of_ISP_and_Domain(isp_name, domain_name, intermediate_df)
        sub_df = intermediate_df.loc[sub_df_indexes]

        domain_name_blocked = detect_domain_name_blocking(sub_df)
        dns_poisoned = detect_DNS_Poison(sub_df)
        IP_blocking = detect_IP_Blocking(sub_df)
        dns_injection = detect_DNS_Injection(sub_df)

        new_row = {'isp':isp_name, 'domain':domain_name, 'domain_name_blocking':domain_name_blocked,
        'dns_poisoned':dns_poisoned,'ip_blocking': IP_blocking, 'dns_injection': dns_injection}

        df = df.append(new_row, ignore_index=True)
    print(df)
    output_data_frame_to_CSV(final_analysis_file, df)

    return df

def detect_domain_name_blocking(sub_df):
    domain_is_live_anywhere = False
    domain_request_works = False

    domain_name_blocking_detected = False
    for index, row in sub_df.iterrows():
        if (row['domain_is_live_anywhere'] == True
        and row['domain_request_works'] == False
        and row['default_dns_returns_different_ip_addresses'] == False):
            if (row['ip_request_works'] == False and row['ip_is_live_anywhere'] == True):
                domain_name_blocking_detected = False

            else:
                domain_name_blocking_detected = True
                break
                #return false because this implies IP blocking
        #need some way to check if the IP works anywhere else, the IP address has to match what the mode is doing,
        #because, this would imply the IP address is working as intended, but, the domain is now

    return domain_name_blocking_detected


def detect_DNS_Poison(sub_df):
    default_DNS_Poisoned = False
    for index, row in sub_df.iterrows():
        if row['default_dns_returns_different_ip_addresses'] == True:
            default_DNS_Poisoned = True
            break
        else:
            default_DNS_Poisoned = False
    return default_DNS_Poisoned

def detect_IP_Blocking(sub_df):

    #DO SOMETHING HERE JAKE
    IP_Blocked = False

    for index, row in sub_df.iterrows():
        #Checks if the domain doesnt work but was found to work elsewhere - might need to get rid of this
        if (row['domain_request_works'] == False and row['domain_is_live_anywhere'] == True):
            #Checks if IP address is blocked too, and IP was found to work somewhere else
            if (row['ip_request_works'] == False and row['ip_is_live_in_other_ISPs'] == True):
                IP_Blocked = True
                break
    return IP_Blocked


def detect_DNS_Injection(sub_df):
    #DO SOMETHING HERE JAKE
    DNS_injection = False
    for index, row in sub_df.iterrows():
        #Checks if the DNS is a public DNS, and also whether the public DNS returns a non-modal IP
        if row['default_dns'] == 0 and row['public_dns_ips_not_mode'] == True:
            DNS_injection = True
            break

    return DNS_injection



def main():
    input_file = 'data.csv'
    output_file = 'analysis_results.csv'
    final_analysis_file = 'isp_domain.csv'
    intermediate_df = compares_results(input_file, output_file)
    outputs_analysis_for_each_domain_each_ISP(final_analysis_file, intermediate_df)



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
