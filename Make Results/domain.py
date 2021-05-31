from website_functions import *

class Domain:

    def __init__(self, domain="", domainNoHTTP = "", domainNoHTTPNoSlash = "", domainNoHTTPNoSlashNoWWW = "", responseCode="", ISP_DNS="", ISP_DNS_IPS="", ISP_IP_Response_Code=[], Hops_to_Domain=-1, Traceroute="", AARC_DNS_IPs="",
    Resolved_IPs = [], Optus_DNS_IPs="", Google_DNS="", Cloudflare_DNS="", Response_Code_Different_DNS_List={},AARC_DNS_Response_Code="", Optus_DNS_Response_Code="",Google_DNS_Response_Code="", Cloudflare_DNS_Response_Code="",
    Block_Page_Different_DNS_List ={}, AARC_DNS_Block_Page = "", Optus_DNS_Block_Page = "", Google_DNS_Block_Page = "", Cloudflare_DNS_Block_Page = "", domainBlockPage="",Cloudflare_Block_Page_Different_DNS_List = {},domainCloudFlareBlockPage="",
    AARC_DNS_Cloudflare_Block_Page = "", Optus_DNS_Cloudflare_Block_Page = "", Google_DNS_Cloudflare_Block_Page = "", Cloudflare_DNS_Cloudflare_Block_Page = "", Default_DNS_Block_Page = [], Default_DNS_Cloudflare_Block_Page = [], Number_of_Script_Tags = -1,
    Number_of_Scripts_Different_DNS_List = {}, AARC_DNS_Number_of_Script_Tags = "", Optus_DNS_Number_of_Script_Tags = "", Google_DNS_Number_of_Script_Tags = "", Cloudflare_DNS_Number_of_Script_Tags = "", Default_DNS_Number_of_Script_Tags = ""):


        #Raw Results
        self.__all_results = {}
        self.domain = domain
        self.domainNoHTTP =domainNoHTTP
        self.domainNoHTTPNoSlash = domainNoHTTPNoSlash
        self.domainNoHTTPNoSlashNoWWW = domainNoHTTPNoSlashNoWWW
        self.domain_concat_name = 'domain_{}'.format(stripDomainName(domain).get('WebsiteNoHttpNoWWWNoSlash').replace('.',""))

        if responseCode == "" or domainBlockPage == "" or domainCloudFlareBlockPage == "":
            self.domainResults = self.return_Response_Code()
        else:
            self.domainResults = None

        if responseCode == "":


            #bug here, I think that the return_Response_Code() is returning an error string, bug was caused when i was reading in results to the domain
            #it was unecessarilly calling the return_Response_Code() method, pretty sure this issue is resolved


            self.responseCode = self.domainResults.get('ResponseCode')
        else:

            self.responseCode = responseCode

        if domainBlockPage == "":

            self.domainBlockPage = self.domainResults.get('BlockPage')
        else:

            self.domainBlockPage = domainBlockPage

        if domainCloudFlareBlockPage == "":

            self.domainCloudFlareBlockPage = self.domainResults.get('CloudflareBlockPage')
        else:

            self.domainCloudFlareBlockPage = domainCloudFlareBlockPage


        if Number_of_Script_Tags == -1:

            self.Number_of_Script_Tags = self.domainResults.get('Number_of_Script_Tags')
            print("Do we get in here")
            print("self.domainResults")
            print(self.domainResults)
            print("self.domainResults.get('Number_of_Script_Tags')")
            print(self.domainResults.get('Number_of_Script_Tags'))

        else:
            self.Number_of_Script_Tags = Number_of_Script_Tags

        print("Number_of_Script_Tags in domain.py line 59")
        print(Number_of_Script_Tags)

        if ISP_DNS == "":
            self.ISP_DNS = self.return_DNS()
        else:
            self.ISP_DNS = ISP_DNS

        if ISP_DNS_IPS == "":

            ipList = self.return_ISP_IP_List()

            if isinstance(ipList, str):
                ipList = ipList.replace("[","").replace("]","").replace(" ","").replace("'","").split(";")
            self.ISP_DNS_IPS = ipList

        else:
            try:
                #splitting in to a list
                ipList = ISP_DNS_IPS
                self.ISP_DNS_IPS = ipList
            except Exception as e:
                self.ISP_DNS_IPS = ISP_DNS_IPS

        if Traceroute == "":
            self.Traceroute = self.tracerouteToDomain()
        else:
            self.Traceroute = Traceroute

        if Hops_to_Domain == -1:
            self.Hops_to_Domain = len(self.Traceroute)
        else:
            self.Hops_to_Domain = Hops_to_Domain

        if Resolved_IPs == []:


            self.Resolved_IPs = self.return_IPs_Different_DNS()



        else:
            self.Resolved_IPs = Resolved_IPs

        if AARC_DNS_IPs == "":
            self.AARC_DNS_IPs = self.Resolved_IPs[1][1]
        else:
            self.AARC_DNS_IPs = AARC_DNS_IPs

        if Optus_DNS_IPs == "":
            self.Optus_DNS_IPs = self.Resolved_IPs[2][1]
        else:
            self.Optus_DNS_IPs = Optus_DNS_IPs

        if Google_DNS == "":
            self.Google_DNS = self.Resolved_IPs[3][1]
        else:
            try:

                ipList = []
                for ip in Google_DNS:

                    ipList.append(ip.replace(" ","").replace("'",""))
                self.Google_DNS = ipList

            except Exception as e:

            #splitting in to a list
                self.Google_DNS = Google_DNS


        if Cloudflare_DNS == "":
            self.Cloudflare_DNS = self.Resolved_IPs[4][1]
        else:
            try:
                ipList = []
                for ip in Cloudflare_DNS:

                    ipList.append(ip.replace(" ","").replace("'",""))
                self.Cloudflare_DNS = ipList


            except Exception as e:

            #splitting in to a list
                self.Cloudflare_DNS = Cloudflare_DNS


        self.set_IP_All_Blockpages_All_Responses() #Sets all response codes, blockpage results

        if ISP_IP_Response_Code == []:

            self.ISP_IP_Response_Code = self.IPResponseCodesList().get('MyDNS')


        else:

            self.ISP_IP_Response_Code = ISP_IP_Response_Code


        if Default_DNS_Block_Page == []:


            self.Default_DNS_Block_Page = self.IPBlockPageList().get('MyDNS')

        else:

            self.Default_DNS_Block_Page = Default_DNS_Block_Page


        if Default_DNS_Cloudflare_Block_Page == []:
            self.Default_DNS_Cloudflare_Block_Page = self.IPCloudFlareBlockPageList().get('MyDNS')
        else:
            self.Default_DNS_Cloudflare_Block_Page = Default_DNS_Cloudflare_Block_Page


        self.Public_DNS_Ips = self.Google_DNS + self.Cloudflare_DNS

        if Response_Code_Different_DNS_List == {}:
            self.Response_Code_Different_DNS_List = self.IPResponseCodesList

        else:
            self.Response_Code_Different_DNS_List = Response_Code_Different_DNS_List

        if AARC_DNS_Response_Code == "":
            self.AARC_DNS_Response_Code = self.IPCloudFlareBlockPageList().get('AARC')
        else:
            self.AARC_DNS_Response_Code = AARC_DNS_Response_Code

        if Optus_DNS_Response_Code == "":
            self.Optus_DNS_Response_Code = self.IPCloudFlareBlockPageList().get('Optus')
        else:
            self.Optus_DNS_Response_Code = Optus_DNS_Response_Code

        if Google_DNS_Response_Code == "":
            self.Google_DNS_Response_Code = self.IPCloudFlareBlockPageList().get('Google')

        else:
            self.Google_DNS_Response_Code = Google_DNS_Response_Code

        if Cloudflare_DNS_Response_Code == "":
            self.Cloudflare_DNS_Response_Code = self.IPCloudFlareBlockPageList().get('Cloudflare')
        else:
            self.Cloudflare_DNS_Response_Code = Cloudflare_DNS_Response_Code

        self.Public_DNS_Response_Codes = self.Google_DNS_Response_Code + self.Cloudflare_DNS_Response_Code
        self.ISP_IP_in_Non_ISP_IP = self.Is_ISP_IP_In_NonISP_DNS_IP()


        #Results Analysis
        self.IntersectionOfPublicAndDefaultDNS = self.IPsInTwoLists(self.ISP_DNS_IPS, self.Public_DNS_Ips)

        #self.DomainBlockPage = self.

        #put in some blockpage lists and cloudflare page lists, exam same as "ISP_IP_in_Non_ISP_IP"



        if Block_Page_Different_DNS_List == {}:

            self.Block_Page_Different_DNS_List = self.IPBlockPageList()
        else:
            self.Block_Page_Different_DNS_List = Block_Page_Different_DNS_List

        if AARC_DNS_Block_Page == "":

            self.AARC_DNS_Block_Page = self.IPBlockPageList().get('AARC')
        else:
            self.AARC_DNS_Block_Page = AARC_DNS_Block_Page

        if Optus_DNS_Block_Page == "":
            self.Optus_DNS_Block_Page = self.IPBlockPageList().get('Optus')
        else:
            self.Optus_DNS_Block_Page = Optus_DNS_Block_Page

        if Google_DNS_Block_Page == "":
            self.Google_DNS_Block_Page = self.IPBlockPageList().get('Google')
        else:
            self.Google_DNS_Block_Page = Google_DNS_Block_Page

        if Cloudflare_DNS_Block_Page == "":
            self.Cloudflare_DNS_Block_Page = self.IPBlockPageList().get('Cloudflare')
        else:
            self.Cloudflare_DNS_Block_Page = Cloudflare_DNS_Block_Page

        self.Block_Page_Public_DNS_List =  self.Google_DNS_Block_Page + self.Cloudflare_DNS_Block_Page



        if Cloudflare_Block_Page_Different_DNS_List == {}:

            self.Cloudflare_Block_Page_Different_DNS_List = self.IPCloudFlareBlockPageList()
        else:
            self.Cloudflare_Block_Page_Different_DNS_List = Cloudflare_Block_Page_Different_DNS_List

        if AARC_DNS_Cloudflare_Block_Page == "":

            self.AARC_DNS_Cloudflare_Block_Page = self.Cloudflare_Block_Page_Different_DNS_List.get('AARC')
        else:
            self.AARC_DNS_Cloudflare_Block_Page = AARC_DNS_Cloudflare_Block_Page

        if Optus_DNS_Cloudflare_Block_Page == "":
            self.Optus_DNS_Cloudflare_Block_Page = self.Cloudflare_Block_Page_Different_DNS_List.get('Optus')
        else:
            self.Optus_DNS_Cloudflare_Block_Page = Optus_DNS_Cloudflare_Block_Page

        if Google_DNS_Cloudflare_Block_Page == "":
            self.Google_DNS_Cloudflare_Block_Page = self.Cloudflare_Block_Page_Different_DNS_List.get('Google')
        else:
            self.Google_DNS_Cloudflare_Block_Page = Google_DNS_Cloudflare_Block_Page

        if Cloudflare_DNS_Cloudflare_Block_Page == "":
            self.Cloudflare_DNS_Cloudflare_Block_Page = self.Cloudflare_Block_Page_Different_DNS_List.get('Cloudflare')
        else:
            self.Cloudflare_DNS_Cloudflare_Block_Page = Cloudflare_DNS_Cloudflare_Block_Page

        self.Cloudflare_Block_Page_Public_DNS_List = self.Google_DNS_Cloudflare_Block_Page + self.Cloudflare_DNS_Cloudflare_Block_Page


        if Number_of_Scripts_Different_DNS_List == {}:
            self.Number_of_Scripts_Different_DNS_List = self.NumberScriptTagList()
        else:
            self.Number_of_Scripts_Different_DNS_List = Number_of_Scripts_Different_DNS_List

        if AARC_DNS_Cloudflare_Block_Page == "":

            self.AARC_DNS_Number_of_Script_Tags = self.Number_of_Scripts_Different_DNS_List.get('AARC')
        else:
            self.AARC_DNS_Number_of_Script_Tags = AARC_DNS_Number_of_Script_Tags

        if Optus_DNS_Cloudflare_Block_Page == "":
            self.Optus_DNS_Number_of_Script_Tags = self.Number_of_Scripts_Different_DNS_List.get('Optus')
        else:
            self.Optus_DNS_Number_of_Script_Tags = Optus_DNS_Number_of_Script_Tags

        if Google_DNS_Cloudflare_Block_Page == "":
            self.Google_DNS_Number_of_Script_Tags = self.Number_of_Scripts_Different_DNS_List.get('Google')
        else:
            self.Google_DNS_Number_of_Script_Tags = Google_DNS_Number_of_Script_Tags

        if Cloudflare_DNS_Cloudflare_Block_Page == "":
            self.Cloudflare_DNS_Number_of_Script_Tags = self.Number_of_Scripts_Different_DNS_List.get('Cloudflare')
        else:
            self.Cloudflare_DNS_Number_of_Script_Tags = Cloudflare_DNS_Number_of_Script_Tags

        #self.All_IPs_From_Every_DNS = self.Response_Code_Different_DNS_List.copy()
        #self.All_IPs_From_Every_DNS['MyDNS'] = self.ISP_IP_Response_Code


    def return_ISP_IP_List(self):
        return getIPAddressOfDomain(self.domainNoHTTPNoSlash)[0]

    def return_DNS(self):
        return getMyDNS()

    def return_Response_Code(self):
        https = False
        http = False

        if self.domain[0:5] == "https":
            https = True

        if self.domain[0:5] == "http:":
            http = True

        try:
            results = requestWebsite(self.domainNoHTTP, http, https)

            return {'ResponseCode':results.get('ResponseCode'), 'BlockPage':results.get('BlockPage'), 'CloudflareBlockPage':results.get('CloudflareBlockPage'), 'Number_of_Script_Tags':results.get('Number_of_Script_Tags')}
        except Exception as e:

            errorMessage = str(e).replace(',',';')
            return {'ResponseCode':'ERROR', 'BlockPage':"N/A", 'CloudflareBlockPage':"N/A", 'Number_of_Script_Tags':"N/A"}


    def return_IPs_Different_DNS(self):

        DifferentDNSIPs = resolveIPFromDNS(self.domainNoHTTPNoSlashNoWWW, listOfDNSs()[0])

        return DifferentDNSIPs


    def set_IP_All_Blockpages_All_Responses(self):
        MyDNS_results = IPResponseCodesAndText(self.ISP_DNS_IPS)
        AARC_results =  IPResponseCodesAndText(self.AARC_DNS_IPs)
        Optus_results = IPResponseCodesAndText(self.Optus_DNS_IPs)
        Google_results = IPResponseCodesAndText(self.Google_DNS)
        Cloudflare_results = IPResponseCodesAndText(self.Cloudflare_DNS)

        self.__all_results = {'MyDNS': MyDNS_results, 'AARC':AARC_results, 'Optus':Optus_results,
        'Google':Google_results, 'Cloudflare':Cloudflare_results}.copy()

    def get_IP_All_Blockpages_All_Responses(self):
        return self.__all_results


    def NumberScriptTagList(self):
        results = self.get_IP_All_Blockpages_All_Responses()

        number_script_tags_results = {'MyDNS':results.get('MyDNS').get('number_of_script_tags'), 'AARC': results.get('AARC').get('number_of_script_tags'), 'Optus':results.get('Optus').get('number_of_script_tags'),
        'Google':results.get('Google').get('number_of_script_tags'), 'Cloudflare':results.get('Cloudflare').get('number_of_script_tags')}
        return number_script_tags_results

    def IPResponseCodesList(self):
        results = self.get_IP_All_Blockpages_All_Responses()

        response_code_results = {'MyDNS':results.get('MyDNS').get('responseCodeList'), 'AARC': results.get('AARC').get('responseCodeList'), 'Optus':results.get('Optus').get('responseCodeList'),
        'Google':results.get('Google').get('responseCodeList'), 'Cloudflare':results.get('Cloudflare').get('responseCodeList')}
        return response_code_results
        # return {'MyDNS':self.ISP_IP_Response_Code, 'AARC': self.IP_All_Blockpages_All_Responses.get('AARC').get('responseCodeList'), 'Optus':self.IP_All_Blockpages_All_Responses.get('Optus').get('responseCodeList'),
        #'Google':self.IP_All_Blockpages_All_Responses.get('Google').get('responseCodeList'), 'Cloudflare':self.IP_All_Blockpages_All_Responses.get('Cloudflare').get('responseCodeList')}

    def IPBlockPageList(self):

        results = self.get_IP_All_Blockpages_All_Responses()

        blockpage_results = {'MyDNS':results.get('MyDNS').get('blockPageList'), 'AARC': results.get('AARC').get('blockPageList'), 'Optus':results.get('Optus').get('blockPageList'),
        'Google':results.get('Google').get('blockPageList'), 'Cloudflare':results.get('Cloudflare').get('blockPageList')}
        return blockpage_results

    def IPCloudFlareBlockPageList(self):

        results = self.get_IP_All_Blockpages_All_Responses()

        cloudflare_blockpage_results = {'MyDNS':results.get('MyDNS').get('cloudFlareBlockPageList'), 'AARC': results.get('AARC').get('cloudFlareBlockPageList'), 'Optus':results.get('Optus').get('cloudFlareBlockPageList'),
        'Google':results.get('Google').get('cloudFlareBlockPageList'), 'Cloudflare':results.get('Cloudflare').get('cloudFlareBlockPageList')}
        return cloudflare_blockpage_results

    def return_class_variables(Domain):
      return(Domain.__dict__)


    def IPResponseCodesListFromString(self):
        IPResponsesList = self.ISP_DNS_IPS

        #issue is here, there are heaps of IP addresses
        responseCodeList = IPResponseCodesAndText(IPResponsesList).get('responseCodeList')

        return responseCodeList

    def tracerouteToDomain(self):

        return scapyTracerouteWithSR(self.domainNoHTTPNoSlashNoWWW)

    def Is_ISP_IP_In_NonISP_DNS_IP(self):
        #formula should be: if dns ip's provide 404's, if non isp dns's provide 200's some form of tampering is happening

        self.getPublicDNSResponses()

        publicDNSIPList = self.Google_DNS + self.Cloudflare_DNS
        for ip in self.ISP_DNS_IPS[0].split("; "):

            if ip in publicDNSIPList:
                return True

        else:
            return False


    def getPublicDNSResponses(self):
        compiledList = self.Google_DNS_Response_Code+self.Cloudflare_DNS_Response_Code

        resultsDict = {}
        for code in compiledList:
            if code in resultsDict:
                resultsDict[code] = resultsDict.get(code)+1
            else:
                resultsDict[code] = 1


        return resultsDict


    def IPsInTwoLists(self, firstDNSIPList, secondDNSIPList):
        firstFoundInSecond = False
        for firstIP in firstDNSIPList:

            if firstIP in secondDNSIPList:
                firstFoundInSecond = True
                return True

        return False
