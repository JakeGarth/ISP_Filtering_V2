import socket

def getIPAddressOfDomain(websiteURL):

    try:
        result = socket.gethostbyname_ex(websiteURL)

        print(result[2])
        IPAddressList = result[2]
        IPaddressString = str(result[2]).replace(',',";")


    except Exception as e:
        IPaddressString = str(e)
        IPaddressString.replace(',',";")
        IPAddressList = ['NaN', 'NaN']

    return IPaddressString, IPAddressList


def main():


    answer = getIPAddressOfDomain("animehd47.com")
    #print(answer[1])

if __name__ == "__main__":

    main()
