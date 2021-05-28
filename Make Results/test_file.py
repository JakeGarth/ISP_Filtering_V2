import requests

IPAddress = '54.253.102.29'

r = requests.get('http://'+IPAddress, timeout=5)
print("r: ")
print(r)
print("text")
print(r.text)
print("status code")
print(r.status_code)
