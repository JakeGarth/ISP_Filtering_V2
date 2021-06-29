from urllib.request import Request, urlopen
import requests
from bs4 import BeautifulSoup

from bs4.element import Comment

def tag_visible(element):
    if element.parent.name in ['style', 'script', 'head', 'title', 'meta', '[document]']:
        return False
    if isinstance(element, Comment):
        return False
    return True


def text_from_html(body):
    soup = BeautifulSoup(body, 'html.parser')
    texts = soup.findAll(text=True)
    visible_texts = filter(tag_visible, texts)
    return u" ".join(t.strip() for t in visible_texts)

#This list needs to expanded
block_page_phrases = [
    "ACCESS TO THIS WEBSITE HAS BEEN DISABLED BECAUSE THE FEDERAL COURT OF AUSTRALIA HAS DETERMINED THAT IT INFRINGES OR FACILITATES THE INFRINGEMENT OF COPYRIGHT",
    "Access Denied",
    "Access to this website has been disabled by an order of the Federal Court of Australia because it infringes or facilitates the infringement of copyright",
    "1800 086 346",
    "1800086346"
    ]

#This list needs to be expanded
cloudflare_phrases = [
    "You've requested an IP address that is part of the Cloudflare network.",
    "Direct IP access not allowed"
    ]

#Function for detecting blockpages
def detectBlockPage(text):
    for phrase in block_page_phrases:

        if phrase.lower() in text.lower():

            return "True"
    return "False"

#Function for detecting cloudflare blockpages
def detectCloudFlare(text):
    for phrase in cloudflare_phrases:
        if phrase.lower() in text.lower():

            return "True"
    return "False"
