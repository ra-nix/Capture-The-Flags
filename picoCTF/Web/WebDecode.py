from bs4 import BeautifulSoup
import re
import requests
import codecs


SITE = "http://titan.picoctf.net:55415/"


browser = requests.session()
index = browser.get(SITE)
soup = BeautifulSoup(index.content, "lxml")


link_uri = []
link_divs = soup.find_all("div", {"class": "navigation-container"})
for div in link_divs:
  for a in div.find_all("a"):
    if a["href"] != "index.html":
      link_uri.append(a["href"])


encoded_content = []
regex = r"[A-Za-z0-9+/=]{50,}"
for i in link_uri:
  obj = browser.get(f"{SITE}/{i}")
  inner_soup = BeautifulSoup(obj.content, "lxml")
  encoded_content.extend(re.findall(regex, inner_soup.prettify()))


for j in encoded_content:
  answer = codecs.decode(j.encode(), "base64")
  if answer.decode().startswith("picoCTF"):
    print(answer.decode())
