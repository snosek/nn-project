"""
	W tym pliku znajdują się napisane przez nas funkcje wyciągające z URLów pożądane cechy.
	Badanie ważności cech znajduje się w pliku data_exploration.
    Link do wyciągniętych w tym pliku danych: https://www.kaggle.com/datasets/stefannosek/nnproject-urls/settings
"""

import pandas as pd
from urllib.parse import urlparse
import re
from bs4 import BeautifulSoup
import requests
import tldextract
from urllib.parse import urlparse, urljoin

df=pd.read_csv('phishing_site_urls.csv')
df

df.loc[18245,'URL']='\x8aRybjUx\x18Ùãl5»7ÆE%Ý\x14Ôk+h\x1f\x0f|U\x1a\x07+ýk©ìÉ\x94½\x93ÆqâF·\x9eõÁ¢w)ëA·ç\x93\x0f°\x9a{t*m!¦2\x03'
df.loc[18277,'URL']='\x90Æe\x1eF§÷%\x11¶\x1c¿Õ\x8c½9¿b@Ö¸ÚZE¤ÒC¢\x98\x8eÄÅª2åç-W³fU¤\x1eJgkz.ø¿n\x80Jçå\x14æu\x87\x85øD%@ðû\x0fÇùM¹u\x0bË'
df.loc[18278,'URL']='\x90Æe\x1eF§÷%\x11¶\x1c¿Õ\x8c½9¿b@Ö¸ÚZE¤ÒC¢\x98\x8eÄÅª2åç-W³fU¤\x1eJgkz.ø¿n\x80Jçå\x14æu\x87\x85øD%@ðû\x0fÇùM¹u\x0bË'
df.loc[18283,'URL']='\x90Æe\x1eF§÷%\x11¶\x1c¿Õ\x8c½9¿b@Ö¸ÚZE¤ÒC¢\x98\x8eÄÅª2åç-W³fU¤\x1eJgkz.ø¿n\x80Jçå\x14æu\x87\x85øD%@ðû\x0fÇùM¹u\x0bË'
df.loc[18288,'URL']='¨R\x98ÊÃ\x86ûaCóÞit×ßÂe-DÖ\x8bØ+9YèÌçÏ\x97¯·\x04"0£ÙÕ.0ößF«7¹N\x89R\x1c\x04Ù{ccÉÄãéçxÄ6a\x1a5Ñ³LÖíÜÉÀ£\x9dÒma¥yRX\x03\x9a*0ÅÝ7×Ê\x83ÁÌ\x05\x05o«Õs¶\x8d0k\x90dèÑ&\x83\x1cÄ\x10"Ï¨mZ\'àD\x8fM×ñ\x01XÚÒK"päî±h¬\x83cAÊeK@4r"^\'ÓFþ1*Ë\x8e\x1d\x8dË PÞô;õ\x9c$úàÑ@\x87þ=êWÑ"Ãhñ\x05\x18®ç^\x18\x11«Ýó^ç\x1a\x1fRú\x8eUJ\x14.<6C\x19\x94y\x1a\x9fÜ\x94FØrÿV2ôæý\x89\x03Zãii\x16\x93I\x0e\x8ab;\x13\x16¨Ë\x97\x9cµu^Í\x99V\x90y)\x9d\xadè»âýº\x01+\x9f\x94S\x99Ö\x1e\x17á\x10\x95\x03Ãì?\x1få6åÔ/'
df.loc[18296,'URL']='1Î¼0#W»æ½Î4>¥õ\x1cª\x94(\\xl\x863(ò5?¹(\x8d°åþ¬eéÍû\x12\x06µÆÒÒ-&\x92\x1d\x14Äv&-Q\x97/9jê½\x9b2\xad òS;ÑwÅût\x02W?(§3¬</Â!*\x07\x87Ø~?ÊmË¨^XV\x9c¹µÂ\x92¦\x183¨|÷4\x10fÈë<\t\x81ô·»n³H\x96\x99éÜúÂÒá/Wîà.K3q4:å\x81)¿®I\x13K.°x±\x8e&\x0fR6\x87\x90¹àÄ\x01#\x1f|9³¢Ü\x89\x87\x94ù\x94ñ\x14\x19~3'
df.loc[18303,'URL']='k\x8d¥¤ZM$:)\x88ìLZ£.^rÕÕ{6eZAä¦v·¢ï\x8böè\x04®~QNgXx_\x84BT\x0f\x0f°ü\x7f\x94Û\x97P¼°\xad9sk\x85%L0gPø·îh Í\x91Öx\x13\x03éovÝf\x91-3Ó¹õ\x85¥Â^¯ÝÀ\\\x96fâhuË\x02S\x7f\\\x92&\x96`ñc\x1cL\x1e¤m\x0f!sÁ\x88\x02F>øsgE¹\x13\x0f)ó)â(2üf\x15ã).!÷\x0f\x92ÿÞ<rDZÅ*¼\x8b/\xa0e¼Ëh\x97\x01úW\x1d+\x06\x9b\x05ï%»»;µÛ\x13\x9e¦M5;ù\\¸¥ß\x9fãV«û°\x8bz¦ö9Ì\'\x06Î\x03|\xa0¼ôªz"8#1¿\x04D4A /.|qt}Òåo#Ûõ\x14*|Bv\x0c®\x18U¬\x9e¢'
df.loc[18304,'URL']="A\x0eìfÙêìÝÕ\x1d2\x87£»\x91¸ü\x19\x909nªÉ®'\x97A½`ym\x9aî¹èDéI5\x08û-ÄXå\x10¦\x01²\x90Â%js²ÍD^\x85^\x89\x9e\x15Á*\x8f\x89^Ü\x98\x86D-À\x18\x91%³;Óßñg\\8+±Wnn@\x83¾IßBëC\x8c³3S7\x9bM(úJzª6¥\x93\x18HmÒ)fæ(\x01þ\x17i\x1e\x13¡d\xa0\x16ù\x8dp"
df.loc[18312,'URL']='½\x13<+\x82U\x1f\x12½¹1\x0c\x88\x801"Kfw§¿âÎ¸pWb®ÜÜ\x81\x07|\x93¾\x85Ö\x87\x18·ff¦o6\x9aQõF\x94õTmK&0\x90Û¤RÍÌP\x03ü.Ò<\'BÉ@-ó\x1aàYN\x01\\\x9a¦~7J\x85¡\x82*\x9aÈú=ÙU\xa0^>R~@O·\x8c'
df.loc[18314,'URL']='¯\x04\x88=\x84ÓÛ±\x13i-\x11Ð\x18'
df.loc[18315,'URL']='=\x9dRã\x0fmôj³{\x94è\x95!ÀM\x97¶6<\x9cN>\x9ew\x85¼Cf\x11£\x1b4ÍnÝÌ\x9c'
df.loc[18316,'URL']='9Ý&Ö\x1aW\x95%\x809¢£\x0cÓ}|¨<\x1cÀPVú½W;hÓ\x06¹\x06N\x8d\x12h1ÌA\x02'
df.loc[18319,'URL']='ò\x82óÒ©è\x88à\x8cÆü\x11\x10Ñ\x04\x80½l¹ñÅÑ÷K\x95¼\x8foÔP©ñ\tØ2¸aV²z\x885\x04;±\x9bg«³wTtÊ\x1e\x8eîFãðf@åº«&¸\x9e\x06õ\x81å¶kºç¡\x13¥$Ô#ì·\x11c\x94B\x98\x06ÊC\x08\x95©ÎË5\x11z\x15z&xW\x04ª>%{rb\x19\x10·'

# długość URL
def length_URL(url):
    l = len(url)
    return l

# scheme
def is_scheme(url):
    scheme = urlparse(url).scheme

    if len(scheme) == 0:
        return 0
    else:
        return 1

# długość hostname
def length_hostname(url):
    # Parse the URL to extract the hostname
    hostname = urlparse(url).hostname
    if hostname== None:
        l = 0
    else:
        l = len(hostname)
    return l

# liczba wystąpień '?'
def nb_qmark(url):
    return url.count('?')

# liczba wystąpień 'www'
def nb_www(url):
    return url.count('www')

# number of digits in URL
def count_digits_URL(url):
    count = 0
    for char in url:
        if char.isdigit():
            count += 1
    return count

# liczba cyfr w hostname
def count_digits_hostname(url):
    # Parse the URL to extract the hostname
    count = 0
    hostname = urlparse(url).hostname
    if hostname == None:
        return 0

    for char in hostname:
        if char.isdigit():
            count+=1
    return count

# najdłuższe słowo
def longest_word_length_in_url(url):
    # Usuń znaki specjalne z URL
    cleaned_url = re.sub(r'[/:?&.=]', ' ', url)
    # Podziel URL na słowa
    words = cleaned_url.split()
    # Znajdź najdłuższe słowo i zwróć jego długość
    if words:
        longest_word = max(words, key=len)
        return len(longest_word)
    else:
        return 0

# najdłuższe słowo w ścieżce
def longest_word_length_in_path(url):
    path = urlparse(url).path
    # Usuń znaki specjalne z path
    cleaned_path = re.sub(r'[/:?&.=]', ' ', path)
    # Podziel path na słowa
    words = cleaned_path.split()
    # Znajdź najdłuższe słowo i zwróć jego długość
    if words:
        longest_word = max(words, key=len)
        return len(longest_word)
    else:
        return 0

# tld in subdomain
def check_tld_in_subdomain(url):
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain
    tld = extracted.suffix

    # Sprawdzenie, czy TLD znajduje się w subdomenie
    if tld in subdomain.split('.'):
        return 1
    return 0

# prefix_suffix
def check_prefix_suffix_in_domain(url):
    extracted = tldextract.extract(url)

    subdomain = extracted.subdomain
    domain = extracted.domain
    suffix = extracted.suffix

    # Sprawdzenie czy domena ma prefiks (czy subdomena nie jest pusta)
    has_prefix = bool(subdomain)

    # Sprawdzenie czy domena ma sufiks (czy suffix nie jest pusty)
    has_suffix = bool(suffix)
    if (has_prefix ==True) or (has_suffix==True):
        return 1
    else:
        return 0

# najkrótsze słowo w hostname
def shortest_host(url):
    hostname = urlparse(url).hostname
    if hostname == None:
        return 0
    # Usuń znaki specjalne z host
    cleaned_hostname = re.sub(r'[/:?&.=]', ' ', hostname)
    # Podziel path na słowa
    words = cleaned_hostname.split()
    # Znajdź najdłuższe słowo i zwróć jego długość
    if words:
        shortest_word = min(words, key=len)
        return len(shortest_word)
    else:
        return 0

# liczba kropek w URL
def nb_dots(url):
    return url.count('.')

# liczba znaków równości w URL
def nb_eq(url):
    return url.count('=')

# liczba znaków slash w URL
def nb_slash(url):
    return url.count('/')

# liczba hyperlinków
def nb_hyperlinks(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # was successful?
        soup = BeautifulSoup(response.text, 'html.parser')
        anchors = soup.find_all('a')
        num_hyperlinks = len(anchors)
        return num_hyperlinks
    except:
        return 0

# ilość wskazówek, że dany URL jest phishingiem
def phish_hints(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    path = parsed_url.path
    
    hints = 0
    # IP address in hostname
    if hostname and re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        hints += 1
    # multiple subdomains
    if hostname and len(hostname.split('.')) > 3:
        hints += 1
    # suspicious TLD
    suspicious_tlds = {'xyz', 'top', 'gq', 'cc', 'ga', 'tk', 'ml'}
    tld = hostname.split('.')[-1] if hostname else ''
    if tld in suspicious_tlds:
        hints += 1
    # common phishing keywords in hostname or path
    phishing_keywords = {'login', 'secure', 'account', 'update', 'verify', 'webscr', 'signin', 'banking'}
    if hostname is not None:
      if any(keyword in hostname for keyword in phishing_keywords) or any(keyword in path for keyword in phishing_keywords):
          hints += 1
    # unusual characters or encoding in URL
    if re.search(r'%[0-9a-fA-F]{2}', url) or '@' in url:
        hints += 1
    # long URLs
    if len(url) > 75:
        hints += 1
    return hints

#Safe anchors typowo nawiązują do kotwicy HTML (<a>) linków uważanych za bezpieczne do naciśnięcia.
#"safe anchors" generalnie oznaczają linki, które nie przekierowują do złośliwych stron,
#posiadających szkodliwą zawartość i które przestrzegają standardy bezpieczeństwa.
def is_safe_anchor(href, base_url):
    parsed_url = urlparse(href)
    count1 = 0
    count2 = 0
    #valid http or https schemes
    if parsed_url.scheme not in ['http', 'https']:
        count1 = 0
    else:
        count1 += 1
        
    # suspicious patterns (IP address in the hostname etc)
    hostname = parsed_url.hostname
    if hostname is None or hostname.replace('.', '').isdigit():
        count2 = 0
    else:
        count2 += 1
        
    if (count1 == 1 and count2 == 1):
      return 1
    else:
      return 0
    
def safe_anchors(url):
    try:
        # request to url
        response = requests.get(url)
        response.raise_for_status()
        # analize the content
        soup = BeautifulSoup(response.content, 'html.parser')
        # find anchor tags
        anchor_tags = soup.find_all('a', href=True)

        for a in anchor_tags:
            href = a['href']
            full_url = urljoin(url, href)
            if is_safe_anchor(full_url, url)==1:
                return 1
            else:
                return 0

    except Exception as e:
        return 0
    
def scheme(url):
    if urlparse(url).scheme == '':
        return 0
    return 1
    
def ratio_digits_url(url):
    length = length_URL(url)
    return count_digits_URL(url)/length if length != 0 else 0

def ratio_digits_hostname(url):
    length = length_hostname(url)
    return count_digits_URL(url)/length if length != 0 else 0

df['length_url'] = df.URL.apply(length_URL)
df['scheme'] = df.URL.apply(is_scheme)
df['length_hostname'] = df.URL.apply(length_hostname)
df['nb_qm'] = df.URL.apply(nb_qmark)
df['nb_www'] = df.URL.apply(nb_www)
df['nb_dots'] = df.URL.apply(nb_dots)
df['nb_eq'] = df.URL.apply(nb_eq)
df['nb_slash'] = df.URL.apply(nb_slash)
df['nb_hyperlinks'] = df.URL.apply(nb_hyperlinks)
df['ratio_digits_url'] = df.URL.apply(ratio_digits_url)
df['ratio_digits_hostname'] = df.URL.apply(ratio_digits_hostname)
df['longest_words_raw'] = df.URL.apply(longest_word_length_in_url)
df['longest_words_path'] = df.URL.apply(longest_word_length_in_path)
df['tld_in_subdomain'] = df.URL.apply(check_tld_in_subdomain)
df['prefix_suffix'] = df.URL.apply(check_prefix_suffix_in_domain)
df['shortest_word_host'] = df.URL.apply(shortest_host)
df['phish_hints'] = df.URL.apply(phish_hints)
df['safe_anchors'] = df.URL.apply(safe_anchors)

df.to_csv('urls.csv', index=False)
