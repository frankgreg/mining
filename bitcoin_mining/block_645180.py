import json
import requests
from bs4 import BeautifulSoup
import pprint
import numpy as np

url = 'https://chain.api.btc.com/v3/block/645180'
response = requests.get(url=url)
block_data = response.json()['data']
pprint.pprint(block_data)


version = block_data['version']
hex(int(version))
f'{int(version):x}'

np.roll(version, 2)
# 00e0ff2f