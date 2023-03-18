import requests
import pandas as pd
import streamlit as st

API_KEY = '0e4df75413670efa7ad17aae13bcbb553cd47ed08d472342e867bec9fb178211'

def check_domain(domain):
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    headers = {'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()['data']
        return {
            'domain': data['attributes']['last_analysis_stats']['harmless']['count'],
            'typosquatting': data['attributes']['last_analysis_stats']['suspicious']['count'],
            'malicious': data['attributes']['last_analysis_stats']['malicious']['count']
        }
    else:
        return None

st.title('Typosquatting Checker')

domain = st.text_input('Enter a domain name')
if st.button('Check'):
    results = check_domain(domain)
    if results is None:
        st.error('Error checking domain')
    else:
        df = pd.DataFrame.from_records([results])
        st.table(df)
