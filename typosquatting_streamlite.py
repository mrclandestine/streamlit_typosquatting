import requests
import pandas as pd
import streamlit as st

API_KEY = '0e4df75413670efa7ad17aae13bcbb553cd47ed08d472342e867bec9fb178211'

def check_domain(domain):
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
headers = {
    "accept": "application/json",
    "x-apikey": "0e4df75413670efa7ad17aae13bcbb553cd47ed08d472342e867bec9fb178211"
    response = requests.get(url, headers=headers)
        data = response.json()['data']
        response = requests.get(url, headers=headers)
print(response.text)
st.title('Typosquatting Checker')

domain = st.text_input('Enter a domain name')
if st.button('Check'):
    results = check_domain(domain)
    if results is None:
        st.error('Error checking domain')
    else:
        df = pd.DataFrame.from_records([results])
        st.table(df)
