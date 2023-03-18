import streamlit as st
import requests

# VirusTotal API key
API_KEY = "0e4df75413670efa7ad17aae13bcbb553cd47ed08d472342e867bec9fb178211"

# VirusTotal API endpoint
API_URL = "https://www.virustotal.com/api/v3/domains/"

# Streamlit app title
st.title("VirusTotal Domain Report")

# Get domain input from user
domain = st.text_input("Enter domain name")

# Check if domain input is empty
if not domain:
    st.warning("Please enter a domain name")
else:
    # Add the API key to the headers
    headers = {"x-apikey": API_KEY}

    # Send a GET request to VirusTotal API to retrieve domain report
    response = requests.get(API_URL + domain, headers=headers)

    # Check if response is successful
    if response.status_code == 200:
        # Display domain report
        report = response.json()
        st.write(f"**Domain**: {report['data']['id']}")
        st.write(f"**Owner**: {report['data']['attributes']['owner']}")
        st.write(f"**Categories**: {', '.join(report['data']['attributes']['categories'])}")
        st.write(f"**Last analysis date**: {report['data']['attributes']['last_analysis_date']}")
        st.write(f"**Detected URLs**: {report['data']['attributes']['url_count']['detected']}")
        st.write(f"**Undetected URLs**: {report['data']['attributes']['url_count']['undetected']}")
    elif response.status_code == 404:
        st.warning("Domain not found on VirusTotal")
    else:
        st.warning("An error occurred while retrieving domain report")
