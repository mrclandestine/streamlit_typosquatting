import streamlit as st
import requests

API_KEY = "0e4df75413670efa7ad17aae13bcbb553cd47ed08d472342e867bec9fb178211"

st.title("VirusTotal Domain Report")

domain = st.text_input("Enter a domain name", value="google.com")

if st.button("Get Report"):

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        "x-apikey": API_KEY,
        "Content-Type": "application/json",
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        report = response.json()["data"]
        st.write("### Basic Information")
        st.write(f"**Domain:** {report['id']}")
        st.write(f"**Creation Date:** {report['attributes']['creation_date']}")
        st.write(f"**Last DNS Resolution:** {report['attributes']['last_dns_records']['last_resolved']}")
        st.write(f"**ASN:** {report['attributes']['asn']}")
        st.write(f"**Categories:** {', '.join(report['attributes']['categories'])}")
        st.write(f"**Country:** {report['attributes']['country']}")

        st.write("### Reputation")
        st.write(f"**Harmless Votes:** {report['attributes']['last_analysis_stats']['harmless']}")
        st.write(f"**Malicious Votes:** {report['attributes']['last_analysis_stats']['malicious']}")
        st.write(f"**Suspicious Votes:** {report['attributes']['last_analysis_stats']['suspicious']}")
        st.write(f"**Undetected Votes:** {report['attributes']['last_analysis_stats']['undetected']}")

        st.write("### Whois")
        st.write(f"```\n{report['attributes']['whois']}\n```")
        
    else:
        st.write("Error fetching report. Please try again later.")
