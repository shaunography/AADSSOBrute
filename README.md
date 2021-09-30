# AADSSOBrute
Python Secureworks Azure AD autologon Seamless SSO brute force POC based on https://www.secureworks.com/research/undetected-azure-active-directory-brute-force-attacks derived from https://github.com/0xj3lly/Azure-Seamless-SSO-Brute-Force

## usage
```
$ python3 AADSSOBrute.py -u username -p password.lst -d domain
```
Both the username (-u) and password (-p) arguments can be either a single username/password or an absolute path to a file containing a list of usernames/passwords.

A list of valid users and/or creds are returned

## testing
Seamless SSO does not need to be enabled. Sign in attempts are not captured in AzureAD/M365 portal. MFA and Conditional Access policies seem to be ignored. The autologon endpoint will seemingly randomly return that the target acount is locked out, however this will clear after a few seconds and the account appears to continue functioniing as normal.

Has been tested against:

online only user account, password hash sync disabled, Seamless SSO disabled, ADFS disabled

online only user account, password hash sync enabled, Seamless SSO disabled, ADFS disabled

on prem user account, password hash sync enabled, seamless SSO enabled, ADFS enabled

Use at your own risk!
