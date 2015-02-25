
# Univ of Washington IdP plugin for login extensions

This authentication plugin allows a shib idp using remoteuser authn to handle forced reauth, 2-factor auth, and some other login capabilities or our pubcookie login system.



# Note 

1. A known issue prevents pubcookie from handling isPassive.  Don't care.  Somebody has to.  We handle it for now.
2. version 1.7 for shib-2.3.6, version 1.5 for shib-2.3.0, version 1.4 for shib 2.2.0,  version 1.3 for earlier shibs
3. version 1.7 has token30 attribute
4. version 1.8 has a capability to set a different pubcookie appid for selected RPs.  This, combined with a modification to pubcookie's login server, allows us to selectively (combination of RP and userid) upgrade some users to a requirement of token authn.  Needed by Workday.



