# Bro::LDAP
=================================

This package provides an analyzer for Lightweight Directory Access Protocol write operations.  The following operations will be written to ldap.log after running the analyzer:

* modifyRequest and modifyResponse
* modifyDNRequest and modifyDNResponse
* addRequest and addResponse
* deleteRequest and deleteResponse
* bindRequest and bindResponse

Additionally, the analyzer will deliver GSSAPI GSS-SPNEGO authentication data in LDAP bindRequests to the gssapi analyzer to be written to the Kerberos or NTLM logs.

#Environment Configuration
## If using the analyzer as a plugin:
1. Install bro-pkg manager

* `$ pip install bro-pkg`
* (Recommended: latest version) `$ pip install git+git://github.com/bro/package-manager@master`

2. Configure bro-pkg & environment

* Bro-pkg needs PATH to bro-config:  `$ export PATH=$PATH:/path_to/bro/build` (modify /path/to)
* Run the autoconfiguration:  `$ bro-pkg autoconfig`
* Setup Bro's environment to match bro-pkgl  `$ eval $(bro-pkg env)`

3. Run the plugin straight from git:
* `$ bro-pkg install ldap-analyzer`
* Test to make sure the plugin is loaded `$ bro -N | grep LDAP` (you should see the plugin loaded)
* `$ bro -C -r your_ldap.pcap` ( -C is optional and used if the pcap contains checksums.  This must come before the -r )

#TO DO:
* Testing script produces an error.  It attempts to access a non-existent file.
