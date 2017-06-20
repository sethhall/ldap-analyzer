# @TEST-EXEC: bro -C -r $TRACES/ldap.pcap
# @TEST-EXEC: btest-diff ldap.log
# @TEST-EXEC: btest-diff ntlm.log
# @TEST-EXEC: btest-diff kerberos.log
