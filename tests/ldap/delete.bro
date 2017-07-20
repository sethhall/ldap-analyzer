# @TEST-EXEC: bro -C -r $TRACES/ldap-delete.pcap %INPUT
# @TEST-EXEC: btest-diff ldap.log
