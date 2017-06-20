

module LDAP;
export  {


    type LDAP::ModifyReqPDU: record  {
        messageID   :	count;
		entry		:	string;
		value		:	string;
    };

    type LDAP::ModifyDNReqPDU: record  {
        messageID   :   count;
		entry		: 	string;
		value		: 	string;
    };

	type LDAP::AddReqPDU: record {
		messageID	:	count;
		entry		:	string;
		value		:	string;
	};

	type LDAP::DeleteReqPDU: record {
		messageID	:	count;
		value		:	string;
	};

    type LDAP::LDAPResultPDU: record  {
        messageID : count;
        result    : count;
        error     : string;
    };
    
    type LDAP::BindReqPDU: record  {
        messageID   : count;
    };

	
}

module GLOBAL;

