
module LDAP;

export {
	type ModifyReqPDU: record {
		messageID : count;
		entry     : string;
		value     : string;
	};

	type ModifyDNReqPDU: record {
		messageID : count;
		entry     : string;
		value     : string;
	};

	type AddReqPDU: record {
		messageID : count;
		entry     : string;
		value     : string;
	};

	type DeleteReqPDU: record {
		messageID : count;
		value     : string;
	};

	type LDAPResultPDU: record {
		messageID : count;
		result    : count;
		error     : string;
	};
	
	type BindReqPDU: record {
		messageID : count;
	};
}

