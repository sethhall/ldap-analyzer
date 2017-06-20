%extern{
#include <cstdlib>
#include <vector>
#include <string>
%}

%header{
RecordVal * build_modreq_pdu(const ModifyReqPDU *pdu);
RecordVal * build_modDNreq_pdu(const ModifyDNReqPDU *pdu);
RecordVal * build_addreq_pdu(const AddReqPDU *pdu);
RecordVal * build_delreq_pdu(const DeleteReqPDU *pdu);
RecordVal * build_ldap_res(LDAPResult *pdu);
RecordVal * build_bindreq_pdu(const BindReqPDU *pdu);
%}


%code{

/*
Builds a ModifyRequest record
- messageID
- object/entry to be modified
- string of modifications to be performed
*/

RecordVal * build_modreq_pdu(const ModifyReqPDU *pdu)  
    {
    RecordVal *rv = new RecordVal(BifType::Record::LDAP::ModifyReqPDU);

	rv->Assign(0, asn1_integer_to_val(pdu->messageID(), TYPE_INT));
	rv->Assign(1, asn1_octet_string_to_val(pdu->object()));
	
	vector<ModificationControl*>  mods = *pdu->mods();
        std::string fullStr;
	for (auto it = mods.begin(); it != mods.end(); ++it){
                if( (*it)->mod_or_control_case_index() != 10 ) continue;

                switch( (*it)->mod()->op())  {
                  case 0:
                    fullStr.append("add ");
                    break;
                  case 1:
                    fullStr.append("delete ");
                    break;
                  case 2:
                    fullStr.append("replace ");
                    break;
                  default:
                    fullStr.append("unknown ");
                    break;
                };

                const u_char * typeStr = asn1_octet_string_to_val((*it)->mod()->type())->Bytes();
                fullStr.append((const char*)typeStr);
                fullStr.append(" ");

                const u_char * valStr = asn1_octet_string_to_val((*it)->mod()->val())->Bytes();
                fullStr.append((const char*)valStr);
                fullStr.append("/");
	}

        rv->Assign(2, new StringVal(fullStr));

    return rv;
    }


/*
Builds an AddRequest record
- messageID
- object/entry to be added
- string of attributes to be added
*/

RecordVal * build_addreq_pdu(const AddReqPDU *pdu)
	{
	RecordVal *rv = new RecordVal(BifType::Record::LDAP::AddReqPDU);
	rv->Assign(0, asn1_integer_to_val(pdu->messageID(), TYPE_INT));
	rv->Assign(1, asn1_octet_string_to_val(pdu->entry()));

	vector<Attribute*>  atts = *pdu->attributes()->atts();
        std::string fullStr;
	for (auto it = atts.begin(); it != atts.end(); ++it){
                if( (*it)->control_check_case_index() != 48 ) continue;


                const u_char * typeStr = asn1_octet_string_to_val((*it)->att()->type())->Bytes();
                fullStr.append((const char*)typeStr);
                fullStr.append(" ");

                const u_char * valStr = asn1_octet_string_to_val((*it)->att()->val())->Bytes();
                fullStr.append((const char*)valStr);
                fullStr.append("/");
	}

        rv->Assign(2, new StringVal(fullStr));

    return rv;
	}


/*
Builds a ModifyDNRequest record
- messageID
- object/entry to be modified
- string of newRDN, newSuperior, and whether or not to delete the old RDN
*/

RecordVal * build_modDNreq_pdu(const ModifyDNReqPDU *pdu)
	{
	RecordVal *rv = new RecordVal(BifType::Record::LDAP::ModifyDNReqPDU);
	rv->Assign(0, asn1_integer_to_val(pdu->messageID(), TYPE_INT));
	rv->Assign(1, asn1_octet_string_to_val(pdu->entry()));

	std::string fullStr;
	const u_char * newRDN = asn1_octet_string_to_val(pdu->newrdn())->Bytes();
	const u_char * newSupe = bytestring_to_val(pdu->newSuperior())->Bytes();

	fullStr.append("newRDN: ");
	fullStr.append((const char*)newRDN);
	fullStr.append(" ");
	fullStr.append("newSuperior: ");
	fullStr.append((const char*)newSupe);
	fullStr.append(" ");
	fullStr.append("deleteold: ");

	uint8 deleteold = pdu->deleteoldrdn();
	             switch(deleteold)  {
                  case 0:
                    fullStr.append("false ");
                    break;
                  default:
                    fullStr.append("true ");
                    break;
                };
	rv->Assign(2, new StringVal(fullStr));
	return rv;
	}

/*
Builds a DeleteRequest record
- messageID
- object/entry to be deleted
*/

RecordVal * build_delreq_pdu(const DeleteReqPDU *pdu)
	{
	RecordVal *rv = new RecordVal(BifType::Record::LDAP::DeleteReqPDU);
	rv->Assign(0, asn1_integer_to_val(pdu->messageID(), TYPE_INT));
	rv->Assign(1, bytestring_to_val(pdu->request()));

	return rv;
	}
/*
Builds a, LDAPResult record
- messageID
- result of request
- error string 
*/

RecordVal * build_ldap_res(LDAPResult *pdu)
    {
    RecordVal *rv = new RecordVal(BifType::Record::LDAP::LDAPResultPDU);
    rv->Assign(0, asn1_integer_to_val(pdu->messageID(), TYPE_INT));
    rv->Assign(1, new Val(pdu->result(), TYPE_INT));
    rv->Assign(2, asn1_octet_string_to_val(pdu->error()));

    return rv;
    }

/*
V2
Builds a BindRequest record
- messageID

*/
RecordVal * build_bindreq_pdu(const BindReqPDU *pdu)
    {
    RecordVal *rv = new RecordVal(BifType::Record::LDAP::BindReqPDU);
    rv->Assign(0, asn1_integer_to_val(pdu->messageID(), TYPE_INT));
    return rv;
    }

%}

refine connection LDAP_Conn += {

#
#Connection oriented functions:
#
	%member{
		// Fields used to determine if the protocol has been confirmed or not.
		bool confirmed;
		bool orig_pdu;
		bool resp_pdu;
		
		analyzer::Analyzer *gssapi;
		analyzer::Analyzer *krb5;
		%}

	%init{
		confirmed = false;
		orig_pdu = false;
		resp_pdu = false;
		
		gssapi = 0;
		krb5 = 0;
		%}
	
	%cleanup{
	
	    if(gssapi)  {
	        gssapi->Done();
	        delete gssapi;
	    }
	    
	    if(krb5)  {
	        krb5->Done();
	        delete krb5;
	    }
	%}

	function SetPDU(is_orig: bool): bool
		%{
		if ( is_orig )
			orig_pdu = true;
		else
			resp_pdu = true;

		return true;
		%}

	function SetConfirmed(): bool
		%{
		confirmed = true;
		return true;
		%}

	function IsConfirmed(): bool
		%{
		return confirmed && orig_pdu && resp_pdu;
		%}

#
# Handle ModifyRequest
#

	function proc_ldap_mod_req(pdu: ModifyReqPDU): bool
	    %{
	    if ( ! ldap_mod_req )
	        return false;
		
	    BifEvent::generate_ldap_mod_req(bro_analyzer(),
	                bro_analyzer()->Conn(),
					build_modreq_pdu(${pdu}));
					
		return true;                       
	    %}

#
# Handle ModifyResponse
#

	function proc_ldap_mod_res(pdu: ModifyResPDU): bool
	    %{
	    if ( ! ldap_mod_res )
	        return false;

	    BifEvent::generate_ldap_mod_res(bro_analyzer(),
	                bro_analyzer()->Conn(),
                        build_ldap_res(pdu->result()));

		return true;                       
	    %}

#
# Handle DeleteRequest
#
	    
	function proc_ldap_del_req(pdu: DeleteReqPDU): bool
	    %{
	    if ( ! ldap_del_req )
	        return false;
		
	    BifEvent::generate_ldap_del_req(bro_analyzer(),
	                bro_analyzer()->Conn(),	
					build_delreq_pdu(pdu));

		return true;                       
	    %}

#
# Handle DeleteResponse
#
	    
	function proc_ldap_del_res(pdu: DeleteResPDU): bool
	    %{
	    if ( ! ldap_del_res )
	        return false;

	    BifEvent::generate_ldap_mod_res(bro_analyzer(),
	                bro_analyzer()->Conn(),
                        build_ldap_res(pdu->result()));

		return true;                       
	    %}
	    
#
# Handle AddRequest
#

	function proc_ldap_add_req(pdu: AddReqPDU): bool
	    %{
	    if ( ! ldap_add_req )
	        return false;
		
	    BifEvent::generate_ldap_add_req(bro_analyzer(),
	                bro_analyzer()->Conn(),
					build_addreq_pdu(pdu));
		return true;                       
	    %}
	
#
# Handle AddResponse
#
    
	function proc_ldap_add_res(pdu: AddResPDU): bool
	    %{
	    if ( ! ldap_add_res )
	        return false;

	    BifEvent::generate_ldap_add_res(bro_analyzer(),
	                bro_analyzer()->Conn(),
                        build_ldap_res(pdu->result()));
				
	    return true;
	    %}

#
# Handle ModifyDNRequest
#

	function proc_ldap_modDN_req(pdu: ModifyDNReqPDU): bool
	    %{
	    if ( ! ldap_modDN_req )
	        return false;
		
	    BifEvent::generate_ldap_modDN_req(bro_analyzer(),
	                bro_analyzer()->Conn(),
					build_modDNreq_pdu(pdu));
		return true;                       
	    %}

#
# Handle ModifyDNResponse
#

	function proc_ldap_modDN_res(pdu: ModifyDNResPDU): bool
	    %{
	    if ( ! ldap_modDN_res )
	        return false;

	    BifEvent::generate_ldap_modDN_res(bro_analyzer(),
	                bro_analyzer()->Conn(),
                    build_ldap_res(pdu->result()));

		return true;                       
	    %}

#
# Handle BindRequest
#

	function proc_ldap_bind_req(pdu: BindReqPDU, is_orig: bool): bool
		%{
	
		BifEvent::generate_ldap_bind_req(bro_analyzer(),
	                bro_analyzer()->Conn(),
                    build_bindreq_pdu(pdu));
                    
                if(memcmp("\x47\x53\x53\x2d\x53\x50\x4e\x45\x47\x4f", asn1_octet_string_to_val(pdu->mechanism())->Bytes(), 10) == 0)  {
                    // "GSS-SPNEGO"
                    if(!gssapi)  {
		        
		        gssapi = analyzer_mgr->InstantiateAnalyzer("GSSAPI", bro_analyzer()->Conn()); 
		    }
		
	            if(gssapi)  {
	                
	                gssapi->DeliverStream(pdu->gssapi().length(), pdu->gssapi().begin(), is_orig);
	                
	            }
                }
                                     
		return true;
		%}
		
        function proc_ldap_bind_res(pdu: BindResPDU, is_orig: bool): bool
            %{
            BifEvent::generate_ldap_bind_res(bro_analyzer(),
	                bro_analyzer()->Conn(),
                        build_ldap_res(pdu->result()));
        
            if ( ${pdu.oid2}->encoding()->meta()->length() == 9 &&
	     		  (memcmp("\x2a\x86\x48\x86\xf7\x12\x01\x02\x02", asn1_oid_to_val(pdu->oid2())->Bytes(), pdu->oid2()->encoding()->meta()->length()) == 0 ||
	     		  memcmp("\x2a\x86\x48\x82\xf7\x12\x01\x02\x02", asn1_oid_to_val(pdu->oid2())->Bytes(), pdu->oid2()->encoding()->meta()->length()) == 0 ) )  {
	        // krb5 && ms-krb5 			
	        if ( ! krb5 ) 				
	            krb5 = analyzer_mgr->InstantiateAnalyzer("KRB", bro_analyzer()->Conn());
	         
                if ( krb5 && memcmp("\x02\x00", pdu->blob().begin(), 2) == 0 )  { 				
	            // 0x0200 is an AP_REP
	            krb5->DeliverPacket(pdu->blob().length()-2, pdu->blob().begin()+2, is_orig, 0, 0, 0);				
	        } 			
	    }
        return true;
        %}
};

refine typeattr ModifyReqPDU += &let {
	proc: bool = $context.connection.proc_ldap_mod_req(this);

};

refine typeattr ModifyResPDU += &let {
	proc: bool = $context.connection.proc_ldap_mod_res(this);

};


refine typeattr DeleteReqPDU += &let {
	proc: bool = $context.connection.proc_ldap_del_req(this);

};

refine typeattr DeleteResPDU += &let {
	proc: bool = $context.connection.proc_ldap_del_res(this);

};

refine typeattr AddReqPDU += &let {
	proc: bool = $context.connection.proc_ldap_add_req(this);

};

refine typeattr AddResPDU += &let {
	proc: bool = $context.connection.proc_ldap_add_res(this);

};

refine typeattr ModifyDNReqPDU += &let {
	proc: bool = $context.connection.proc_ldap_modDN_req(this);

};

refine typeattr ModifyDNResPDU += &let {
	proc: bool = $context.connection.proc_ldap_modDN_res(this);

};

refine typeattr BindReqPDU += &let {
	proc: bool = $context.connection.proc_ldap_bind_req(this, is_orig);
};

refine typeattr BindResPDU += &let {
	proc: bool = $context.connection.proc_ldap_bind_res(this, is_orig);
};
