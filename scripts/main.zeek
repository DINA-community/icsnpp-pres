module pres;

export
{
    redef enum Log::ID += { LOG };

    type Info: record
    {
        ts:             time     &log;
        uid:            string   &log;
        id:             conn_id  &log;
        bytes_orig:     count    &log &default=0;
        bytes_resp:     count    &log &default=0;
        packets_orig:   count    &log &default=0;
        packets_resp:   count    &log &default=0;
        refused:        bool     &log &default=F;
        refuse_reason:  string   &log &optional;
        aborted:        bool     &log &default=F;
        abort_reason:   string   &log &optional;
        cids:           string   &log &optional;
    };

    global log_pres: event(rec: Info);
}

redef record connection += {
    pres_info: Info &optional;
};

function get_info(c: connection): Info {
    if(!c?$pres_info) {
        c$pres_info = [
            $ts=network_time(),
            $uid=c$uid,
            $id=c$id,
        ];
    }
    return c$pres_info;
}

function log_cdl(cdl: Context_list, log: Info) {
    log $ cids = "";
    for(i in cdl) {
        local cid = cdl[i] $ presentation_context_identifier;
        local oid = cdl[i] $ abstract_syntax_name;
        log $ cids += fmt("%d:%s;", cid, oid);
    }
}

function log_user_data_plain(is_orig: bool, data: string, log: Info) {
    if(is_orig) {
        log$bytes_orig += |data|;
        log$packets_orig += 1;
    } else {
        log$bytes_resp += |data|;
        log$packets_resp += 1;
    }
}

function log_user_data(is_orig: bool, data: User_data, log: Info) {
    if(data ?$ simply_encoded_data) {
        log_user_data_plain(is_orig, data $ simply_encoded_data, log);
    }
    if(data ?$ fully_encoded_data) {
        local pdv_list = data $ fully_encoded_data;
        for(i in pdv_list) {
            if(pdv_list[i] ?$ presentation_data_values) {
                local pdv = pdv_list[i] $ presentation_data_values;
                if(pdv ?$ single_ASN1_type)
                    log_user_data_plain(is_orig, pdv $ single_ASN1_type, log);
                if(pdv ?$ octet_aligned)
                    log_user_data_plain(is_orig, pdv $ octet_aligned, log);
                if(pdv ?$ arbitrary)
                    log_user_data_plain(is_orig, pdv $ arbitrary, log);
            }
        }
    }
}

event zeek_init() &priority=5 {
    Log::create_stream(pres::LOG, [$columns = Info, $ev = log_pres, $path="pres"]);
}

event pres_connect(c: connection, is_orig: bool, ppdu: CP_type) {

    local log = get_info(c);
    if(ppdu ?$ normal_mode_parameters && ppdu $ normal_mode_parameters ?$ presentation_context_definition_list) {
        local cdl = ppdu $ normal_mode_parameters $ presentation_context_definition_list;
        log_cdl(cdl, log);
    }
}

event pres_refuse(c: connection, is_orig: bool, ppdu: CPR_PPDU) {
    local log = get_info(c);
    log $ refused = T;
    if(ppdu ?$ normal_mode_parameters && ppdu $ normal_mode_parameters ?$ provider_reason)
        log $ refuse_reason = cat(ppdu $ normal_mode_parameters $ provider_reason);
}

event pres_abort(c: connection, is_orig: bool, ppdu: Abort_type) {
    local log = get_info(c);
    log $ aborted = T;
    if(ppdu ?$ arp_ppdu && ppdu $ arp_ppdu ?$ provider_reason)
        log $ abort_reason = cat(ppdu $ arp_ppdu $ provider_reason);
}

event pres_typed_data(c: connection, is_orig: bool, ppdu: Typed_data_type) {
    local log = get_info(c);
    if(ppdu ?$ ttdPPDU)
        log_user_data(is_orig, ppdu $ ttdPPDU, log);
}

event pres_data(c: connection, is_orig: bool, ppdu: CPC_type) {
    local log = get_info(c);
    log_user_data(is_orig, ppdu, log);
}

event connection_state_remove(c: connection) {
    if ( c?$pres_info ) {
        Log::write(LOG, c$pres_info);
        delete c$pres_info;
    }
}
