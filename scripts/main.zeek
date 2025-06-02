module pres;

export
{
    redef enum Log::ID += { LOG };

    type Info: record
    {
        ts_start:     time    &log;
        ts_end:       time    &log;
        uid:          string  &log;
        id:           conn_id &log;

        refused:        bool     &log &default=F;
        refuse_reason:  string   &log &optional;
        aborted:        bool     &log &default=F;
        abort_reason:   string   &log &optional;
        cids:           string   &log &optional;
        data_bytes:     count    &log &default=0;
        data_packets:   count    &log &default=0;
    };

    global log_pres: event(rec: Info);
}

redef record connection += {
    iso_pres_log_rec: Info &optional;
};

function get_or_create_log_rec(c: connection): Info {
    if(! c ?$ iso_pres_log_rec) {
        local now = network_time();
        c $ iso_pres_log_rec = [$ts_start=now, $ts_end=now, $uid=c$uid, $id=c$id];
    }
    return c $ iso_pres_log_rec;
}

function log_cdl(cdl: Context_list, log: Info) {
    log $ cids = "";
    for(i in cdl) {
        local cid = cdl[i] $ presentation_context_identifier;
        local oid = cdl[i] $ abstract_syntax_name;
        log $ cids += fmt("%d:%s;", cid, oid);
    }
}

function log_user_data_plain(data: string, log: Info) {
    log $ data_packets += 1;
    log $ data_bytes += |data|;
}

function log_user_data(data: User_data, log: Info) {
    if(data ?$ simply_encoded_data) {
        log_user_data_plain(data $ simply_encoded_data, log);
    }
    if(data ?$ fully_encoded_data) {
        local pdv_list = data $ fully_encoded_data;
        for(i in pdv_list) {
            if(pdv_list[i] ?$ presentation_data_values) {
                local pdv = pdv_list[i] $ presentation_data_values;
                if(pdv ?$ single_ASN1_type)
                    log_user_data_plain(pdv $ single_ASN1_type, log);
                if(pdv ?$ octet_aligned)
                    log_user_data_plain(pdv $ octet_aligned, log);
                if(pdv ?$ arbitrary)
                    log_user_data_plain(pdv $ arbitrary, log);
            }
        }
    }
}

event zeek_init() &priority=5 {
    Log::create_stream(pres::LOG, [$columns = Info, $ev = log_pres, $path="pres"]);
}

event pres_connect(c: connection, is_orig: bool, ppdu: CP_type) {
    local log = get_or_create_log_rec(c);
    if(ppdu ?$ normal_mode_parameters && ppdu $ normal_mode_parameters ?$ presentation_context_definition_list) {
        local cdl = ppdu $ normal_mode_parameters $ presentation_context_definition_list;
        log_cdl(cdl, log);
    }
}

event pres_refuse(c: connection, is_orig: bool, ppdu: CPR_PPDU) {
    local log = get_or_create_log_rec(c);
    log $ refused = T;
    if(ppdu ?$ normal_mode_parameters && ppdu $ normal_mode_parameters ?$ provider_reason)
        log $ refuse_reason = cat(ppdu $ normal_mode_parameters $ provider_reason);
}

event pres_abort(c: connection, is_orig: bool, ppdu: Abort_type) {
    local log = get_or_create_log_rec(c);
    log $ aborted = T;
    if(ppdu ?$ arp_ppdu && ppdu $ arp_ppdu ?$ provider_reason)
        log $ abort_reason = cat(ppdu $ arp_ppdu $ provider_reason);
}

event pres_typed_data(c: connection, is_orig: bool, ppdu: Typed_data_type) {
    local log = get_or_create_log_rec(c);
    if(ppdu ?$ ttdPPDU)
        log_user_data(ppdu $ ttdPPDU, log);
}

event pres_data(c: connection, is_orig: bool, ppdu: CPC_type) {
    local log = get_or_create_log_rec(c);
    log_user_data(ppdu, log);
}

event connection_state_remove(c: connection) {
    if ( c ?$ iso_pres_log_rec ) {
        Log::write(LOG, c $ iso_pres_log_rec);
        delete c $ iso_pres_log_rec;
    }
}
