#include <utility>
#include <map>
#include <vector>
#include <iostream>
#include <algorithm>

#include "Analyzer.h"
#include "Plugin.h"
#include "process.h"

#include <zeek/analyzer/Manager.h>

namespace zeek::plugin::pres {

using namespace zeek;

constexpr uint8_t DATA_TRANSFER      = 1;
constexpr uint8_t REFUSE             = 12;
constexpr uint8_t CONNECTION_REQUEST = 13;
constexpr uint8_t CONNECTION_ACCEPT  = 14;
constexpr uint8_t ABORT              = 25;
constexpr uint8_t ABORT_ACCEPT       = 26;
constexpr uint8_t TYPED_DATA         = 33;
constexpr uint8_t RESYNCHRONIZE_ACK  = 34;
constexpr uint8_t RESYNCHRONIZE      = 53;

constexpr const char* CONTEXT_TABLE_NAME = "iso_8650_context_identifier";

PRES_Analyzer::PRES_Analyzer(zeek::Connection* c) : Analyzer("PRES", c) {}

/*
 * The first byte of data must be the si value from the session layer
 * of the current packet followd by the actual payload
 */
void PRES_Analyzer::DeliverPacket(int len, const u_char* data, bool orig,
                                  uint64_t, const IP_Hdr*, int) {
    if(!data || len < 1)
        return;

    IntrusivePtr<Val> pdu = nullptr;
    IntrusivePtr<RecordVal> user_data = nullptr;

    // Read session state, then advance to pdu payload.
    uint8_t sess_state = data[0];
    data++;
    len--;

    switch(sess_state) {
        case CONNECTION_REQUEST:
            pdu = parse<CP_type>(len, data, &asn_DEF_CP_type, process_CP_type);
            if (pdu)
                parse_context_list(cast_intrusive<RecordVal>(pdu));
            break;
        case CONNECTION_ACCEPT:
            pdu = parse<CPA_PPDU>(len, data, &asn_DEF_CPA_PPDU, process_CPA_PPDU);
            break;
        case ABORT:
        case ABORT_ACCEPT:
            pdu = parse<Abort_type>(len, data, &asn_DEF_Abort_type, process_Abort_type);
            break;
        case TYPED_DATA:
            pdu = parse<Typed_data_type_t>(len, data, &asn_DEF_Typed_data_type, process_Typed_data_type);
            break;
        case RESYNCHRONIZE:
            pdu = parse<RS_PPDU>(len, data, &asn_DEF_RS_PPDU, process_RS_PPDU);
            break;
        case RESYNCHRONIZE_ACK:
            pdu = parse<RSA_PPDU>(len, data, &asn_DEF_CPA_PPDU, process_RSA_PPDU);
            break;
        case REFUSE:
            pdu = parse<CPR_PPDU>(len, data, &asn_DEF_CPR_PPDU, process_CPR_PPDU);
            break;
        default:
            pdu = parse<CPC_type_t>(len, data, &asn_DEF_CPC_type, process_CPC_type);
            if (pdu)
                user_data = cast_intrusive<RecordVal>(pdu);
            break;
    }

    if(!user_data && pdu) {
        if(auto rec = cast_intrusive<RecordVal>(pdu)) {
            if(rec->HasField("ttdPPDU")) {
                user_data = cast_intrusive<RecordVal>(rec->GetField("ttdPPDU"));
            } else if (rec->HasField("normal_mode_parameters")) {
                rec = cast_intrusive<RecordVal>(rec->GetField("normal_mode_parameters"));
                if(rec && rec->HasField("user_data"))
                    user_data = cast_intrusive<RecordVal>(rec->GetField("user_data"));
            }
        }
    }

    if(user_data)
        forward(user_data, orig);
}


/*
 * Parses context definition list from a CP-type pdu and populates the per-connection context table.
 */
void PRES_Analyzer::parse_context_list(IntrusivePtr<RecordVal> pdu) {
    auto contexts_val = ConnVal()->GetField(CONTEXT_TABLE_NAME);
    if (!contexts_val || contexts_val->GetType()->Tag() != zeek::TYPE_TABLE) {
        reporter->InternalError("Context table '%s' missing or wrong type", CONTEXT_TABLE_NAME);
        return;
    }
    auto contexts = cast_intrusive<TableVal>(contexts_val);

    if(!pdu) {
        Weird("pres_unable_to_extract_cp_type_pdu", "unable to extract CP-type pdu");
        return;
    }

    if(!pdu->HasField("normal_mode_parameters")) {
        Weird("pres_unable_to_extract_normal_mode_parameters", "unable to extract normal mode parameters from CP-type pdu");
        return;
    }
    auto nmp = cast_intrusive<RecordVal>(pdu->GetField("normal_mode_parameters"));
    if(!nmp) {
        Weird("pres_null_normal_mode_parameters", "normal_mode_parameters extraction failed");
        return;
    }

    if(!nmp->HasField("presentation_context_definition_list")) {
        Weird("pres_unable_to_extract_context_def_list", "unable to extract context definition list from CP-type pdu");
        return;
    }
    auto cdl_field = nmp->GetField("presentation_context_definition_list");
    if (!cdl_field || cdl_field->GetType()->Tag() != zeek::TYPE_VECTOR) {
        Weird("pres_bad_context_def_list", "presentation_context_definition_list wrong type or null");
        return;
    }
    auto cdl = cast_intrusive<VectorVal>(cdl_field);

    // Iterate over all context definition records and update mapping.
    for(unsigned int i=0; i<cdl->Size(); i++) {
        auto ctx_val = cdl->ValAt(i);
        if (!ctx_val || ctx_val->GetType()->Tag() != zeek::TYPE_RECORD) {
            Weird("pres_context_rec_null", "context item null or not a record");
            continue;
        }
        auto ctx = cast_intrusive<RecordVal>(ctx_val);
        if(!ctx || !ctx->HasField("presentation_context_identifier")) {
            Weird("pres_unable_to_extract_context_id", "unable to extract context identifier");
            continue;
        }
        auto cid = ctx->GetField("presentation_context_identifier");
        auto asn = ctx->GetField("abstract_syntax_name");
        if (!cid || !asn)
            continue;
        contexts->Assign(cid, asn);
    }
}

/*
 * Forwards user_data object to the appropriate child analyzer based on context identifier mapping.
 */
void PRES_Analyzer::forward(IntrusivePtr<RecordVal> user_data, bool orig) {
    auto contexts_val = ConnVal()->GetField(CONTEXT_TABLE_NAME);
    if (!contexts_val || contexts_val->GetType()->Tag() != zeek::TYPE_TABLE)
        return;
    auto contexts = contexts_val->AsTableVal();

    auto fec_field = user_data->GetField("fully_encoded_data");
    if (!fec_field || fec_field->GetType()->Tag() != zeek::TYPE_VECTOR)
        return;
    auto fec = fec_field->AsVectorVal();

    for(unsigned int i = 0; i < fec->Size(); i++) {
        auto pdv_val = fec->ValAt(i);
        if (!pdv_val || pdv_val->GetType()->Tag() != zeek::TYPE_RECORD)
            continue;
        auto pdv = cast_intrusive<RecordVal>(pdv_val);
        if (!pdv)
            continue;

        auto cid = pdv->GetField("presentation_context_identifier");
        auto oid = (cid && contexts) ? contexts->Find(cid) : nullptr;
        if(!oid)
            continue;

        // Canonicalize analyzer name based on OID.
        std::string analyzer_key = util::canonify_name("ISO:" + oid->AsStringVal()->ToStdString());
        auto *analyzer = FindChild(analyzer_key.c_str());
        if(!analyzer) {
            analyzer = analyzer_mgr->InstantiateAnalyzer(analyzer_key.c_str(), Conn());
            if(!analyzer)
                continue;
            AddChildAnalyzer(analyzer);
        }

        auto pdv_data_val = pdv->GetField("presentation_data_values");
        if (!pdv_data_val || pdv_data_val->GetType()->Tag() != zeek::TYPE_RECORD)
            continue;
        auto pdv_data = cast_intrusive<RecordVal>(pdv_data_val);

        auto data_val = pdv_data->GetField("single_ASN1_type");
        if (!data_val || data_val->GetType()->Tag() != zeek::TYPE_STRING)
            continue;
        auto data = cast_intrusive<StringVal>(data_val);

        analyzer->NextPacket(data->Len(), data->Bytes(), orig);
    }
}

template <typename CTYPE, typename DESCTYPE>
IntrusivePtr<Val> PRES_Analyzer::parse(
    int len, const u_char *data, DESCTYPE *desc,
    IntrusivePtr<Val> (*process)(CTYPE*)) 
{
    if (!data || len <= 0 || !desc || !process)
        return nullptr;

    CTYPE *pdu = nullptr;

    asn_dec_rval_t rval = ber_decode(nullptr, desc, reinterpret_cast<void**>(&pdu), data, len);
    if(rval.code != RC_OK || !pdu) {
        Weird("pres_parse_error", "unable to parse packet");
        if(pdu)
            desc->free_struct(desc, pdu, 0);
        return nullptr;
    }

    auto res = process(pdu);
    desc->free_struct(desc, pdu, 0);
    return res;
}

} // namespace zeek::plugin::pres
