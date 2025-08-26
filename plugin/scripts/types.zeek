#THIS CODE IS GENERATED. DON'T CHANGE MANUALLY!
module pres;
export {
  
  # ======== PRIMITIVE TYPES =======
  type Presentation_selector: string;
  
  type Presentation_context_identifier: int;
  
  type Abstract_syntax_name: string;
  
  type Transfer_syntax_name: string;
  
  type Simply_encoded_data: string;
  
  type Result: enum {
    Result_acceptance = 0,
    Result_user_rejection = 1,
    provider_rejection = 2,
  };
  
  type Provider_reason: enum {
    Provider_reason_reason_not_specified = 0,
    temporary_congestion = 1,
    local_limit_exceeded = 2,
    called_presentation_address_unknown = 3,
    protocol_version_not_supported = 4,
    default_context_not_supported = 5,
    user_data_not_readable = 6,
    no_PSAP_available = 7,
  };
  
  type Abort_reason: enum {
    Abort_reason_reason_not_specified = 0,
    unrecognized_ppdu = 1,
    unexpected_ppdu = 2,
    unexpected_session_service_primitive = 3,
    unrecognized_ppdu_parameter = 4,
    unexpected_ppdu_parameter = 5,
    invalid_ppdu_parameter_value = 6,
  };
  
  type Event_identifier: enum {
    cp_PPDU = 0,
    cpa_PPDU = 1,
    cpr_PPDU = 2,
    aru_PPDU = 3,
    arp_PPDU = 4,
    ac_PPDU = 5,
    aca_PPDU = 6,
    td_PPDU = 7,
    ttd_PPDU = 8,
    te_PPDU = 9,
    tc_PPDU = 10,
    tcc_PPDU = 11,
    rs_PPDU = 12,
    rsa_PPDU = 13,
    s_release_indication = 14,
    s_release_confirm = 15,
    s_token_give_indication = 16,
    s_token_please_indication = 17,
    s_control_give_indication = 18,
    s_sync_minor_indication = 19,
    s_sync_minor_confirm = 20,
    s_sync_major_indication = 21,
    s_sync_major_confirm = 22,
    s_p_exception_report_indication = 23,
    s_u_exception_report_indication = 24,
    s_activity_start_indication = 25,
    s_activity_resume_indication = 26,
    s_activity_interrupt_indication = 27,
    s_activity_interrupt_confirm = 28,
    s_activity_discard_indication = 29,
    s_activity_discard_confirm = 30,
    s_activity_end_indication = 31,
    s_activity_end_confirm = 32,
  };
  
  
  # ======== COMPLEX TYPES =======
  type Mode_selector: record {
    mode_value: enum {
      normal_mode = 1,
    };
  };
  
  type Protocol_version: vector of enum {
    version_1,
  };
  
  type Calling_presentation_selector: Presentation_selector;
  
  type Called_presentation_selector: Presentation_selector;
  
  type Context_list: vector of record {
    presentation_context_identifier: Presentation_context_identifier;
    abstract_syntax_name: Abstract_syntax_name;
    transfer_syntax_name_list: vector of Transfer_syntax_name;
  };
  
  type Presentation_context_definition_list: Context_list;
  
  type Default_context_name: record {
    abstract_syntax_name: Abstract_syntax_name;
    transfer_syntax_name: Transfer_syntax_name;
  };
  
  type Presentation_requirements: vector of enum {
    context_management,
    restoration,
  };
  
  type User_session_requirements: vector of enum {
    half_duplex,
    duplex,
    expedited_data,
    minor_synchronize,
    major_synchronize,
    resynchronize,
    activity_management,
    negotiated_release,
    capability_data,
    exceptions,
    typed_data,
    symmetric_synchronize,
    data_separation,
  };
  
  type Protocol_options: vector of enum {
    nominated_context,
    short_encoding,
    packed_encoding_rules,
  };
  
  type PDV_list: record {
    transfer_syntax_name: Transfer_syntax_name &optional;
    presentation_context_identifier: Presentation_context_identifier;
    presentation_data_values: record {
      single_ASN1_type: string &optional;
      octet_aligned: string &optional;
      arbitrary: string &optional;
    };
  };
  
  type Fully_encoded_data: vector of PDV_list;
  
  type User_data: record {
    simply_encoded_data: Simply_encoded_data &optional;
    fully_encoded_data: Fully_encoded_data &optional;
  };
  
  type CP_type: record {
    mode_selector: Mode_selector;
    normal_mode_parameters: record {
      protocol_version: Protocol_version;
      calling_presentation_selector: Calling_presentation_selector &optional;
      called_presentation_selector: Called_presentation_selector &optional;
      presentation_context_definition_list: Presentation_context_definition_list &optional;
      default_context_name: Default_context_name &optional;
      presentation_requirements: Presentation_requirements &optional;
      user_session_requirements: User_session_requirements &optional;
      protocol_options: Protocol_options;
      initiators_nominated_context: Presentation_context_identifier &optional;
      extensions: record {
      } &optional;
      user_data: User_data &optional;
    } &optional;
  };
  
  type CPC_type: User_data;
  
  type Responding_presentation_selector: Presentation_selector;
  
  type Result_list: vector of record {
    result: Result;
    transfer_syntax_name: Transfer_syntax_name &optional;
    provider_reason: enum {
      Result_list_reason_not_specified = 0,
      abstract_syntax_not_supported = 1,
      proposed_transfer_syntaxes_not_supported = 2,
      local_limit_on_DCS_exceeded = 3,
    } &optional;
  };
  
  type Presentation_context_definition_result_list: Result_list;
  
  type CPA_PPDU: record {
    mode_selector: Mode_selector;
    normal_mode_parameters: record {
      protocol_version: Protocol_version;
      responding_presentation_selector: Responding_presentation_selector &optional;
      presentation_context_definition_result_list: Presentation_context_definition_result_list &optional;
      presentation_requirements: Presentation_requirements &optional;
      user_session_requirements: User_session_requirements &optional;
      protocol_options: Protocol_options;
      responders_nominated_context: Presentation_context_identifier &optional;
      user_data: User_data &optional;
    } &optional;
  };
  
  type Default_context_result: Result;
  
  type CPR_PPDU: record {
    normal_mode_parameters: record {
      protocol_version: Protocol_version;
      responding_presentation_selector: Responding_presentation_selector &optional;
      presentation_context_definition_result_list: Presentation_context_definition_result_list &optional;
      default_context_result: Default_context_result &optional;
      provider_reason: Provider_reason &optional;
      user_data: User_data &optional;
    } &optional;
  };
  
  type Presentation_context_identifier_list: vector of record {
    presentation_context_identifier: Presentation_context_identifier;
    transfer_syntax_name: Transfer_syntax_name;
  };
  
  type ARU_PPDU: record {
    normal_mode_parameters: record {
      presentation_context_identifier_list: Presentation_context_identifier_list &optional;
      user_data: User_data &optional;
    } &optional;
  };
  
  type ARP_PPDU: record {
    provider_reason: Abort_reason &optional;
    event_identifier: Event_identifier &optional;
  };
  
  type Abort_type: record {
    aru_ppdu: ARU_PPDU &optional;
    arp_ppdu: ARP_PPDU &optional;
  };
  
  type Presentation_context_addition_list: Context_list;
  
  type Presentation_context_deletion_list: vector of Presentation_context_identifier;
  
  type AC_PPDU: record {
    presentation_context_addition_list: Presentation_context_addition_list &optional;
    presentation_context_deletion_list: Presentation_context_deletion_list &optional;
    user_data: User_data &optional;
  };
  
  type Presentation_context_addition_result_list: Result_list;
  
  type Presentation_context_deletion_result_list: vector of enum {
    Presentation_context_deletion_result_list_acceptance = 0,
    Presentation_context_deletion_result_list_user_rejection = 1,
  };
  
  type ACA_PPDU: record {
    presentation_context_addition_result_list: Presentation_context_addition_result_list &optional;
    presentation_context_deletion_result_list: Presentation_context_deletion_result_list &optional;
    user_data: User_data &optional;
  };
  
  type Typed_data_type: record {
    acPPDU: AC_PPDU &optional;
    acaPPDU: ACA_PPDU &optional;
    ttdPPDU: User_data &optional;
  };
  
  type RS_PPDU: record {
    presentation_context_identifier_list: Presentation_context_identifier_list &optional;
    user_data: User_data &optional;
  };
  
  type RSA_PPDU: record {
    presentation_context_identifier_list: Presentation_context_identifier_list &optional;
    user_data: User_data &optional;
  };
  
}
