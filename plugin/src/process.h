/* THIS CODE IS GENERATED. DON'T CHANGE MANUALLY! */

#pragma once

#include "zeek/Val.h"
#include <AC-PPDU.h>
#include <ACA-PPDU.h>
#include <ARP-PPDU.h>
#include <ARU-PPDU.h>
#include <Abort-type.h>
#include <CP-type.h>
#include <CPA-PPDU.h>
#include <CPC-type.h>
#include <CPR-PPDU.h>
#include <Called-presentation-selector.h>
#include <Calling-presentation-selector.h>
#include <Context-list.h>
#include <Default-context-name.h>
#include <Default-context-result.h>
#include <Fully-encoded-data.h>
#include <Mode-selector.h>
#include <PDV-list.h>
#include <Presentation-context-addition-list.h>
#include <Presentation-context-addition-result-list.h>
#include <Presentation-context-definition-list.h>
#include <Presentation-context-definition-result-list.h>
#include <Presentation-context-deletion-list.h>
#include <Presentation-context-deletion-result-list.h>
#include <Presentation-context-identifier-list.h>
#include <Presentation-requirements.h>
#include <Protocol-options.h>
#include <Protocol-version.h>
#include <RS-PPDU.h>
#include <RSA-PPDU.h>
#include <Responding-presentation-selector.h>
#include <Result-list.h>
#include <Typed-data-type.h>
#include <User-data.h>
#include <User-session-requirements.h>

using namespace zeek;

namespace zeek::plugin::pres {

IntrusivePtr<Val> process_CP_type(const CP_type_t *src);
IntrusivePtr<Val> process_CPC_type(const CPC_type_t *src);
IntrusivePtr<Val> process_CPA_PPDU(const CPA_PPDU_t *src);
IntrusivePtr<Val> process_CPR_PPDU(const CPR_PPDU_t *src);
IntrusivePtr<Val> process_Abort_type(const Abort_type_t *src);
IntrusivePtr<Val> process_ARU_PPDU(const ARU_PPDU_t *src);
IntrusivePtr<Val> process_ARP_PPDU(const ARP_PPDU_t *src);
IntrusivePtr<Val> process_Typed_data_type(const Typed_data_type_t *src);
IntrusivePtr<Val> process_AC_PPDU(const AC_PPDU_t *src);
IntrusivePtr<Val> process_ACA_PPDU(const ACA_PPDU_t *src);
IntrusivePtr<Val> process_RS_PPDU(const RS_PPDU_t *src);
IntrusivePtr<Val> process_RSA_PPDU(const RSA_PPDU_t *src);
IntrusivePtr<Val>
process_Called_presentation_selector(const Called_presentation_selector_t *src);
IntrusivePtr<Val> process_Calling_presentation_selector(
    const Calling_presentation_selector_t *src);
IntrusivePtr<Val> process_Context_list(const Context_list_t *src);
IntrusivePtr<Val>
process_Default_context_name(const Default_context_name_t *src);
IntrusivePtr<Val>
process_Default_context_result(const Default_context_result_t *src);
IntrusivePtr<Val> process_Mode_selector(const Mode_selector_t *src);
IntrusivePtr<Val> process_Presentation_context_addition_list(
    const Presentation_context_addition_list_t *src);
IntrusivePtr<Val> process_Presentation_context_addition_result_list(
    const Presentation_context_addition_result_list_t *src);
IntrusivePtr<Val> process_Presentation_context_definition_list(
    const Presentation_context_definition_list_t *src);
IntrusivePtr<Val> process_Presentation_context_definition_result_list(
    const Presentation_context_definition_result_list_t *src);
IntrusivePtr<Val> process_Presentation_context_deletion_list(
    const Presentation_context_deletion_list_t *src);
IntrusivePtr<Val> process_Presentation_context_deletion_result_list(
    const Presentation_context_deletion_result_list_t *src);
IntrusivePtr<Val> process_Presentation_context_identifier_list(
    const Presentation_context_identifier_list_t *src);
IntrusivePtr<Val>
process_Presentation_requirements(const Presentation_requirements_t *src);
IntrusivePtr<Val> process_Protocol_options(const Protocol_options_t *src);
IntrusivePtr<Val> process_Protocol_version(const Protocol_version_t *src);
IntrusivePtr<Val> process_Responding_presentation_selector(
    const Responding_presentation_selector_t *src);
IntrusivePtr<Val> process_Result_list(const Result_list_t *src);
IntrusivePtr<Val> process_User_data(const User_data_t *src);
IntrusivePtr<Val> process_Fully_encoded_data(const Fully_encoded_data_t *src);
IntrusivePtr<Val> process_PDV_list(const PDV_list_t *src);
IntrusivePtr<Val>
process_User_session_requirements(const User_session_requirements_t *src);

} // namespace zeek::plugin::pres
