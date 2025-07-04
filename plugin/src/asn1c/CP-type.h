/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "PRES"
 * 	found in "../../../../utils/ISO8823-PRESENTATION.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_CP_type_H_
#define	_CP_type_H_


#include <asn_application.h>

/* Including external dependencies */
#include "Mode-selector.h"
#include "Protocol-version.h"
#include "Calling-presentation-selector.h"
#include "Called-presentation-selector.h"
#include "Presentation-requirements.h"
#include "User-session-requirements.h"
#include "Protocol-options.h"
#include "Presentation-context-identifier.h"
#include <constr_SEQUENCE.h>
#include <constr_SET.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */

/*
 * Method of determining the components presence
 */
typedef enum CP_type_PR {
	CP_type_PR_mode_selector,	/* Member mode_selector is present */
	CP_type_PR_normal_mode_parameters,	/* Member normal_mode_parameters is present */
} CP_type_PR;

/* Forward declarations */
struct Context_list;
struct Default_context_name;
struct User_data;

/* CP-type */
typedef struct CP_type {
	Mode_selector_t	 mode_selector;
	struct CP_type__normal_mode_parameters {
		Protocol_version_t	*protocol_version	/* DEFAULT {version-1} */;
		Calling_presentation_selector_t	*calling_presentation_selector	/* OPTIONAL */;
		Called_presentation_selector_t	*called_presentation_selector	/* OPTIONAL */;
		struct Context_list	*presentation_context_definition_list	/* OPTIONAL */;
		struct Default_context_name	*default_context_name	/* OPTIONAL */;
		Presentation_requirements_t	*presentation_requirements	/* OPTIONAL */;
		User_session_requirements_t	*user_session_requirements	/* OPTIONAL */;
		Protocol_options_t	*protocol_options	/* DEFAULT {} */;
		Presentation_context_identifier_t	*initiators_nominated_context	/* OPTIONAL */;
		struct CP_type__normal_mode_parameters__extensions {
			/*
			 * This type is extensible,
			 * possible extensions are below.
			 */
			
			/* Context for parsing across buffer boundaries */
			asn_struct_ctx_t _asn_ctx;
		} *extensions;
		struct User_data	*user_data	/* OPTIONAL */;
		
		/* Context for parsing across buffer boundaries */
		asn_struct_ctx_t _asn_ctx;
	} *normal_mode_parameters;
	
	/* Presence bitmask: ASN_SET_ISPRESENT(pCP_type, CP_type_PR_x) */
	unsigned int _presence_map
		[((2+(8*sizeof(unsigned int))-1)/(8*sizeof(unsigned int)))];
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} CP_type_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CP_type;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "Presentation-context-definition-list.h"
#include "Default-context-name.h"
#include "User-data.h"

#endif	/* _CP_type_H_ */
#include <asn_internal.h>
