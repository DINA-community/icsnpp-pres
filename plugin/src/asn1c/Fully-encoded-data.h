/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "PRES"
 * 	found in "../../../../utils/ISO8823-PRESENTATION.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_Fully_encoded_data_H_
#define	_Fully_encoded_data_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct PDV_list;

/* Fully-encoded-data */
typedef struct Fully_encoded_data {
	A_SEQUENCE_OF(struct PDV_list) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} Fully_encoded_data_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_Fully_encoded_data;

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "PDV-list.h"

#endif	/* _Fully_encoded_data_H_ */
#include <asn_internal.h>
