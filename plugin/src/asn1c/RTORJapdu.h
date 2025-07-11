/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Reliable-Transfer-APDU"
 * 	found in "/tmp/wireshark/epan/dissectors/asn1/rtse/rtse.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_RTORJapdu_H_
#define	_RTORJapdu_H_


#include <asn_application.h>

/* Including external dependencies */
#include "RefuseReason.h"
#include <ANY.h>
#include <constr_SET.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */

/*
 * Method of determining the components presence
 */
typedef enum RTORJapdu_PR {
	RTORJapdu_PR_refuseReason,	/* Member refuseReason is present */
	RTORJapdu_PR_userDataRJ,	/* Member userDataRJ is present */
} RTORJapdu_PR;

/* RTORJapdu */
typedef struct RTORJapdu {
	RefuseReason_t	*refuseReason	/* OPTIONAL */;
	ANY_t	*userDataRJ	/* OPTIONAL */;
	
	/* Presence bitmask: ASN_SET_ISPRESENT(pRTORJapdu, RTORJapdu_PR_x) */
	unsigned int _presence_map
		[((2+(8*sizeof(unsigned int))-1)/(8*sizeof(unsigned int)))];
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RTORJapdu_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RTORJapdu;

#ifdef __cplusplus
}
#endif

#endif	/* _RTORJapdu_H_ */
#include <asn_internal.h>
