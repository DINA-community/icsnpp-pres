/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Reliable-Transfer-APDU"
 * 	found in "/tmp/wireshark/epan/dissectors/asn1/rtse/rtse.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_AbortReason_H_
#define	_AbortReason_H_


#include <asn_application.h>

/* Including external dependencies */
#include <NativeInteger.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum AbortReason {
	AbortReason_localSystemProblem	= 0,
	AbortReason_invalidParameter	= 1,
	AbortReason_unrecognizedActivity	= 2,
	AbortReason_temporaryProblem	= 3,
	AbortReason_protocolError	= 4,
	AbortReason_permanentProblem	= 5,
	AbortReason_userError	= 6,
	AbortReason_transferCompleted	= 7
} e_AbortReason;

/* AbortReason */
typedef long	 AbortReason_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_AbortReason;
asn_struct_free_f AbortReason_free;
asn_struct_print_f AbortReason_print;
asn_constr_check_f AbortReason_constraint;
ber_type_decoder_f AbortReason_decode_ber;
der_type_encoder_f AbortReason_encode_der;
xer_type_decoder_f AbortReason_decode_xer;
xer_type_encoder_f AbortReason_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _AbortReason_H_ */
#include <asn_internal.h>
