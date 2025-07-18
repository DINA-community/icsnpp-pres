/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Reliable-Transfer-APDU"
 * 	found in "/tmp/wireshark/epan/dissectors/asn1/rtse/rtse.asn"
 * 	`asn1c -fcompound-names`
 */

#ifndef	_CommonReference_H_
#define	_CommonReference_H_


#include <asn_application.h>

/* Including external dependencies */
#include <UTCTime.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CommonReference */
typedef UTCTime_t	 CommonReference_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_CommonReference;
asn_struct_free_f CommonReference_free;
asn_struct_print_f CommonReference_print;
asn_constr_check_f CommonReference_constraint;
ber_type_decoder_f CommonReference_decode_ber;
der_type_encoder_f CommonReference_encode_der;
xer_type_decoder_f CommonReference_decode_xer;
xer_type_encoder_f CommonReference_encode_xer;

#ifdef __cplusplus
}
#endif

#endif	/* _CommonReference_H_ */
#include <asn_internal.h>
