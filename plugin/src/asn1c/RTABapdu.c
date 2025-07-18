/*
 * Generated by asn1c-0.9.28 (http://lionet.info/asn1c)
 * From ASN.1 module "Reliable-Transfer-APDU"
 * 	found in "/tmp/wireshark/epan/dissectors/asn1/rtse/rtse.asn"
 * 	`asn1c -fcompound-names`
 */

#include "RTABapdu.h"

static asn_TYPE_member_t asn_MBR_RTABapdu_1[] = {
	{ ATF_POINTER, 3, offsetof(struct RTABapdu, abortReason),
		(ASN_TAG_CLASS_CONTEXT | (0 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_AbortReason,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"abortReason"
		},
	{ ATF_POINTER, 2, offsetof(struct RTABapdu, reflectedParameter),
		(ASN_TAG_CLASS_CONTEXT | (1 << 2)),
		-1,	/* IMPLICIT tag at current level */
		&asn_DEF_BIT_STRING,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"reflectedParameter"
		},
	{ ATF_POINTER, 1, offsetof(struct RTABapdu, userdataAB),
		(ASN_TAG_CLASS_CONTEXT | (2 << 2)),
		+1,	/* EXPLICIT tag at current level */
		&asn_DEF_ANY,
		0,	/* Defer constraints checking to the member type */
		0,	/* PER is not compiled, use -gen-PER */
		0,
		"userdataAB"
		},
};
static const ber_tlv_tag_t asn_DEF_RTABapdu_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (17 << 2))
};
static const asn_TYPE_tag2member_t asn_MAP_RTABapdu_tag2el_1[] = {
    { (ASN_TAG_CLASS_CONTEXT | (0 << 2)), 0, 0, 0 }, /* abortReason */
    { (ASN_TAG_CLASS_CONTEXT | (1 << 2)), 1, 0, 0 }, /* reflectedParameter */
    { (ASN_TAG_CLASS_CONTEXT | (2 << 2)), 2, 0, 0 } /* userdataAB */
};
static const uint8_t asn_MAP_RTABapdu_mmap_1[(3 + (8 * sizeof(unsigned int)) - 1) / 8] = {
	(0 << 7) | (0 << 6) | (0 << 5)
};
static asn_SET_specifics_t asn_SPC_RTABapdu_specs_1 = {
	sizeof(struct RTABapdu),
	offsetof(struct RTABapdu, _asn_ctx),
	offsetof(struct RTABapdu, _presence_map),
	asn_MAP_RTABapdu_tag2el_1,
	3,	/* Count of tags in the map */
	asn_MAP_RTABapdu_tag2el_1,	/* Same as above */
	3,	/* Count of tags in the CXER map */
	0,	/* Whether extensible */
	(unsigned int *)asn_MAP_RTABapdu_mmap_1	/* Mandatory elements map */
};
asn_TYPE_descriptor_t asn_DEF_RTABapdu = {
	"RTABapdu",
	"RTABapdu",
	SET_free,
	SET_print,
	SET_constraint,
	SET_decode_ber,
	SET_encode_der,
	SET_decode_xer,
	SET_encode_xer,
	0, 0,	/* No PER support, use "-gen-PER" to enable */
	0,	/* Use generic outmost tag fetcher */
	asn_DEF_RTABapdu_tags_1,
	sizeof(asn_DEF_RTABapdu_tags_1)
		/sizeof(asn_DEF_RTABapdu_tags_1[0]), /* 1 */
	asn_DEF_RTABapdu_tags_1,	/* Same as above */
	sizeof(asn_DEF_RTABapdu_tags_1)
		/sizeof(asn_DEF_RTABapdu_tags_1[0]), /* 1 */
	0,	/* No PER visible constraints */
	asn_MBR_RTABapdu_1,
	3,	/* Elements count */
	&asn_SPC_RTABapdu_specs_1	/* Additional specs */
};

