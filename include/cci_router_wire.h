/*
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#define CCIR_VERSION (1)

typedef union ccir_rir_data {
	/* Generic RIR payload format (without URI pointer) */
	/* Use this struct when determining the length of the payload */
	struct ccir_rir_rec_size {
		uint32_t as;		/* Autonomous System id */
		/* 32b */
		uint32_t subnet;	/* Subnet id */
		/* 64b */
		uint32_t router;	/* Router id */
		/* 96b */
		uint32_t cookie;	/* Random cookie to define instance */
		/* 128b */
		uint16_t rate;		/* Gb/s */
		uint8_t caps;		/* Reserved */
		uint8_t len;		/* Router URI len */
		/* 160b */
	} rec_size;

	/* RIR payload format */
	struct ccir_rir_rec {
		uint32_t as;		/* Autonomous System id */
		/* 32b */
		uint32_t subnet;	/* Subnet id */
		/* 64b */
		uint32_t router;	/* Router id */
		/* 96b */
		uint32_t cookie;	/* Random cookie to define instance */
		/* 128b */
		uint16_t rate;		/* Gb/s */
		uint8_t caps;		/* Reserved */
		uint8_t len;		/* Router URI len */
		/* 160b */
		char data[1];		/* Note: the URI will be padded to
					   a multiple of 32b. The URI len will
					   indicate the actual length of the URI
					   less the padding. */
	} rec;
} ccir_rir_data_t;

typedef union ccir_peer_hdr {
	/* Generic header type, used by all messages */
	struct ccir_peer_hdr_generic {
		uint8_t type;		/* Header type - must not clash with e2e types */
		uint8_t a[3];		/* As needed by header types */
		/* 32b */
	} generic;

	/* Generic connect request (without data ptr) */
	/* Use this struct when determining the length of a header */
	struct ccir_peer_hdr_connect_size {
		uint8_t type;		/* CCIR_PEER_MSG_CONNECT */
		uint8_t version;	/* For compatability */
		uint8_t len;		/* Sender's URI length */
		uint8_t pad;
		/* 32b */
	} connect_size;

	/* Connect request */
	struct ccir_peer_hdr_connect {
		uint8_t type;		/* CCIR_PEER_MSG_CONNECT */
		uint8_t version;	/* For compatability */
		uint8_t len;		/* Sender's URI length */
		uint8_t pad;
		/* 32b */
		char data[1];		/* Start of sender's URI */
	} connect;

	/* Bye message */
	struct ccir_peer_hdr_bye {
		uint8_t type;		/* CCIR_PEER_MSG_BYE */
		uint8_t a[3];		/* Pad */
	} bye;

	/* Generic router information records (without data ptr) */
	/* Use this struct when determining the length of a header */
	struct ccir_peer_hdr_rir_size {
		uint8_t type;		/* CCIR_PEER_MSG_RIR */
		uint8_t count;		/* Number of included records */
		uint8_t a[2];		/* Pad */
		/* 32b */
	} rir_size;

	/* Router information records */
	struct ccir_peer_hdr_rir {
		uint8_t type;		/* CCIR_PEER_MSG_RIR */
		uint8_t count;		/* Number of included records */
		uint8_t a[2];		/* Pad */
		/* 32b */
		char data[1];		/* RIR data payload */
	} rir;
} ccir_peer_hdr_t;

#define CCIR_PEER_BIT_SHIFT	(3)
#define CCIR_PEER_BIT		((uint8_t)(1 << CCIR_PEER_BIT_SHIFT))
#define CCIR_IS_PEER_HDR(x)	((uint8_t)(x) & CCIR_PEER_BIT)
#define CCIR_PEER_HDR_MASK	((uint8_t)~(CCIR_PEER_BIT))
#define CCIR_PEER_HDR_TYPE(x)	((uint8_t)(x) & CCIR_PEER_HDR_MASK)
#define CCIR_PEER_SET_HDR_TYPE(x) ((uint8_t)((x) | CCIR_PEER_BIT))

typedef enum ccir_peer_hdr_type {
	CCIR_PEER_MSG_CONNECT = 0,
	CCIR_PEER_MSG_BYE,
	CCIR_PEER_MSG_RIR,
	CCIR_PEER_MSG_MAX = 7		/* We can never exceed this */
} ccir_peer_hdr_type_t;

static inline const char *
ccir_peer_hdr_str(ccir_peer_hdr_type_t type)
{
	switch (type) {
	case CCIR_PEER_MSG_CONNECT:
		return "CCIR_PEER_MSG_CONNECT";
	case CCIR_PEER_MSG_BYE:
		return "CCIR_PEER_MSG_BYE";
	case CCIR_PEER_MSG_RIR:
		return "CCIR_PEER_MSG_RIR";
	default:
		return "Unknown peer msg type";
	}
}

static inline void
ccir_pack_connect(ccir_peer_hdr_t *hdr, const char *uri)
{
	hdr->connect.type = CCIR_PEER_SET_HDR_TYPE(CCIR_PEER_MSG_CONNECT);
	hdr->connect.version = CCIR_VERSION;
	hdr->connect.len = (uint8_t) strlen(uri);
	memcpy(hdr->connect.data, uri, hdr->connect.len);
	return;
}

static inline void
ccir_pack_bye(ccir_peer_hdr_t *hdr)
{
	hdr->bye.type = CCIR_PEER_SET_HDR_TYPE(CCIR_PEER_MSG_BYE);
	return;
}

static inline void
ccir_pack_rir(ccir_peer_hdr_t *hdr)
{
	hdr->rir.type = CCIR_PEER_SET_HDR_TYPE(CCIR_PEER_MSG_RIR);
	hdr->rir.count = 1;
}
