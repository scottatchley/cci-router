/*
 * Copyright (c) 2013 UT-Battelle, LLC.  All rights reserved.
 *
 * See COPYING in top-level directory
 *
 * $COPYRIGHT$
 *
 */

#include <arpa/inet.h>

#define U32_HI 0
#define U32_LO 1

static inline uint64_t
ccir_htonll(uint64_t in)
{
	union {
		uint64_t u64;
		uint32_t u32[2];
	} out;

	out.u32[U32_HI] = htonl((uint32_t)(in >> 32));
	out.u32[U32_LO] = htonl((uint32_t)(in & 0xFFFFFFFF));

	return out.u64;
}

static inline uint64_t
ccir_ntohll(uint64_t in)
{
	union {
		uint64_t u64;
		uint32_t u32[2];
	} out;

	out.u32[U32_HI] = ntohl((uint32_t)(in >> 32));
	out.u32[U32_LO] = ntohl((uint32_t)(in & 0xFFFFFFFF));

	return out.u64;
}

#define CCIR_VERSION (1)

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

	/* Generic delete msg (without data ptr) */
	/* Use this struct when determining the length of a header */
	struct ccir_peer_hdr_del_size {
		uint8_t type;		/* CCIR_PEER_MSG_DEL */
		uint8_t bye;		/* Set if closing connection */
		uint8_t count;		/* Number of endpoints */
		uint8_t a;		/* Pad */
		/* 32b */
	} del_size;

	/* Delete message */
	struct ccir_peer_hdr_del {
		uint8_t type;		/* CCIR_PEER_MSG_DEL */
		uint8_t bye;		/* Set if closing connection */
		uint8_t count;		/* Number of endpoints */
		uint8_t a;		/* Pad */
		/* 32b */
		char data[1];		/* Start of router's ID */
	} del;

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

	/* For easy byte swapping to/from network order */
	uint32_t net;
} ccir_peer_hdr_t;

#define CCIR_PEER_BIT_SHIFT	(3)
#define CCIR_PEER_BIT		((uint8_t)(1 << CCIR_PEER_BIT_SHIFT))
#define CCIR_IS_PEER_HDR(x)	((uint8_t)(x) & CCIR_PEER_BIT)
#define CCIR_PEER_HDR_MASK	((uint8_t)~(CCIR_PEER_BIT))
#define CCIR_PEER_HDR_TYPE(x)	((uint8_t)(x) & CCIR_PEER_HDR_MASK)
#define CCIR_PEER_SET_HDR_TYPE(x) ((uint8_t)((x) | CCIR_PEER_BIT))

typedef enum ccir_peer_hdr_type {
	CCIR_PEER_MSG_CONNECT = 0,
	CCIR_PEER_MSG_DEL,
	CCIR_PEER_MSG_RIR,
	CCIR_PEER_MSG_MAX = 7		/* We can never exceed this */
} ccir_peer_hdr_type_t;

static inline const char *
ccir_peer_hdr_str(ccir_peer_hdr_type_t type)
{
	switch (type) {
	case CCIR_PEER_MSG_CONNECT:
		return "CCIR_PEER_MSG_CONNECT";
	case CCIR_PEER_MSG_DEL:
		return "CCIR_PEER_MSG_DEL";
	case CCIR_PEER_MSG_RIR:
		return "CCIR_PEER_MSG_RIR";
	default:
		return "Unknown peer msg type";
	}
}

static inline void
ccir_pack_connect(ccir_peer_hdr_t *hdr, const char *uri)
{
	assert(strlen(uri) < 256); /* must fit in uint8_t */

	hdr->connect.type = CCIR_PEER_SET_HDR_TYPE(CCIR_PEER_MSG_CONNECT);
	hdr->connect.version = CCIR_VERSION;
	hdr->connect.len = (uint8_t) strlen(uri);
	memcpy(hdr->connect.data, uri, hdr->connect.len);
	hdr->net = htonl(hdr->net);
	return;
}

/* RIR payload format */
typedef struct ccir_rir_data {
	uint64_t instance;	/* Seconds since epoch */
	/* 64b */
	uint32_t as;		/* Autonomous System id */
	/* 96b */
	uint32_t subnet;	/* Subnet id */
	/* 128b */
	uint32_t router;	/* Router id */
	/* 160b */
	uint16_t rate;		/* Gb/s */
	uint8_t caps;		/* Subnet capabilities */
	uint8_t pad;		/* Reserved */
	/* 192b */
} ccir_rir_data_t;

static inline void
ccir_pack_rir(ccir_peer_hdr_t *hdr)
{
	hdr->rir.type = CCIR_PEER_SET_HDR_TYPE(CCIR_PEER_MSG_RIR);
	hdr->rir.count = 1;
	hdr->net = htonl(hdr->net);
}

typedef struct ccir_del_data {
	/* DEL payload format */
	/* already includes one subnet, we can allocate (N-1) * sizeof(subnet) */
	uint64_t instance;	/* Router instance */
	/* 64b */
	uint32_t router;	/* Router id */
	/* 96b */
	uint32_t subnet[1];	/* Subnet list */
} ccir_del_data_t;

static inline void
ccir_pack_del(ccir_peer_hdr_t *hdr, uint8_t bye, uint8_t count)
{
	hdr->del.type = CCIR_PEER_SET_HDR_TYPE(CCIR_PEER_MSG_DEL);
	hdr->del.bye = bye;
	hdr->del.count = count;
	hdr->net = htonl(hdr->net);
	return;
}
