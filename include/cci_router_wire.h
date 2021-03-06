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

	/* Generic RMA handle info (without data ptr) */
	/* Use this struct when determining the length of a header */
	struct ccir_peer_hdr_rma_size {
		uint8_t type;		/* CCIR_PEER_MSG_RMA_INFO */
		uint8_t pad[3];
		/* 32b */
	} rma_size;

	/* rma request */
	struct ccir_peer_hdr_rma {
		uint8_t type;		/* CCIR_PEER_MSG_RMA_INFO */
		uint8_t pad[3];
		/* 32b */
		char data[1];		/* Start of sender's RMA info */
	} rma;

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

	/* Release the RMA buffer */
	struct ccir_peer_hdr_rma_done {
		uint32_t type	:  8;	/* CCIR_PEER_MSG_RMA_DONE */
		uint32_t idx	: 24;	/* Index of RMA buffer */
		/* 32b */
	} done;

	/* For easy byte swapping to/from network order */
	uint32_t net;
} ccir_peer_hdr_t;

#define CCIR_PEER_BIT_SHIFT	(7)
#define CCIR_PEER_BIT		((uint8_t)(1 << CCIR_PEER_BIT_SHIFT))
#define CCIR_IS_PEER_HDR(x)	((uint8_t)(x) & CCIR_PEER_BIT)
#define CCIR_PEER_HDR_MASK	((uint8_t)~(CCIR_PEER_BIT))
#define CCIR_PEER_HDR_TYPE(x)	((uint8_t)(x) & CCIR_PEER_HDR_MASK)
#define CCIR_PEER_SET_HDR_TYPE(x) ((uint8_t)((x) | CCIR_PEER_BIT))

typedef enum ccir_peer_hdr_type {
	CCIR_PEER_MSG_CONNECT = 0,
	CCIR_PEER_MSG_RMA_INFO,
	CCIR_PEER_MSG_DEL,
	CCIR_PEER_MSG_RIR,
	CCIR_PEER_MSG_RMA_DONE,		/* The receiver can release the RMA buffer */
	CCIR_PEER_MSG_MAX = CCIR_PEER_HDR_MASK	/* We can never exceed this */
} ccir_peer_hdr_type_t;

static inline const char *
ccir_peer_hdr_str(ccir_peer_hdr_type_t type)
{
	switch (type) {
	case CCIR_PEER_MSG_CONNECT:
		return "CCIR_PEER_MSG_CONNECT";
	case CCIR_PEER_MSG_RMA_INFO:
		return "CCIR_PEER_MSG_RMA_INFO";
	case CCIR_PEER_MSG_DEL:
		return "CCIR_PEER_MSG_DEL";
	case CCIR_PEER_MSG_RIR:
		return "CCIR_PEER_MSG_RIR";
	case CCIR_PEER_MSG_RMA_DONE:
		return "CCIR_PEER_MSG_RMA_DONE";
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

/* RMA info */
typedef struct ccir_rma_info {
	struct {
		uint64_t stuff[4];	/* Must match cci_rma_handle_t */
	} handle;
	/* 256b */
	uint32_t rma_len;		/* Length of a RMA transfer */
	/* 288b */
	uint32_t rma_cnt;		/* Number of RMA buffers in handle */
	/* 320b */
} ccir_rma_info_t;

static inline void
ccir_pack_rma_info(ccir_peer_hdr_t *hdr, void *handle, int len,
		uint32_t rma_len, uint32_t rma_cnt)
{
	ccir_rma_info_t *info = (ccir_rma_info_t *)hdr->rma.data;

	hdr->rma.type = CCIR_PEER_SET_HDR_TYPE(CCIR_PEER_MSG_RMA_INFO);
	assert(len == sizeof(info->handle));
	/* the cci_rma_handle_t is already in network order */
	memcpy(&(info->handle), handle, len);
	info->rma_len = htonl(rma_len);
	info->rma_cnt = htonl(rma_cnt);
	hdr->net = htonl(hdr->net);
}

static inline int
ccir_parse_rma_info(ccir_peer_hdr_t *hdr, void **handle, int len,
		uint32_t *rma_len, uint32_t *rma_cnt)
{
	void *h = NULL;
	ccir_rma_info_t *info = (ccir_rma_info_t *)hdr->rma.data;

	assert(len == sizeof(info->handle));

	h = calloc(1, len);
	if (!h)
		return ENOMEM;
	/* the cci_rma_handle_t stays in network order */
	memcpy(h, &(info->handle), len);
	*handle = h;
	*rma_len = ntohl(info->rma_len);
	*rma_cnt = ntohl(info->rma_cnt);
	return 0;
}

/* RIR payload format */
typedef struct ccir_rir_data {
	uint64_t instance;	/* Seconds since epoch */
	/* 64b */
	uint32_t router;	/* Router id */
	/* 96b */
	uint32_t as;		/* Autonomous System id */
	/* 128b */
	struct rir_subnet {
		uint32_t id;		/* Subnet id */
		uint16_t rate;		/* Gb/s */
		uint8_t caps;		/* Subnet capabilities */
		uint8_t pad;		/* Reserved */
	} subnet[1];
	/* 192b */
} ccir_rir_data_t;

static inline void
ccir_pack_rir(ccir_peer_hdr_t *hdr, uint8_t count)
{
	hdr->rir.type = CCIR_PEER_SET_HDR_TYPE(CCIR_PEER_MSG_RIR);
	hdr->rir.count = count;
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

static inline void
ccir_pack_rma_done(ccir_peer_hdr_t *hdr, uint32_t index)
{
	hdr->done.type = CCIR_PEER_SET_HDR_TYPE(CCIR_PEER_MSG_RMA_DONE);
	assert((index >> 24) == 0);
	hdr->done.idx = index;
	hdr->net = htonl(hdr->net);
}
