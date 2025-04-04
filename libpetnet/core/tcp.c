/* 
 * Copyright (c) 2020, Jack Lange <jacklange@cs.pitt.edu>
 * All rights reserved.
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the file "PETLAB_LICENSE".
 */

#include <string.h>
#include <errno.h>

#include <petnet.h>

#include <petlib/pet_util.h>
#include <petlib/pet_log.h>
#include <petlib/pet_hashtable.h>
#include <petlib/pet_json.h>

#include <util/ip_address.h>
#include <util/inet.h>
#include <util/checksum.h>

#include "ethernet.h"
#include "ipv4.h"
#include "tcp.h"
#include "tcp_connection.h"
#include "packet.h"
#include "socket.h"


extern int petnet_errno;

struct tcp_state {
    struct tcp_con_map * con_map;
};

static void __print_debug_msg(const char *);
static struct packet *__construct_pkt(struct tcp_connection *);
static int __send_data_pkt(struct tcp_connection *);
static int __send_flagged_pkt(struct tcp_connection *, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t);
static int __close_connection(struct tcp_connection *);
static int __tcp_pkt_rx_ipv4(struct packet *);

static inline struct tcp_raw_hdr *
__get_tcp_hdr(struct packet * pkt)
{
    struct tcp_raw_hdr * tcp_hdr = pkt->layer_2_hdr + pkt->layer_2_hdr_len + pkt->layer_3_hdr_len;

    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = tcp_hdr;
    pkt->layer_4_hdr_len = tcp_hdr->header_len * 4;

    return tcp_hdr;
}


static inline struct tcp_raw_hdr *
__make_tcp_hdr(struct packet * pkt, 
               uint32_t        option_len)
{
    pkt->layer_4_type    = TCP_PKT;
    pkt->layer_4_hdr     = pet_malloc(sizeof(struct tcp_raw_hdr) + option_len);
    pkt->layer_4_hdr_len = sizeof(struct tcp_raw_hdr) + option_len;

    return (struct tcp_raw_hdr *)(pkt->layer_4_hdr);
}

static inline void *
__get_payload(struct packet * pkt)
{
    if (pkt->layer_3_type == IPV4_PKT) {
        struct ipv4_raw_hdr * ipv4_hdr = pkt->layer_3_hdr;

        pkt->payload     = pkt->layer_4_hdr + pkt->layer_4_hdr_len;
        pkt->payload_len = ntohs(ipv4_hdr->total_len) - (pkt->layer_3_hdr_len + pkt->layer_4_hdr_len);

        return pkt->payload;
    } else {
        log_error("Unhandled layer 3 packet format\n");
        return NULL;
    }

}

pet_json_obj_t
tcp_hdr_to_json(struct tcp_raw_hdr * hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    hdr_json = pet_json_new_obj("TCP Header");

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not create TCP Header JSON\n");
        goto err;
    }

    pet_json_add_u16 (hdr_json, "src port",    ntohs(hdr->src_port));
    pet_json_add_u16 (hdr_json, "dst port",    ntohs(hdr->dst_port));
    pet_json_add_u32 (hdr_json, "seq num",     ntohl(hdr->seq_num));
    pet_json_add_u32 (hdr_json, "ack num",     ntohl(hdr->ack_num));
    pet_json_add_u8  (hdr_json, "header len",  hdr->header_len * 4);
    pet_json_add_bool(hdr_json, "URG flag",    hdr->flags.URG);
    pet_json_add_bool(hdr_json, "ACK flag",    hdr->flags.ACK);
    pet_json_add_bool(hdr_json, "PSH flag",    hdr->flags.PSH);
    pet_json_add_bool(hdr_json, "RST flag",    hdr->flags.RST);
    pet_json_add_bool(hdr_json, "SYN flag",    hdr->flags.SYN);
    pet_json_add_bool(hdr_json, "FIN flag",    hdr->flags.FIN);
    pet_json_add_u16 (hdr_json, "recv win",    ntohs(hdr->recv_win));
    pet_json_add_u16 (hdr_json, "checksum",    ntohs(hdr->checksum));
    pet_json_add_u16 (hdr_json, "urgent ptr",  ntohs(hdr->urgent_ptr));


    return hdr_json;

err:
    if (hdr_json != PET_JSON_INVALID_OBJ) pet_json_free(hdr_json);

    return PET_JSON_INVALID_OBJ;
}


void
print_tcp_header(struct tcp_raw_hdr * tcp_hdr)
{
    pet_json_obj_t hdr_json = PET_JSON_INVALID_OBJ;

    char * json_str = NULL;

    hdr_json = tcp_hdr_to_json(tcp_hdr);

    if (hdr_json == PET_JSON_INVALID_OBJ) {
        log_error("Could not serialize TCP Header to JSON\n");
        return;
    }

    json_str = pet_json_serialize(hdr_json);

    pet_printf("\"TCP Header\": %s\n", json_str);

    pet_free(json_str);
    pet_json_free(hdr_json);

    return;

}





int 
tcp_listen(struct socket    * sock, 
           struct ipv4_addr * local_addr,
           uint16_t           local_port)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection * con = NULL;
	uint8_t remote_ip_octets[] = {0, 0, 0, 0};
    struct ipv4_addr *remote_ip = ipv4_addr_from_octets(remote_ip_octets);

    con = create_ipv4_tcp_con(tcp_state->con_map, local_addr, remote_ip, local_port, 0);
    con->con_state = LISTEN;

    put_and_unlock_tcp_con(con);
    __print_debug_msg("Listening...\n");
    return 0;

}

int 
tcp_connect_ipv4(struct socket    * sock, 
                 struct ipv4_addr * local_addr, 
                 uint16_t           local_port,
                 struct ipv4_addr * remote_addr,
                 uint16_t           remote_port)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection * con = NULL;

    con = create_ipv4_tcp_con(tcp_state->con_map, local_addr, remote_addr, local_port, remote_port);

    // send SYN
    __send_flagged_pkt(con, 0, 1, 0, 0, 0, 0);
    con->con_state = SYN_SENT;

    put_and_unlock_tcp_con(con);
    return 0;
}

static void __print_debug_msg(const char *msg) {
    if (petnet_state->debug_enable) {
        pet_printf(msg);
    }
}

// constructs a new packet for the specified tcp_connection
// payload is NULL by default
static struct packet *__construct_pkt(struct tcp_connection *con) {

    struct packet *pkt;
    struct tcp_raw_hdr *tcp_hdr;

    if (con == NULL) {
        return NULL;
    }

    pkt = create_empty_packet();
    tcp_hdr = __make_tcp_hdr(pkt, 0);

    tcp_hdr->src_port = htons(con->ipv4_tuple.local_port);
    tcp_hdr->dst_port = htons(con->ipv4_tuple.remote_port);
    tcp_hdr->header_len = pkt->layer_4_hdr_len / 4;
    tcp_hdr->checksum = 0;
    pkt->payload = NULL;
    pkt->payload_len = 0;

    return pkt;

}

static int __send_flagged_pkt(struct tcp_connection * con, uint8_t ack, uint8_t syn, uint8_t fin, uint8_t rst, uint8_t urg, uint8_t psh) {

    struct packet *pkt;
    struct tcp_raw_hdr *hdr;

    pkt = __construct_pkt(con);
    hdr = (struct tcp_raw_hdr *) pkt->layer_4_hdr;
    hdr->flags.ACK = ack;
    hdr->flags.FIN = fin;
    hdr->flags.PSH = psh;
    hdr->flags.RST = rst;
    hdr->flags.SYN = syn;
    hdr->flags.URG = urg;
    if (petnet_state->debug_enable) {
        pet_printf("About to send TCP packet...\n");
        print_tcp_header(hdr);
    }

    if (ipv4_pkt_tx(pkt, con->ipv4_tuple.remote_ip) != 0) {
        return -1;
    }
    __print_debug_msg("Flagged packet transmitted\n");

    return 0;

}

static int __send_data_pkt(struct tcp_connection * con) {
    
    struct packet *pkt;
	struct socket *sock = con->sock;
	uint32_t len = 0;
	void *buf = NULL;

    if (con == NULL) {
        return -1;
    }

    pkt = __construct_pkt(con);
	
	len = pet_socket_send_capacity(sock);
	buf = pet_malloc(len);
	pet_socket_sending_data(sock, buf, len);
	pkt->payload_len = len;
	pkt->payload = pet_malloc(len);
	memcpy(pkt->payload, buf, len);
	pet_free(buf);
	
	if (ipv4_pkt_tx(pkt, con->ipv4_tuple.remote_ip) < 0) {
		return -1;
	}
    __print_debug_msg("Data packet transmitted\n");
	
	return 0;

}

int
tcp_send(struct socket * sock)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection * con = get_and_lock_tcp_con_from_sock(tcp_state->con_map, sock);

    if (con->con_state != ESTABLISHED) {
        log_error("TCP connection is not established\n");
        if (con != NULL) put_and_unlock_tcp_con(con);
        return -1;
    }
    
    __send_data_pkt(con);
    put_and_unlock_tcp_con(con);
    return 0;

}

static int __close_connection(struct tcp_connection *con) {

    struct tcp_state *tcp_state = petnet_state->tcp_state;

    remove_tcp_con(tcp_state->con_map, con);
    return 0;

}

/* Petnet assumes SO_LINGER semantics, so if we'ere here there is no pending write data */
int
tcp_close(struct socket * sock)
{
    struct tcp_state      * tcp_state = petnet_state->tcp_state;
    struct tcp_connection * con = get_and_lock_tcp_con_from_sock(tcp_state->con_map, sock);

    if (con->con_state != ESTABLISHED) {
        log_error("TCP connection is not established\n");
        if (con != NULL) put_and_unlock_tcp_con(con);
        return -1;
    }

    __send_flagged_pkt(con, 0, 0, 1, 0, 0, 0);
    con->con_state = FIN_WAIT1;
    __print_debug_msg("State changed to FIN_WAIT1\n");
    put_and_unlock_tcp_con(con);
    return 0;
}

static int __tcp_pkt_rx_ipv4(struct packet *pkt) {

	struct tcp_state *tcp_state = petnet_state->tcp_state;
	struct tcp_connection *con = NULL;
	struct socket *sock = NULL;
	struct ipv4_raw_hdr *ipv4_hdr = (struct ipv4_raw_hdr *)pkt->layer_3_hdr;
	struct tcp_raw_hdr *tcp_hdr = __get_tcp_hdr(pkt);
	//void *payload = __get_payload(pkt);
	uint32_t len = -1;
	void *buf = NULL;
	struct ipv4_addr *src_ip = ipv4_addr_from_octets(ipv4_hdr->src_ip);
	struct ipv4_addr *dst_ip = ipv4_addr_from_octets(ipv4_hdr->dst_ip);
	uint16_t src_port = htons(tcp_hdr->src_port);
	uint16_t dst_port = htons(tcp_hdr->dst_port);

	if (petnet_state->debug_enable) {
		pet_printf("Received TCP packet\n");
		print_tcp_header(tcp_hdr);
	}
	
	con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map, dst_ip, src_ip, dst_port, src_port);
    if (con == NULL) { // connection probably still in LISTEN state
        uint8_t octets[] = {0, 0, 0, 0};
        struct ipv4_addr *empty_src_ip = ipv4_addr_from_octets(octets);
        con = get_and_lock_tcp_con_from_ipv4(tcp_state->con_map, dst_ip, empty_src_ip, dst_port, 0);
        if (con == NULL) {
            __print_debug_msg("TCP connection does not exist\n");
            return -1;
        }
        remove_tcp_con(tcp_state->con_map, con);
        con = create_ipv4_tcp_con(tcp_state->con_map, dst_ip, src_ip, dst_port, src_port);
        con->con_state = LISTEN;
        __print_debug_msg("Connection information updated\n");
    }
	sock = con->sock;
	
    if (petnet_state->debug_enable) {
        pet_printf("state=%d\n", con->con_state);
    }
    if (con->con_state == ESTABLISHED) {

        if (tcp_hdr->flags.RST > 0) {
            __print_debug_msg("Received RST\n");
            __close_connection(con);
            pet_socket_closed(sock);
            return 0;

        } else if (tcp_hdr->flags.FIN > 0) {
            __print_debug_msg("Received FIN\n");
            __send_flagged_pkt(con, 1, 0, 0, 0, 0, 0);
            con->con_state = CLOSE_WAIT;
            __print_debug_msg("State changed to CLOSE_WAIT\n");
            __send_flagged_pkt(con, 0, 0, 1, 0, 0, 0);
            con->con_state = LAST_ACK;
            __print_debug_msg("State changed to LAST_ACK\n");
        }

		len = pet_socket_recv_capacity(sock);
        buf = pet_malloc(len);
        pet_socket_received_data(sock, buf, len);
        __send_flagged_pkt(con, 1, 0, 0, 0, 0, 0);

	} else if (con->con_state == LISTEN) {

		if (tcp_hdr->flags.SYN > 0) {
            __print_debug_msg("Received SYN\n");
            __send_flagged_pkt(con, 1, 1, 0, 0, 0, 0);
            con->con_state = SYN_RCVD;
            __print_debug_msg("State changed to SYN_RCVD\n");

        } else {
            __print_debug_msg("Received unexpected packet\n");
        }

    } else if (con->con_state == SYN_SENT) {

        if (tcp_hdr->flags.SYN > 0 && tcp_hdr->flags.ACK > 0) {
            __print_debug_msg("Received SYN-ACK\n");
            __send_flagged_pkt(con, 1, 0, 0, 0, 0, 0);
            con->con_state = ESTABLISHED;
            __print_debug_msg("State changed to ESTABLISHED\n");
            pet_socket_connected(sock);
        }

    } else if (con->con_state == SYN_RCVD) {

        if (tcp_hdr->flags.ACK > 0) {
            __print_debug_msg("Received ACK\n");
            con->con_state = ESTABLISHED;
            __print_debug_msg("State changed to ESTABLISHED\n");
            pet_socket_accepted(sock, src_ip, src_port);

        } else {
            __print_debug_msg("Received unexpected packet\n");
        }

    } else if (con->con_state == FIN_WAIT1) {

        if (tcp_hdr->flags.ACK > 0) {
            __print_debug_msg("Received ACK\n");
            con->con_state = FIN_WAIT2;
            __print_debug_msg("State changed to FIN_WAIT2\n");
        } else {
            __print_debug_msg("Received unexpected packet\n");
        }

    } else if (con->con_state == FIN_WAIT2) {

        if (tcp_hdr->flags.FIN > 0) {
            __print_debug_msg("Received FIN\n");
            __send_flagged_pkt(con, 1, 0, 0, 0, 0, 0);
            con->con_state = TIME_WAIT;
            __print_debug_msg("State changed to TIME_WAIT\n");
        }

    } else if (con->con_state == LAST_ACK) {

        if (tcp_hdr->flags.ACK > 0) {
            __print_debug_msg("Received ACK\n");
            con->con_state = CLOSED;
            __print_debug_msg("State changed to CLOSED\n");
            __close_connection(con);
            pet_socket_closed(sock);
            return 0;
        }

    }
	
	put_and_unlock_tcp_con(con);
	return 0;
	
}

int 
tcp_pkt_rx(struct packet * pkt)
{
    if (pkt->layer_3_type == IPV4_PKT) {
		return __tcp_pkt_rx_ipv4(pkt);
    }

    return -1;
}

int 
tcp_init(struct petnet * petnet_state)
{
    struct tcp_state * state = pet_malloc(sizeof(struct tcp_state));

    state->con_map  = create_tcp_con_map();

    petnet_state->tcp_state = state;
    
    return 0;
}
