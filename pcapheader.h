#pragma once
#define PCAPHEADER_H


#include <stdint.h>



struct ether_header
{
    uint8_t ether_dmac[6];
    uint8_t ether_smac[6];
    uint16_t ether_type;
};

struct ip_header
   {

    unsigned int ihl:4;
    unsigned int version:4;

    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_ff;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};


struct tcp_header
{
    uint16_t sport;
    uint16_t dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint16_t res1:4;
    uint16_t doff:4;

};
