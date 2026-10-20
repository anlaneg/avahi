#ifndef foodnshfoo
#define foodnshfoo

/***
  This file is part of avahi.

  avahi is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of the
  License, or (at your option) any later version.

  avahi is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General
  Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with avahi; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
  USA.
***/

#include "rr.h"
#include "hashmap.h"

#define AVAHI_DNS_PACKET_HEADER_SIZE 12
#define AVAHI_DNS_PACKET_EXTRA_SIZE 48
#define AVAHI_DNS_LABELS_MAX 127
#define AVAHI_DNS_RDATA_MAX 0xFFFF
#define AVAHI_DNS_PACKET_SIZE_MAX (AVAHI_DNS_PACKET_HEADER_SIZE + 256 + 2 + 2 + 4 + 2 + AVAHI_DNS_RDATA_MAX)

typedef struct AvahiDnsPacket {
    size_t size/*报文长度*/, rindex/*指出读指针（解析器）位置点*/, max_size, res_size;
    AvahiHashmap *name_table; /* for name compression */
    uint8_t *data;
} AvahiDnsPacket;

#define AVAHI_DNS_PACKET_DATA(p) ((p)->data ? (p)->data : ((uint8_t*) p) + sizeof(AvahiDnsPacket))

AvahiDnsPacket* avahi_dns_packet_new(unsigned mtu);
AvahiDnsPacket* avahi_dns_packet_new_query(unsigned mtu);
AvahiDnsPacket* avahi_dns_packet_new_response(unsigned mtu, int aa);

AvahiDnsPacket* avahi_dns_packet_new_reply(AvahiDnsPacket* p, unsigned mtu, int copy_queries, int aa);

void avahi_dns_packet_free(AvahiDnsPacket *p);
void avahi_dns_packet_set_field(AvahiDnsPacket *p, unsigned idx, uint16_t v);
uint16_t avahi_dns_packet_get_field(AvahiDnsPacket *p, unsigned idx);
void avahi_dns_packet_inc_field(AvahiDnsPacket *p, unsigned idx);

uint8_t *avahi_dns_packet_extend(AvahiDnsPacket *p, size_t l);

void avahi_dns_packet_cleanup_name_table(AvahiDnsPacket *p);

uint8_t *avahi_dns_packet_append_uint16(AvahiDnsPacket *p, uint16_t v);
uint8_t *avahi_dns_packet_append_uint32(AvahiDnsPacket *p, uint32_t v);
uint8_t *avahi_dns_packet_append_name(AvahiDnsPacket *p, const char *name);
uint8_t *avahi_dns_packet_append_bytes(AvahiDnsPacket  *p, const void *d, size_t l);
uint8_t* avahi_dns_packet_append_key(AvahiDnsPacket *p, AvahiKey *k, int unicast_response);
uint8_t* avahi_dns_packet_append_record(AvahiDnsPacket *p, AvahiRecord *r, int cache_flush, unsigned max_ttl);
uint8_t* avahi_dns_packet_append_string(AvahiDnsPacket *p, const char *s);

int avahi_dns_packet_is_query(AvahiDnsPacket *p);
int avahi_dns_packet_check_valid(AvahiDnsPacket *p);
int avahi_dns_packet_check_valid_multicast(AvahiDnsPacket *p);

int avahi_dns_packet_consume_uint16(AvahiDnsPacket *p, uint16_t *ret_v);
int avahi_dns_packet_consume_uint32(AvahiDnsPacket *p, uint32_t *ret_v);
int avahi_dns_packet_consume_name(AvahiDnsPacket *p, char *ret_name, size_t l);
int avahi_dns_packet_consume_bytes(AvahiDnsPacket *p, void* ret_data, size_t l);
AvahiKey* avahi_dns_packet_consume_key(AvahiDnsPacket *p, int *ret_unicast_response);
AvahiRecord* avahi_dns_packet_consume_record(AvahiDnsPacket *p, int *ret_cache_flush);
int avahi_dns_packet_consume_string(AvahiDnsPacket *p, char *ret_string, size_t l);

const void* avahi_dns_packet_get_rptr(AvahiDnsPacket *p);

int avahi_dns_packet_skip(AvahiDnsPacket *p, size_t length);

int avahi_dns_packet_is_empty(AvahiDnsPacket *p);
size_t avahi_dns_packet_space(AvahiDnsPacket *p);
size_t avahi_dns_packet_reserve_size(AvahiDnsPacket *p, size_t res_size);
size_t avahi_dns_packet_reserved_space(AvahiDnsPacket *p);

/**
 * dns报文header是固定的12字节格式如下示，：
 * struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;//number of entries in the question section
    uint16_t ancount;//number of resource records in the answer section
    uint16_t nscount;//number of name server resource records in the authority records section
    uint16_t arcount;//number of resource records in the additional records section
   } __attribute__ ((packed));
   其中flags字段定义为AVAHI_DNS_FLAG*字段解释

   在header后面，会有4个可变字段，分别为
   1。 question
   2。 answer
   3.  authoritative nameservers
   4.  addtional records

   对于查询报文，问题(question)数通常是 1，而其他 3 项则均为 0。
   类似地，对于应答报文，回答数至少是 1，剩下的两项可以是 0 或非 0。

   question格式：
   [Question Name:可变长度,Question type:16bits,Question class:16bits]

   查询名(Question Name)是要查找的名字，它是一个或多个标识符的序列。
	每个标识符以首字节的计数值来说明随后标识符的字节长度， 每个名字以最后字节为 0 结束，
	长度为 0 的标识符是根标识符。 计数字节的值必须是 0 ~ 63 的数，因为标识符的最大长度仅为 63
   例如：gemini.tuc.noao.edu
   存储为6gemini3tuc4noao3edu0

   以下定义了header中各字段的偏移量
 */
#define AVAHI_DNS_FIELD_ID 0
#define AVAHI_DNS_FIELD_FLAGS 1
#define AVAHI_DNS_FIELD_QDCOUNT 2
#define AVAHI_DNS_FIELD_ANCOUNT 3
#define AVAHI_DNS_FIELD_NSCOUNT 4
#define AVAHI_DNS_FIELD_ARCOUNT 5

/*第15bit用于表示Question/Response两种情况*/
#define AVAHI_DNS_FLAG_QR (1 << 15)
/*opcode 占4 bit（16-20bit)：通常值为 0（标准查询），其他值为 1（反向查询）和 2（服务器状态请求）*/
#define AVAHI_DNS_FLAG_OPCODE (15 << 11)
#define AVAHI_DNS_FLAG_RCODE (15)
//TC 是 1 bit字段(22bit)，表示 “可截断的(Truncated)”。使用 UDP 时，它表示当应答的总长度超过 512 字节时，只返回前 512 个字节。
#define AVAHI_DNS_FLAG_TC (1 << 9)
//AA 是 1 bit(21bit) 标志，表示 “授权回答(Authoritative Answer)” 。该名字服务器是授权于该域的。
#define AVAHI_DNS_FLAG_AA (1 << 10)

//RD 是 1 bit(23 bit)字段 表示 “期望递归(Recursion Desired)”。 该比特能在一个查询中设置，
//并在响应中返回。 这个标志告诉名字服务器必须处理这个查询，也称为一个递归查询。
//如果该位为 0，且被请求的名字服务器没有一个授权回答，它就返回一个能解答该查询的其他名字服务器列表，
//这称为迭代查询。 在后面的例子中，我们将看到这两种类型查询的例子。

//RA 是 1 bit(24 bit) 字段，表示 “可用递归(Recursion Available)”。 如果名字服务器支持递归查询，
//则在响应中将该比特设置为 1。 在后面的例子中可看到大多数名字服务器都提供递归查询，除了某些根服务器。

//z 随后的 3 bit(25bit,26bit,27bit) 字段必须为 0。

//rcode(Response Code) 是一个 4 bit(28,29,30,31) 的返回码字段。
//通常的值为 0（没有差错）和 3（名字差错）。 名字差错只能从一个授权名字服务器上返回，
//它表示在查询中指定的域名不存在。
#define AVAHI_DNS_FLAGS(qr/*查询/响应标记*/, opcode/*操作码*/, aa, tc, rd, ra, z/*纯零*/, ad, cd, rcode) \
        (((uint16_t) !!qr << 15) |  \
         ((uint16_t) (opcode & 15) << 11) | \
         ((uint16_t) !!aa << 10) | \
         ((uint16_t) !!tc << 9) | \
         ((uint16_t) !!rd << 8) | \
         ((uint16_t) !!ra << 7) | \
         ((uint16_t) !!ad << 5) | \
         ((uint16_t) !!cd << 4) | \
         ((uint16_t) (rcode & 15)))

#define AVAHI_MDNS_SUFFIX_LOCAL "local"
#define AVAHI_MDNS_SUFFIX_ADDR_IPV4 "254.169.in-addr.arpa"
#define AVAHI_MDNS_SUFFIX_ADDR_IPV6 "0.8.e.f.ip6.arpa"

#endif

