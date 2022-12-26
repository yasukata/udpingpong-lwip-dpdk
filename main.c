/*
 *
 * Copyright 2022 Kenichi Yasukata
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#include <arpa/inet.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_bus_pci.h>

/* workaround to avoid conflicts between dpdk and lwip definitions */
#undef IP_DF
#undef IP_MF
#undef IP_RF
#undef IP_OFFMASK

#include <lwip/opt.h>
#include <lwip/init.h>
#include <lwip/pbuf.h>
#include <lwip/netif.h>
#include <lwip/etharp.h>
#include <lwip/udp.h>
#include <lwip/timeouts.h>

#include <netif/ethernet.h>

#define MAX_PKT_BURST (128)
#define NUM_SLOT (1024)

#define MEMPOOL_CACHE_SIZE (256)

#define PACKET_BUF_SIZE (1518)

static struct rte_mempool *pktmbuf_pool = NULL;
static int tx_idx = 0;
static struct rte_mbuf *tx_mbufs[MAX_PKT_BURST] = { 0 };

#define MAX_QUEUE_DEPTH (4096)
static bool is_client = false;
static unsigned long counter[MAX_QUEUE_DEPTH] = { 0 };
static int init_state = 0;

static void tx_flush(void)
{
	int xmit = tx_idx, xmitted = 0;
	while (xmitted != xmit)
		xmitted += rte_eth_tx_burst(0 /* port id */, 0 /* queue id */, &tx_mbufs[xmitted], xmit - xmitted);
	tx_idx = 0;
}

static err_t low_level_output(struct netif *netif __attribute__((unused)), struct pbuf *p)
{
	char buf[PACKET_BUF_SIZE];
	void *bufptr, *largebuf = NULL;
	if (sizeof(buf) < p->tot_len) {
		largebuf = (char *) malloc(p->tot_len);
		assert(largebuf);
		bufptr = largebuf;
	} else
		bufptr = buf;

	pbuf_copy_partial(p, bufptr, p->tot_len, 0);

	assert((tx_mbufs[tx_idx] = rte_pktmbuf_alloc(pktmbuf_pool)) != NULL);
	assert(p->tot_len <= RTE_MBUF_DEFAULT_BUF_SIZE);
	rte_memcpy(rte_pktmbuf_mtod(tx_mbufs[tx_idx], void *), bufptr, p->tot_len);
	rte_pktmbuf_pkt_len(tx_mbufs[tx_idx]) = rte_pktmbuf_data_len(tx_mbufs[tx_idx]) = p->tot_len;
	if (++tx_idx == MAX_PKT_BURST)
		tx_flush();

	if (largebuf)
		free(largebuf);
	return ERR_OK;
}

static void udp_recv_handler(void *arg __attribute__((unused)),
			     struct udp_pcb *upcb,
			     struct pbuf *p, const ip_addr_t *addr,
			     u16_t port)
{
	int i;
	assert(p->len >= sizeof(int));
	i = *((int *) p->payload); // lazy access
	assert(i <= MAX_QUEUE_DEPTH);
	if (is_client) {
		if (i < MAX_QUEUE_DEPTH) {
			counter[i]++;
			assert(udp_sendto(upcb, p, addr, port) == ERR_OK);
		} else
			init_state = 1;
	} else
		assert(udp_sendto(upcb, p, addr, port) == ERR_OK);
	pbuf_free(p);
}

static uint8_t _mac[6];
static uint16_t _mtu;

static err_t if_init(struct netif *netif)
{
	for (int i = 0; i < 6; i++)
		netif->hwaddr[i] = _mac[i];
	netif->mtu = _mtu;
	netif->output = etharp_output;
	netif->linkoutput = low_level_output;
	netif->hwaddr_len = 6;
	netif->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_IGMP;
	return ERR_OK;
}

int main(int argc, char* const* argv)
{
	struct netif _netif = { 0 };
	ip4_addr_t _addr, _mask, _gate, _remote_addr;
	size_t additional_payload_len = 0;
	int queue_depth = 1;
	int server_port = 10000;

	/* setting up dpdk */
	{
		int ret;
		uint16_t nb_rxd = NUM_SLOT;
		uint16_t nb_txd = NUM_SLOT;

		assert((ret = rte_eal_init(argc, (char **) argv)) >= 0);
		argc -= ret;
		argv += ret;

		assert(rte_eth_dev_count_avail() == 1);

		assert((pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
					RTE_MAX(1 /* nb_ports */ * (nb_rxd + nb_txd + MAX_PKT_BURST + 1 * MEMPOOL_CACHE_SIZE), 8192),
					MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
					rte_socket_id())) != NULL);

		{
			struct rte_eth_dev_info dev_info;
			struct rte_eth_conf local_port_conf = { 0 };

			assert(rte_eth_dev_info_get(0 /* port id */, &dev_info) >= 0);

			assert(rte_eth_dev_configure(0 /* port id */, 1 /* num queues */, 1 /* num queues */, &local_port_conf) >= 0);

			assert(rte_eth_dev_adjust_nb_rx_tx_desc(0 /* port id */, &nb_rxd, &nb_txd) >= 0);

			{
				struct rte_ether_addr ports_eth_addr;
				assert(rte_eth_macaddr_get(0 /* port id */, &ports_eth_addr) >= 0);
				for (int i = 0; i < 6; i++)
					_mac[i] = ports_eth_addr.addr_bytes[i];
			}

			assert(rte_eth_dev_get_mtu(0 /* port id */, &_mtu) >= 0);
			assert(_mtu <= PACKET_BUF_SIZE);

			assert(rte_eth_rx_queue_setup(0 /* port id */, 0 /* queue */, nb_rxd,
						rte_eth_dev_socket_id(0 /* port id */),
						&dev_info.default_rxconf,
						pktmbuf_pool) >= 0);

			assert(rte_eth_tx_queue_setup(0 /* port id */, 0 /* queue */, nb_txd,
						rte_eth_dev_socket_id(0 /* port id */),
						&dev_info.default_txconf) >= 0);

			assert(rte_eth_dev_start(0 /* port id */) >= 0);
			assert(rte_eth_promiscuous_enable(0 /* port id */) >= 0);
		}
	}

	/* parse other arg */
	{
		int ch;
		bool _a = false, _g = false, _m = false;
		while ((ch = getopt(argc, argv, "a:g:l:m:p:q:s:")) != -1) {
			switch (ch) {
			case 'a':
				inet_pton(AF_INET, optarg, &_addr);
				_a = true;
				break;
			case 'g':
				inet_pton(AF_INET, optarg, &_gate);
				_g = true;
				break;
			case 'm':
				inet_pton(AF_INET, optarg, &_mask);
				_m = true;
				break;
			case 'l':
				additional_payload_len = atol(optarg);
				break;
			case 'p':
				server_port = atoi(optarg);
				break;
			case 'q':
				queue_depth = atoi(optarg);
				assert(queue_depth < MAX_QUEUE_DEPTH);
				break;
			case 's':
				inet_pton(AF_INET, optarg, &_remote_addr);
				is_client = true;
				break;
			default:
				assert(0);
				break;
			}
		}
		assert(_a && _g && _m);
	}

	/* setting up lwip */
	{
		lwip_init();
		udp_init();
		assert(netif_add(&_netif, &_addr, &_mask, &_gate, NULL, if_init, ethernet_input) != NULL);
		netif_set_default(&_netif);
		netif_set_link_up(&_netif);
		netif_set_up(&_netif);
	}

	/* main procedure */
	{
		struct timespec _t;
		struct udp_pcb *upcb;
			sys_check_timeouts();
		assert((upcb = udp_new()) != NULL);
		udp_recv(upcb, udp_recv_handler, NULL);
		if (is_client) {
			struct pbuf *p;
			assert((p = pbuf_alloc(PBUF_TRANSPORT, sizeof(int) + additional_payload_len, PBUF_RAM)) != NULL);
			*((int *) p->payload) = MAX_QUEUE_DEPTH;
			assert(udp_sendto(upcb, p, &_remote_addr, server_port) == ERR_OK);
			pbuf_free(p);
		} else
			assert(udp_bind(upcb, IP_ADDR_ANY, server_port) == ERR_OK);

		printf("-- pid %d : application (%s) has started --\n",
				getpid(),
				is_client ? "client" : "server");

		assert(!clock_gettime(CLOCK_REALTIME, &_t));

		/* primary loop */
		while (1) {
			struct rte_mbuf *rx_mbufs[MAX_PKT_BURST];
			unsigned short i, nb_rx = rte_eth_rx_burst(0 /* port id */, 0 /* queue id */, rx_mbufs, MAX_PKT_BURST);
			for (i = 0; i < nb_rx; i++) {
				{
					struct pbuf *p;
					assert((p = pbuf_alloc(PBUF_RAW, rte_pktmbuf_pkt_len(rx_mbufs[i]), PBUF_POOL)) != NULL);
					pbuf_take(p, rte_pktmbuf_mtod(rx_mbufs[i], void *), rte_pktmbuf_pkt_len(rx_mbufs[i]));
					p->len = p->tot_len = rte_pktmbuf_pkt_len(rx_mbufs[i]);
					assert(_netif.input(p, &_netif) == ERR_OK);
				}
				rte_pktmbuf_free(rx_mbufs[i]);
			}
			tx_flush();
			sys_check_timeouts();
			if (is_client) {
				if (init_state == 1) {
					int j;
					printf("transmit %d packets (payload len %lu + sizeof(int) %lu)\n", queue_depth, additional_payload_len, sizeof(int));
					for (j = 0; j < queue_depth; j++) {
						struct pbuf *p;
						assert((p = pbuf_alloc(PBUF_TRANSPORT, sizeof(int) + additional_payload_len, PBUF_RAM)) != NULL);
						*((int *) p->payload) = j;
						memset((void *)((uintptr_t) p->payload + sizeof(int)), 'A', additional_payload_len);
						p->len = sizeof(int) + additional_payload_len;
						assert(udp_sendto(upcb, p, &_remote_addr, server_port) == ERR_OK);
						pbuf_free(p);
					}
					init_state = 2;
				}
				{
					struct timespec __t;
					assert(!clock_gettime(CLOCK_REALTIME, &__t));
					if ((_t.tv_sec * 1000000000UL + _t.tv_nsec) + 1000000000UL
							< (__t.tv_sec * 1000000000UL + __t.tv_nsec)) {
						int j;
						unsigned long total = 0;
						for (j = 0; j < queue_depth; j++) {
							printf("[%d]: %lu\n", j, counter[j]);
							total += counter[j];
						}
						printf("total: %lu\n\n", total);
						memset(counter, 0, sizeof(counter[0]) * queue_depth);
						_t = __t;
					}
				}
			}
		}
	}

	return 0;
}
