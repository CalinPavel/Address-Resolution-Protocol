#include "queue.h"
#include "skel.h"

int interfaces[ROUTER_NUM_INTERFACES];

// tabela de rutare
struct route_table_entry *rtable;
int rtable_len;

// Arp table
struct arp_entry *arp_table;
int arp_table_len;


struct route_table_entry *get_best(uint32_t dest_ip)
{
	struct route_table_entry *best_match = NULL;

	for (int i = 0; i < rtable_len; i++)
	{
		if ((rtable[i].mask & dest_ip) == rtable[i].prefix)
		{
			if (best_match == NULL)
				best_match = &rtable[i];
			else if (ntohl(best_match->mask) < ntohl(rtable[i].mask))
				best_match = &rtable[i];
		}
	}
	return best_match;
}

struct arp_entry *get_arp_entry(uint32_t dest_ip)
{
	for (int i = 0; i < arp_table_len; i++)
	{
		if (arp_table[i].ip == dest_ip)
			return &arp_table[i];
	}

	return NULL;
}

int main(int argc, char *argv[])
{
	// setvbuf(stdout, NULL, _IONBF, 0);

	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");

	// coada
	// queue q = queue_create();

	arp_table = malloc(sizeof(struct arp_entry) * 50000);
	DIE(arp_table == NULL, "memory");

	// len
	rtable_len = read_rtable("rtable0.txt", rtable);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);
	

	while (1)
	{
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;

		// if (ntohs(eth_hdr->ether_type) != ETHERTYPE_ARP)
		// {

		// 	struct arp_header *arp_hdr = (struct arp_header *)(m.payload + sizeof(struct ether_header));

		// 	//request
		// 	if (arp_hdr->op == 1)
		// 	{
		// 		for (int i = 0; i <= arp_table_len - 1; i++)
		// 		{
		// 			if (arp_hdr->tpa == arp_table[i].ip)
		// 			{
		// 				memcpy(eth_hdr->ether_dhost, arp_table[i].mac, sizeof(arp_table[i].mac));
		// 				send_packet(&m);
		// 			}
		// 			else
		// 			{
		// 				// queue_enq(q,&m);
		// 				// packet new;
		// 				// struct arp_header *arp_new = (struct arp_header *)(new.payload + sizeof(struct ether_header));
		// 				memcpy(eth_hdr->ether_dhost, arp_table[i].mac, sizeof(arp_table[i].mac));
		// 				send_packet(&m);
		// 				// memcpy(eth_hdr->ether_dhost, "ff:ff:ff:ff:ff:ff" , sizeof(arp_hdr->tha));
		// 				// memcpy(eth_hdr->ether_shost , arp_hdr->sha , sizeof(arp_hdr->sha));
		// 				// memcpy(eth_hdr->ether_type , ETHERTYPE_ARP , sizeof(arp_hdr->htype));
		// 				// send_packet(&new);
		// 			}
		// 		}
		// 	}

		// if(arp_hdr->op == 2){
		// 	//arp_hdr.sha adresa mac primita
		// }
		// }

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
		{
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

			// if (ip_checksum(ip_hdr, sizeof(struct iphdr)))
			// {
			// 	fprintf(stderr, "Checksum gresit");
			// 	continue;
			// }

			// struct in_addr daddr;
			// daddr.s_addr = ip_hdr->daddr;

			struct route_table_entry *best_match = get_best(ip_hdr->daddr);

			if (!best_match)
				continue;

			// struct in_addr best;
			// best.s_addr= best_match->next_hop;

			struct arp_entry *arp_e = get_arp_entry(best_match->next_hop);

			memcpy(eth_hdr->ether_dhost, arp_e->mac, 6);
			get_interface_mac( best_match->interface,eth_hdr->ether_shost);
			m.interface = best_match->interface;
			send_packet(&m);

			// 	struct icmp *icmp_header = (struct icmp *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

			// 	// if (icmp_header->icmp_type == ICMP_ECHO)
			// 	// {
			// 		// memcpy(eth_hdr->ether_dhost , ip_hdr->saddr , sizeof(eth_hdr->ether_dhost ));
			// 		// memcpy(eth_hdr->ether_shost , ip_hdr->daddr, sizeof(eth_hdr->ether_shost ));
			// 		icmp_header->icmp_type = ICMP_ECHOREPLY;

			// 		send_packet(&m);
		}
	}
}
