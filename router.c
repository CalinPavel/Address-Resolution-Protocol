#include "queue.h"
#include "skel.h"

int interfaces[ROUTER_NUM_INTERFACES];

#define ARP_CACHE_SIZE 8
// tabela de rutare
struct route_table_entry *rtable;
int rtable_len;

// Arp table
struct arp_entry *arp_table;
int arp_table_len;

struct arp_entry arp_array[ARP_CACHE_SIZE];
int cache_index = 0;

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
	// printf("Se cauta in cache:\n");
	for (int i = 0; i < ARP_CACHE_SIZE; i++)
	{
		// printf("Ip-ul cautat: ");
		//	printf("%d\n", dest_ip);
		// printf("Ip-ul din cache: ");
		// printf("%d\n", arp_array[i].ip);
		if (arp_array[i].ip == dest_ip)
			return &arp_array[i];
	}
	return NULL;
}

// struct arp_entry *get_arp_entry(uint32_t dest_ip)
// {
// 	// printf("Se cauta in cache:\n");
// 	for (int i = 0; i < ARP_CACHE_SIZE; i++)
// 	{
// 		// printf("%d\n", arp_table[i].ip);
// 		if (arp_table[i].ip == dest_ip)
// 			return &arp_table[i];
// 	}
// 	return NULL;
// }

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);

	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");

	// coada
	queue q = queue_create();

	// arp_table = malloc(sizeof(struct arp_entry) * 50000);
	// DIE(arp_table == NULL, "memory");

	// len
	rtable_len = read_rtable(argv[1], rtable);
	// arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	while (1)
	{
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
		{

			struct arp_header *arp_hdr = (struct arp_header *)(m.payload + sizeof(struct ether_header));

			// request
			if (arp_hdr->op == 512)
			{
				printf("A venit reply avem de trimis din coada!");

				arp_array[cache_index].ip = arp_hdr->spa;
				memcpy(arp_array[cache_index].mac, arp_hdr->sha, sizeof(arp_array[cache_index].mac));

				if (!queue_empty(q))
				{
					packet *redirect = queue_deq(q);

					struct ether_header *eth_hdr_redirect = (struct ether_header *)(redirect->payload);
					printf("hereeee");
					printf("%hhu abcd", eth_hdr_redirect->ether_dhost);

					struct iphdr *ip_hdr_redirect = (struct iphdr *)(redirect->payload + sizeof(struct ether_header));
					printf("%d" , ip_hdr_redirect->daddr);
					printf("-------------\n");
					struct route_table_entry *best_match1 = get_best(ip_hdr_redirect->daddr);
					printf("%d" ,best_match1);
					struct arp_entry *arp_e = get_arp_entry(best_match1->next_hop);

					memcpy(eth_hdr_redirect->ether_dhost, arp_e->mac ,sizeof(eth_hdr_redirect->ether_dhost));
					// Adresa sursa <-> destinatia primita
					// memcpy(eth_hdr_redirect->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr_redirect->ether_shost));

					get_interface_mac(best_match1->interface ,eth_hdr_redirect->ether_shost );

					redirect->interface = best_match1->interface;

					// struct icmphdr *icmp_hdr_redirect = (struct icmphdr *)((&redirect->payload) + sizeof(struct ether_header) + sizeof(struct iphdr));
					send_packet(redirect);
					printf("s a trimis!");
					continue;
				}

				// printf("I got here1!");

				// memcpy(eth_hdr_redirect->ether_dhost, arp_array[cache_index-1].mac, 6);
				// struct route_table_entry *best_match = get_best(ip_hdr_redirect->daddr);

				// printf("I got here2!");
				// 			// // printf("here");
				// 			//  printf("%hhn" , eth_hdr_redirect->ether_dhost);
				// 			  get_interface_mac(best_match->interface, eth_hdr_redirect->ether_shost);
				// 			  redirect->interface = best_match->interface;
				// 				memcpy(eth_hdr_redirect->ether_dhost, eth_hdr->ether_shost ,sizeof(eth_hdr->ether_dhost));
				// // 			// 	// send_packet(&m);
				//

				// send_packet(&m);
				// printf("A plecat packetul!");
			}
			// reply
			if (arp_hdr->op == 256) // == > request
			{
				// adresa router
				// queue_enq(q, &m);

				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));
				get_interface_mac(m.interface, eth_hdr->ether_shost);

				memcpy(arp_hdr->sha, eth_hdr->ether_shost, sizeof(eth_hdr->ether_dhost));

				arp_hdr->op = htons(ARPOP_REPLY);
				memcpy(arp_hdr->tha, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));

				uint32_t addr = arp_hdr->tpa;
				arp_hdr->tpa = arp_hdr->spa;
				arp_hdr->spa = addr;

				send_packet(&m);
			}
		}

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
		{
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

			// echo
			int check = 0;
			struct icmphdr *icmp_hdr_new_1 = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
			if (icmp_hdr_new_1->type == ICMP_ECHO)
			{

				for (int i = 0; i < ROUTER_NUM_INTERFACES; i++)
				{
					uint32_t temp;
					inet_pton(AF_INET, get_interface_ip(i), &temp);
					if (temp == ip_hdr->daddr)
					{
						packet new;

						// build header
						struct ether_header *eth_hdr_new = (struct ether_header *)(new.payload);
						// Adresa destinatie <-> sursa primita
						memcpy(eth_hdr_new->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr_new->ether_dhost));
						// Adresa sursa <-> destinatia primita
						memcpy(eth_hdr_new->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr_new->ether_shost));
						// Type header-ul
						eth_hdr_new->ether_type = htons(ETHERTYPE_IP);

						// build ip1
						struct iphdr *ip_hdr_new_1 = (struct iphdr *)(new.payload + sizeof(struct ether_header));
						ip_hdr_new_1->version = 4;
						ip_hdr_new_1->ihl = 5;
						ip_hdr_new_1->tos = 0;
						ip_hdr_new_1->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 64);
						ip_hdr_new_1->frag_off = 0;
						ip_hdr_new_1->ttl = 64;
						ip_hdr_new_1->protocol = IPPROTO_ICMP;

						uint32_t addr = ip_hdr->saddr;
						ip_hdr_new_1->saddr = ip_hdr->daddr;
						ip_hdr_new_1->daddr = addr;

						ip_hdr_new_1->check = 0;
						ip_hdr_new_1->check = ip_checksum((void *)ip_hdr_new_1, sizeof(struct iphdr));

						// build icmp1
						struct icmphdr *icmp_hdr_new_1 = (struct icmphdr *)(new.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
						icmp_hdr_new_1->code = 0;
						icmp_hdr_new_1->type = ICMP_ECHOREPLY;

						// icmp_hdr_new_1->hun.ih_idseq.icd_id = htons(getpid());
						icmp_hdr_new_1->checksum = 0;
						icmp_hdr_new_1->checksum = icmp_checksum((void *)icmp_hdr_new_1, sizeof(struct icmphdr));

						// build ip original
						struct iphdr *ip_hdr_new_2 = (struct iphdr *)(new.payload + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
						ip_hdr_new_2->version = 4;
						ip_hdr_new_2->ihl = 5;
						ip_hdr_new_2->tos = 0;
						ip_hdr_new_2->tot_len = ip_hdr->tot_len;
						ip_hdr_new_2->frag_off = 0;
						ip_hdr_new_2->ttl = 1;
						ip_hdr_new_2->protocol = IPPROTO_ICMP;

						uint32_t addr1 = ip_hdr->daddr;
						ip_hdr_new_2->saddr = ip_hdr->saddr;
						ip_hdr_new_2->daddr = addr1;

						ip_hdr_new_2->check = 0;
						ip_hdr_new_2->check = ip_hdr->check;

						// build original icmp
						struct icmphdr *icmp_hdr_new_2 = (struct icmphdr *)(new.payload + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr));
						icmp_hdr_new_2->code = 0;
						icmp_hdr_new_2->type = 0;

						// icmp_hdr_new_2->icmp_hun.ih_idseq.icd_id = htons(getpid());
						icmp_hdr_new_2->checksum = 0;
						icmp_hdr_new_2->checksum = icmp_checksum((void *)icmp_hdr_new_2, sizeof(struct icmphdr));

						// interfata
						new.interface = m.interface;
						new.len = m.len + 64;
						// trimite packet
						send_packet(&new);
						check = 1;
						continue;
					}
				}
			}

			if (check == 1)
			{
				continue;
			}

			if (ip_checksum((void *)ip_hdr, sizeof(struct iphdr)) != 0)
				continue;

			// timer
			if (ip_hdr->ttl <= 1)
			{
				// build packet
				packet new;

				// build header
				struct ether_header *eth_hdr_new = (struct ether_header *)(new.payload);
				// Adresa destinatie <-> sursa primita
				memcpy(eth_hdr_new->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr_new->ether_dhost));
				// Adresa sursa <-> destinatia primita
				memcpy(eth_hdr_new->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr_new->ether_shost));
				// Type header-ul
				eth_hdr_new->ether_type = htons(ETHERTYPE_IP);

				// build ip1
				struct iphdr *ip_hdr_new_1 = (struct iphdr *)(new.payload + sizeof(struct ether_header));
				ip_hdr_new_1->version = 4;
				ip_hdr_new_1->ihl = 5;
				ip_hdr_new_1->tos = 0;
				ip_hdr_new_1->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 64);
				ip_hdr_new_1->frag_off = 0;
				ip_hdr_new_1->ttl = 64;
				ip_hdr_new_1->protocol = IPPROTO_ICMP;

				uint32_t addr = ip_hdr->saddr;
				ip_hdr_new_1->saddr = ip_hdr->daddr;
				ip_hdr_new_1->daddr = addr;

				ip_hdr_new_1->check = 0;
				ip_hdr_new_1->check = ip_checksum((void *)ip_hdr_new_1, sizeof(struct iphdr));

				// build icmp1
				struct icmphdr *icmp_hdr_new_1 = (struct icmphdr *)(new.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
				icmp_hdr_new_1->code = 0;
				icmp_hdr_new_1->type = 11;

				// icmp_hdr_new_1->hun.ih_idseq.icd_id = htons(getpid());
				icmp_hdr_new_1->checksum = 0;
				icmp_hdr_new_1->checksum = icmp_checksum((void *)icmp_hdr_new_1, sizeof(struct icmphdr));

				// build ip original
				struct iphdr *ip_hdr_new_2 = (struct iphdr *)(new.payload + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
				ip_hdr_new_2->version = 4;
				ip_hdr_new_2->ihl = 5;
				ip_hdr_new_2->tos = 0;
				ip_hdr_new_2->tot_len = ip_hdr->tot_len;
				ip_hdr_new_2->frag_off = 0;
				ip_hdr_new_2->ttl = 1;
				ip_hdr_new_2->protocol = IPPROTO_ICMP;

				uint32_t addr1 = ip_hdr->daddr;
				ip_hdr_new_2->saddr = ip_hdr->saddr;
				ip_hdr_new_2->daddr = addr1;

				ip_hdr_new_2->check = 0;
				ip_hdr_new_2->check = ip_hdr->check;

				// build original icmp
				struct icmphdr *icmp_hdr_new_2 = (struct icmphdr *)(new.payload + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr));
				icmp_hdr_new_2->code = 0;
				icmp_hdr_new_2->type = 8;

				// icmp_hdr_new_2->icmp_hun.ih_idseq.icd_id = htons(getpid());
				icmp_hdr_new_2->checksum = 0;
				icmp_hdr_new_2->checksum = icmp_checksum((void *)icmp_hdr_new_2, sizeof(struct icmphdr));

				// interfata
				new.interface = m.interface;
				new.len = m.len + 64;
				// trimite packet
				send_packet(&new);
				continue;
			}

			struct route_table_entry *best_match = get_best(ip_hdr->daddr);

			if (!best_match)
				continue;

			struct arp_entry *arp_e = get_arp_entry(best_match->next_hop);

			if (arp_e == NULL)
			{
				// printf("host unreachable!");

				packet *queue1;
				queue1 = (packet *)malloc(sizeof(packet));
				memcpy(queue1, &m, sizeof(packet));

				queue_enq(q, queue1);
				// build arp request
				packet new;
				// build header
				struct ether_header *eth_hdr_new = (struct ether_header *)(new.payload);
				// Adresa destinatie <-> sursa primita
				// memcpy(eth_hdr_new->ether_shost, eth_hdr->ether_dhost, sizeof(eth_hdr_new->ether_dhost));
				get_interface_mac(best_match->interface, eth_hdr_new->ether_shost);
				// Adresa sursa <-> destinatia primita
				memset(eth_hdr_new->ether_dhost, 1, sizeof(eth_hdr_new->ether_dhost));
				// Type header-ul
				eth_hdr_new->ether_type = htons(ETHERTYPE_ARP);

				struct arp_header *arp_hdr_new = (struct arp_header *)(new.payload + sizeof(struct ether_header));

				// Hardware type for ethernet
				arp_hdr_new->htype = htons(1);
				// Protocol type for IP
				arp_hdr_new->ptype = htons(ETH_P_IP);
				// Hardware address length
				arp_hdr_new->hlen = 6;
				// Protocol address length
				arp_hdr_new->plen = 4;
				// OpCode: 1 for ARP request
				arp_hdr_new->op = htons(ARPOP_REQUEST);
				// Adresa mac sursa
				// Adresa mac destinatie , nu o cunoastem
				memset(arp_hdr_new->tha, 0xff, sizeof(arp_hdr_new->tha));
				// Adresa mac sursa
				uint8_t mac;
				get_interface_mac(m.interface, &mac);
				printf("%d", mac);
				memcpy(arp_hdr_new->sha, &mac, sizeof(arp_hdr_new->sha));

				arp_hdr_new->tpa = best_match->next_hop;
				// Adresa ip sursa

				arp_hdr_new->spa = inet_addr(get_interface_ip(m.interface));

				new.interface = m.interface;
				new.len = sizeof(struct ether_header) + sizeof(struct arp_header);
				// trimite packet
				send_packet(&new);
				continue;
			}

			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum((void *)ip_hdr, sizeof(struct iphdr));

			memcpy(eth_hdr->ether_dhost, arp_e->mac, 6);
			get_interface_mac(best_match->interface, eth_hdr->ether_shost);
			m.interface = best_match->interface;

			send_packet(&m);
		}
	}
}
