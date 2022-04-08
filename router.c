#include "queue.h"
#include "skel.h"

int main(int argc, char *argv[])
{
	packet m;
	int rc;
	
	struct route_table_entry *rtable;
	int rtable_len;

	rtable = malloc(sizeof(struct route_table_entry) * 100);
	DIE(rtable == NULL, "memory");
	rtable_len = read_rtable( "rtable0.txt" , sizeof(struct route_table_entry));

	queue q = queue_create();


	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		struct ether_header *eth_hdr = (struct ether_header *) m.payload;

		if (ntohs(eth_hdr->ether_type) != ETHERTYPE_IP) {
			continue;
		}


		
	// 	if(m.interface == get_interface_mac(m.interface,))
	// }

	//primeste pachetul si ia header ul de ethernet din el

}


