# Packet processing capabilities for C++

## Usage

Example of procession packets read from a pcap file

```c
struct workflow
{
	pcap_t* handle;
	int datalink;
	bool (*decode)(const std::shared_ptr<pkt::thread_vars>& tv,
		const std::shared_ptr<pkt::packet>& p,
		const std::uint8_t* pkt, const int& len,
		const std::shared_ptr<pkt::packet_queue>& pq);
	std::shared_ptr<pkt::thread_vars> tv;
	std::shared_ptr<pkt::packet_queue> pq;
};

static void packet_handler(u_char* user,
	const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	workflow* wf = (workflow *)user;

	std::shared_ptr<pkt::packet> p(pkt::packet::of(packet, pkthdr->caplen));

	pkt::decode::update_packet_counters(wf->tv, p);

	bool err = wf->decode(wf->tv, p, p->pkt.data(), p->pkt.size(), wf->pq);
}

static bool process_pcap_file(const char* filenm)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	workflow wf;

	wf.handle = pcap_open_offline(filenm, errbuf);
	if (wf.handle == NULL)
		return false;

	wf.datalink = pcap_datalink(wf.handle);
	switch (wf.datalink) {
	case LINKTYPE_LINUX_SLL:
		wf.decode = pkt::sll::decode;
		break;
	case LINKTYPE_ETHERNET:
		wf.decode = pkt::ethernet::decode;
		break;
	case LINKTYPE_PPP:
		wf.decode = pkt::ppp::decode;
		break;
	case LINKTYPE_RAW:
	case LINKTYPE_RAW2:
		wf.decode = pkt::raw::decode;
		break;
	case LINKTYPE_NULL:
		wf.decode = pkt::null::decode;
		break;
	}

	wf.tv = pkt::thread_vars::create();
	wf.pq = pkt::packet_queue::create();

	if (pcap_loop(wf.handle, 0, packet_handler, (u_char*)&wf) < 0)
		return false;

	for (int i = 0; i < pkt::counter_max; ++i)
		printf("%s: %lld\n", wf.tv->cc.name(i).c_str(), wf.tv->cc.get(i));

	return true;
}
```