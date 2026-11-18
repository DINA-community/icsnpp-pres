# @TEST-DOC: A Resynchronize-Ack SPDU (SI 0x22) carrying a CPA-PPDU must not crash Zeek.
# @TEST-EXEC: zeek -C -r ${TRACES}/resync-ack-cpa.pcap ${PACKAGE} %INPUT >output 2>&1
# @TEST-EXEC: test -f pres.log -o -f weird.log

event zeek_init() &priority=5
	{
	Analyzer::register_for_port(Analyzer::ANALYZER_TPKT, 102/tcp);
	}
