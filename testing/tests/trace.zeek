# @TEST-DOC: Test Zeek parsing a trace file through the cotp analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/trace.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff pres.log
#

module pres;

event zeek_init() &priority=5 {
    # the script of tpkt is not loaded even if the tpkt plugin is installed
    Analyzer::register_for_port(Analyzer::ANALYZER_TPKT, 102/tcp);
}

event pres_connect(c: connection, is_orig: bool, ppdu: CP_type) {
  print("Testing pres: connect "+cat(ppdu)+"\n");
}

event pres_refuse(c: connection, is_orig: bool, ppdu: CPR_PPDU) {
  print("Testing pres: refuse "+cat(ppdu)+"\n");
}

event pres_abort(c: connection, is_orig: bool, ppdu: Abort_type) {
  print("Testing pres: abort "+cat(ppdu)+"\n");
}

event pres_typed_data(c: connection, is_orig: bool, ppdu: Typed_data_type) {
  print("Testing pres: typed data "+cat(ppdu)+"\n");
}

event pres_data(c: connection, is_orig: bool, ppdu: CPC_type) {
  print("Testing pres: data "+cat(ppdu)+"\n");
}
