#pragma once

#include <zeek/analyzer/Analyzer.h>

#include "asn1c/Context-list.h"
#include "asn1c/User-data.h"
 
using namespace zeek;

namespace zeek::plugin::pres {
   
    class PRES_Analyzer : public zeek::analyzer::Analyzer {
        public:
            explicit PRES_Analyzer(Connection* conn);
            void DeliverPacket(int len, const u_char* data, bool is_orig,
                uint64_t seq = -1, const IP_Hdr* ip = nullptr, int caplen = 0) override;

            static Analyzer* Instantiate(Connection* conn) { return new PRES_Analyzer(conn); }

        private:
            template <typename CTYPE, typename DESCTYPE>
            IntrusivePtr<Val> parse(
                int len, const u_char *data,
                DESCTYPE *desc,
                IntrusivePtr<Val> (*process)(const CTYPE*)
            );

            void parse_context_list(IntrusivePtr<RecordVal>);
            void forward(IntrusivePtr<RecordVal>, bool);
            
    };

} // namespace zeek::plugin::pres 
