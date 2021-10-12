#ifndef ANALYZER_PROTOCOL_S7COMM_H
#define ANALYZER_PROTOCOL_S7COMM_H

#include <zeek/analyzer/protocol/tcp/TCP.h>
#include "s7comm_pac.h"

namespace analyzer {
    namespace s7comm {
        class S7comm_Analyzer : public zeek::analyzer::tcp::TCP_ApplicationAnalyzer {
            public:
                S7comm_Analyzer(zeek::Connection* conn);
                virtual ~S7comm_Analyzer();

                virtual void Done();
                virtual void DeliverStream(int len, const u_char* data, bool orig);
                virtual void Undelivered(uint64_t seq, int len, bool orig);

                virtual void EndpointEOF(bool is_orig);

                static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn) {
                    return new S7comm_Analyzer(conn);
                    }

            protected:
                binpac::S7comm::S7comm_Conn* interp;
                bool had_gap;
            };
        }
    }

#endif
