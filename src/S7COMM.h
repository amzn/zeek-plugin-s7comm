#ifndef ANALYZER_PROTOCOL_S7COMM_H
#define ANALYZER_PROTOCOL_S7COMM_H

#include "analyzer/protocol/tcp/TCP.h"
#include "s7comm_pac.h"

namespace analyzer { 
    namespace s7comm {
        class S7COMM_Analyzer : public tcp::TCP_ApplicationAnalyzer {
            public:
                S7COMM_Analyzer(Connection* conn);
                virtual ~S7COMM_Analyzer();

                virtual void Done();
                virtual void DeliverStream(int len, const u_char* data, bool orig);
                virtual void Undelivered(uint64_t seq, int len, bool orig);

                virtual void EndpointEOF(bool is_orig);

                static analyzer::Analyzer* Instantiate(Connection* conn) { 
                    return new S7COMM_Analyzer(conn);
                    }

            protected:
                binpac::S7COMM::S7COMM_Conn* interp;
                bool had_gap;
            };
        } 
    }

#endif
