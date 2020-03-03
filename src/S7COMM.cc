#include "S7COMM.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"
#include "Reporter.h"
#include "events.bif.h"

using namespace analyzer::s7comm;

S7COMM_Analyzer::S7COMM_Analyzer(Connection* c): tcp::TCP_ApplicationAnalyzer("S7COMM", c) {
    interp = new binpac::S7COMM::S7COMM_Conn(this);
    had_gap = false;
    }

S7COMM_Analyzer::~S7COMM_Analyzer() {
    delete interp;
    }

void S7COMM_Analyzer::Done() {
    tcp::TCP_ApplicationAnalyzer::Done();
    interp->FlowEOF(true);
    interp->FlowEOF(false);
    }

void S7COMM_Analyzer::EndpointEOF(bool is_orig) {
    tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
    interp->FlowEOF(is_orig);
    }

void S7COMM_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);
    assert(TCP());
    if(TCP()->IsPartial())
        return;
    // If only one side had a content gap, we could still try to
    // deliver data to the other side if the script layer can handle this.
    if(had_gap)
        return;

    try {
        interp->NewData(orig, data, data + len);
        }
    catch(const binpac::Exception& e) {
        ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
        }
    }

void S7COMM_Analyzer::Undelivered(uint64_t seq, int len, bool orig) {
    tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);
    had_gap = true;
    interp->NewGap(orig, len);
    }
