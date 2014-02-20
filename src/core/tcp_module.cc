#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"


using std::cout;
using std::endl;
using std::cerr;
using std::string;

int main(int argc, char *argv[])
{
  MinetHandle mux, sock;

  MinetInit(MINET_TCP_MODULE);

  mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
  sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

  if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
    return -1;
  }

  if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
    MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
    return -1;
  }

  MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

  MinetEvent event;

  while (MinetGetNextEvent(event)==0) {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else {
      //  Data from the IP layer below  //
      if (event.handle==mux) {
      	Packet p;
      	MinetReceive(mux,p);
      	unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
      	cerr << "estimated header len="<<tcphlen<<"\n";
      	p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
      	IPHeader ipl=p.FindHeader(Headers::IPHeader);
      	TCPHeader tcph=p.FindHeader(Headers::TCPHeader);

      	cerr << "TCP Packet: IP Header is "<<ipl<<" and ";
      	cerr << "TCP Header is "<<tcph << " and ";

      	cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");
      	
      }
      //  Data from the Sockets layer above  //
      if (event.handle==sock) {
        SockRequestResponse s;
        MinetReceive(sock,s);
        cerr << "Received Socket Request:" << s << endl;
      }
    }
  }
  return 0;
}

void MuxHandler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist) {

  /* VARIABLES */
  //packet and headers
  Packet p;
  TCPHeader tcph;
  IPHeader iph;
  unsigned tcphlen;
  unsigned iphlen;

  //packet properties
  unsigned short total_len;
  bool checksumok;
  unsigned char flags; //to hold syn, fin, rst, psh flags of packet p
  unsigned int seqnum;


  /* BEGIN */

  //grab packet from ip
  MinetReceive(mux,p);

  //get header length estimates
  unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
  unsigned iphlen=IPHeader::EstimateIPHeaderLength(p);

  //extract headers...
  p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);

  //store headers in tcph and iph
  tcph=p.FindHeader(Headers::TCPHeader);
  iph=p.FindHeader(Headers::IPHeader);

  //check if checksum is correct 
  checksumok=tcph.IsCorrectChecksum(p);

  //CONFUSED
  // //length of headers
  // iph.GetTotalLength(total_len); //total length including ip header
  // seg_len = total_len - iphlen; //segment length including tcp header
  // data_len = seg_len - tcphlen; //actual data length
  // Buffer data = p.GetPayload().ExtractFront(data_len);

  //fill out a blank reference connection object
  Connection c;

  // note that this is flipped around because
  // "source" is interepreted as "this machine"

  //info from iph
  iph.GetDestIP(c.src);
  iph.GetSourceIP(c.dest);
  iph.GetProtocol(c.protocol);

  //info from tcph
  tcph.GetDestPort(c.srcport);
  tcph.GetSourcePort(c.destport);
  tcph.GetFlags(flags);
  tcph.GetSeqNum(seqnum);

  //find ConnectionToStateMapping in list
  ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);

  //fetch state from the ConnectionToStateMapping
  unsigned int state = (*cs).state.GetState()

  if (cs!=clist.end()) {
    
    switch(state) {

      case CLOSED:

        break;

      case LISTEN:
        cout << "listening wheee" << endl;

        //if SYN bit is set
        if(IS_SYN(flags)){

          /*NOTE THAT WE ARE DOING STOP AND WAIT ATM. 
          COMMENTED OUT SET COMMANDS ARE FOR GBN */

          /* MAKE SYNACK PACKET */
          Packet ret_p;

          /* MAKE IP HEADER */
          IPHeader ret_iph;

          ret_iph.SetProtocol(IP_PROTO_TCP);
          ret_iph.SetSourceIP(*cs.connection.src);
          ret_iph.SetDestIP(*cs.connection.dest);
          ret_iph.SetTotalLength(TCP_HEADER_LENGTH+IP_HEADER_BASE_LENGTH);
          // push it onto the packet
          ret_p.PushFrontHeader(ret_iph);

          /*MAKE TCP HEADER*/
          //variables
          TCPHeader ret_tcph;
          unsigned int my_seqnum = 0; //hardcoded atm, should be random
          unsigned char my_flags;

          ret_tcph.SetSourcePort(*cs.srcport, ret_p);
          ret_tcph.SetDestPort(*cs.destport, ret_p);
          ret_tcph.SetSeqNum(my_seqnum, ret_p);
          ret_tcph.SetAckNum(seqnum+1, ret_p); //set to isn+1

          //set flags
          SET_SYN(my_flags);
          ret_tcph.SetFlags(my_flags, ret_p);

          ret_tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, ret_p);
          // ret_tcph.SetWinSize(0, ret_p);
          // ret_tcph.SetUrgentPtr(0, ret_p);
          // ret_tcph.SetOptions(0, ret_p);

          //recompute checksum with headers in
          ret_tcph.RecomputeChecksum(ret_p);

          //make sure ip header is in front
          ret_p.PushBackHeader(ret_tcph);

          //update state
          (*cs).state.SetState(SYN_RCVD);
          //(*cs).state.SetTimerTries(SYN_RCVD);
          //(*cs).state.SetLastAcked(SYN_RCVD);
          (*cs).state.SetLastSent(my_seqnum);
          //(*cs).state.SetSendRwnd(SYN_RCVD);
          (*cs).state.SetLastRecvd(seqnum);

          //use minetSend for above packet and mux
          MinetSend(mux, ret_p);
        }

        break;

      case SYN_RCVD:

        break;

      case SYN_SENT:

        break;

      case SYN_SENT1:

        break;

      case ESTABLISHED:
        cout << "current state: established" << endl;
        break;

      case SEND_DATA:

        break;

      case CLOSE_WAIT:

        break;

      case FIN_WAIT1:

        break;

      case CLOSING:

        break;

      case LAST_ACK:

        break;

      case FIN_WAIT2:

        break;

      case TIME_WAIT:

        break;


    }//switch

  }//if (cs!=clist.end())


}//muxhandler