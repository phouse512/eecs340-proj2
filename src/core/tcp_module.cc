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

  //declare variables
  Packet p;
  unsigned short len;
  bool checksumok;
  unsigned char flags; //to hold syn, fin, rst, psh flags of packet p

  //grab packet from ip
  MinetReceive(mux,p);

  //pop off header
  p.ExtractHeaderFromPayload<TCPHeader>(8);

  //store headers in tcph and iph
  TCPHeader tcph;
  tcph=p.FindHeader(Headers::TCPHeader);
  checksumok=tcph.IsCorrectChecksum(p);
  IPHeader iph;
  iph=p.FindHeader(Headers::IPHeader);

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

        //if receives a SYN flag
        if(IS_SYN(flags)){

          //set state to SYN_RCVD
          (*cs).state.SetState(SYN_RCVD);

          //make return packet with syn_ack

          //use minetSend for above packet and mux

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