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

  //received packet properties
  unsigned short total_len; //length of packet w/ headers
  unsigned short data_len; //length of data
  Buffer data;  
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
  p.ExtractHeaderFromPayload<IPHeader>(iphlen);

  //store headers in tcph and iph
  tcph=p.FindHeader(Headers::TCPHeader);
  iph=p.FindHeader(Headers::IPHeader);

  //check if checksum is correct 
  checksumok=tcph.IsCorrectChecksum(p);

  //length of headers
  iph.GetTotalLength(total_len); //total length including ip header
  data_len = total_len - iphlen - tcphlen; //actual data length
  
  //get data
  data = p.GetPayload().ExtractFront(data_len);

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
  tcph.GetAckNum();
  // tcph.GetWinSize();
  // tcph.GetUrgentPtr();
  // tcph.GetOptions();

  //find ConnectionToStateMapping in list
  ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);

  //fetch state from the ConnectionToStateMapping
  unsigned int state = (*cs).state.GetState()

  if (cs!=clist.end() && checksumok) {
    
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
          ret_iph.SetSourceIP((*cs).connection.src);
          ret_iph.SetDestIP((*cs).connection.dest);
          ret_iph.SetTotalLength(TCP_HEADER_LENGTH+IP_HEADER_BASE_LENGTH);
          // push it onto the packet
          ret_p.PushFrontHeader(ret_iph);

          /*MAKE TCP HEADER*/
          //variables
          TCPHeader ret_tcph;
          unsigned int my_seqnum = 0; //hardcoded atm, should be random
          unsigned char my_flags;

          ret_tcph.SetSourcePort((*cs).srcport, ret_p);
          ret_tcph.SetDestPort((*cs).destport, ret_p);
          ret_tcph.SetSeqNum(my_seqnum, ret_p);
          ret_tcph.SetAckNum(seqnum+1, ret_p); //set to isn+1

          //set flags
          SET_SYN(my_flags);
          SET_ACK(my_flags);
          ret_tcph.SetFlags(my_flags, ret_p);

          ret_tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, ret_p);
          // ret_tcph.SetWinSize(0, ret_p);
          // ret_tcph.SetUrgentPtr(0, ret_p);
          // ret_tcph.SetOptions(0, ret_p);

          //recompute checksum with headers in
          ret_tcph.RecomputeChecksum(ret_p);

          //make sure ip header is in front
          ret_p.PushBackHeader(ret_tcph);

          /* end header */

          //update state
          //need to update state after every state
          (*cs).state.SetState(SYN_RCVD);
          //(*cs).state.SetTimerTries(SYN_RCVD);
          //(*cs).state.SetLastAcked(SYN_RCVD);
          (*cs).state.SetLastSent(my_seqnum);
          //(*cs).state.SetSendRwnd(SYN_RCVD);
          (*cs).state.SetLastRecvd(seqnum, 0); //no data in syn packet

          //use minetSend for above packet and mux
          MinetSend(mux, ret_p);
        }

        break;

      case SYN_RCVD:
        // Necessary conditions to move into ESTABLISHED: 
        // SYN bit not set, ACK bit set, seqnum == client_isn+1, ack == server_isn+1

        if(IS_SYN(flags)==false 
          && IS_ACK(flags)==true
          && seqnum==(*cs).state.GetLastRecvd()+1 
          && acknum==(*cs).state.GetLastSent()+1) {

          /* FORWARD DATA TO SOCKET */
          SockRequestResponse response;
          response.type = WRITE;
          response.connection = c;
          response.data = data;
          response.bytes = data_len; 
          MinetSend(sock, response);

          /* ACK PACKET - IMPLEMENT AFTER TIMERS ARE IN? */

          //update state
          (*cs).state.SetState(ESTABLISHED);
          //(*cs).state.SetTimerTries(SYN_RCVD);
          (*cs).state.SetLastAcked(acknum-1);
          //(*cs).state.SetLastSent(my_seqnum);
          //(*cs).state.SetSendRwnd(SYN_RCVD);
          (*cs).state.SetLastRecvd(seqnum, data_len); //account for length of data


        }

        break;

      case SYN_SENT:

        break;

      case SYN_SENT1:

        break;

      case ESTABLISHED:
        cout << "current state: established" << endl;

        /* FORWARD DATA TO SOCKET */
        SockRequestResponse response;
        response.type = WRITE;
        response.connection = c;
        response.data = data;
        response.bytes = data_len; 
        MinetSend(sock, response);

        /* ACK PACKET - IMPLEMENT AFTER TIMERS ARE IN? */

        //update state
        //(*cs).state.SetState(ESTABLISHED);
        //(*cs).state.SetTimerTries(SYN_RCVD);
        if(IS_ACK(flags)){
          (*cs).state.SetLastAcked(acknum-1);
        }
        //(*cs).state.SetLastSent(my_seqnum);
        //(*cs).state.SetSendRwnd(SYN_RCVD);
        (*cs).state.SetLastRecvd(seqnum, data_len); //account for length of data


        }

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


void SockHandler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist) {

    //grab request from socket
    SockRequestResponse request;
    MinetReceive(sock, request);

    //switch based on what socket wants to do
    switch(request.type){

      case CONNECT:

        break;

      case ACCEPT:

        /* ADD A NEW ACCEPT CONNECTION */

        // first initialize the ConnectionToStateMapping
        ConnectionToStateMapping<TCPState> new_cs;

        //Create a new accept connection - will start at LISTEN

        //the new connection is what's specified by the request from the socket
        new_cs.connection = s.connection;

        //generate new state
        //implement timertries eventually, right now set to 1?
        unsigned int timertries = 1;
        TCPState accept_c = TCPState(rand(), LISTEN, timertries);
        
        //fill out state of ConnectionToStateMapping
        new_cs.state = accept_c;

        //add new ConnectionToStateMapping to list
        clist.push_front(new_cs);

        //send a STATUS to the socket with only error code set
        SockRequestResponse response;
        response.type = STATUS;
        response.error = EOK;
        MinetSend(sock, response);        

        break;

      case WRITE:

        break;

      case FORWARD:

        break;

      case CLOSE:

        break;

      case STATUS:

        break;

    }//switch
}//sockhandler