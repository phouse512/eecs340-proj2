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
#include "tcpstate.h"
#include "constate.h"


#include <iostream>

#include "Minet.h"


using std::cout;
using std::endl;
using std::cerr;
using std::string;

void MuxHandler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist);
void SockHandler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist);
Packet MakePacket(ConnectionToStateMapping<TCPState> cs, unsigned int cmd, unsigned short data_len);

//for the making of packets
#define SEND_SYNACK 1
#define SEND_SYN 2

//timertries set to 3, rfc default
#define TIMERTRIES 3

int main(int argc, char *argv[])
{
  MinetHandle mux, sock;

  ConnectionList<TCPState> clist;


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
    cout << "****************NEW EVENT*******************" << endl;
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow 
	|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } else {
      //  Data from the IP layer below  //
      if (event.handle==mux) {
      	MuxHandler(mux, sock, clist);
      }
      //  Data from the Sockets layer above  //
      if (event.handle==sock) {
        SockHandler(mux, sock, clist);
      }
    }
  }
  return 0;
}

void MuxHandler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist) {
  cout << "in MuxHandler" << endl;
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
  unsigned int acknum;


  /* BEGIN */

  //grab packet from ip
  MinetReceive(mux,p);

  //get header length estimates
  tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
  iphlen=IPHeader::EstimateIPHeaderLength(p);

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
  tcph.GetAckNum(acknum);
  // tcph.GetWinSize();
  // tcph.GetUrgentPtr();
  // tcph.GetOptions();

  //find ConnectionToStateMapping in list
  ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);

  //fetch state from the ConnectionToStateMapping
  unsigned int state = (*cs).state.GetState();

  if (cs!=clist.end() && checksumok) {
    SockRequestResponse response;
    Packet ret_p;
    switch(state) {

      case CLOSED:
        cout << "currently closed :(" << endl;
        break;

      case LISTEN:
        cout << "listening wheee" << endl;

        //if SYN bit is set
        if(IS_SYN(flags)){

          /*NOTE THAT WE ARE DOING STOP AND WAIT ATM. 
          COMMENTED OUT SET COMMANDS ARE FOR GBN */    

          //update state
          //need to update state after every state
          (*cs).state.SetState(SYN_RCVD);
          //(*cs).state.SetTimerTries(SYN_RCVD);
          //(*cs).state.SetLastAcked(SYN_RCVD);
          (*cs).state.SetLastSent(my_seqnum);
          //(*cs).state.SetSendRwnd(SYN_RCVD);
          (*cs).state.SetLastRecvd(seqnum+1); //no data in syn packet

          //make return packet
          ret_p = MakePacket(*cs, SEND_SYNACK, 0);

          //use minetSend for above packet and mux
          MinetSend(mux, ret_p);
        }

        break;

      case SYN_RCVD:
        // Necessary conditions to move into ESTABLISHED: 
        // SYN bit not set, ACK bit set, seqnum == client_isn+1, ack == server_isn+1
        cout << "currently in syn_rcvd" << endl;
        // if(IS_SYN(flags)==false 
        //   && IS_ACK(flags)==true
        //   && seqnum==(*cs).state.GetLastRecvd()+1 
        //   && acknum==(*cs).state.GetLastSent()+1) {

          // /* FORWARD DATA TO SOCKET */
          // cout << "inside the logic" << endl;
          // response.type = WRITE;
          // response.connection = c;
          // response.data = data;
          // response.bytes = data_len; 
          // MinetSend(sock, response);

          /* ACK PACKET - IMPLEMENT AFTER TIMERS ARE IN? */

          //update state
          (*cs).state.SetState(ESTABLISHED);
                  cout << "set state to estab in synrcvd" << endl;

          //(*cs).state.SetTimerTries(SYN_RCVD);
          (*cs).state.SetLastAcked(acknum);
          //(*cs).state.SetLastSent(my_seqnum);
          //(*cs).state.SetSendRwnd(SYN_RCVD);
          (*cs).state.SetLastRecvd(seqnum, data_len); //account for length of data

                  //send a STATUS to the socket with only error code set
        response.type = WRITE;
        response.error = EOK;
        response.bytes = 0;
        MinetSend(sock, response);        


       // }

        break;

      case SYN_SENT:
        cout << "currently at syn_sent" << endl;
        break;

      case ESTABLISHED:
        cout << "current state: established" << endl;

        /* FORWARD DATA TO SOCKET */
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
  cout << "in SockHandler" << endl;
    //variables
    SockRequestResponse request;
    SockRequestResponse response;
    //ConnectionToStateMapping<TCPState> new_cs;
    unsigned int initial_seq_num;
    TCPState accept_c; //the new state we add to the list
    Packet ret_p;

    //grab request from socket
    MinetReceive(sock, request);

    //ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);

    //switch based on what socket wants to do
    switch(request.type){

      case CONNECT:
        // cout << "attempting to add a new connection :(" << endl;
        // /* ADD A NEW CONNECT CONNECTION */

        // // first initialize the ConnectionToStateMapping
        // //Create a new accept connection - will start at SYN_sent
        // //the new connection is what's specified by the request from the socket
        // new_cs.connection = request.connection;

        // //generate new state
        // //implement timertries eventually, right now set to 1?
        // timertries = 1;
        // initial_seq_num = rand();
        // accept_c = TCPState(initial_seq_num, SYN_SENT, timertries);
        
        // //fill out state of ConnectionToStateMapping
        // new_cs.state = accept_c;

        // //set state
        // new_cs.state.SetLastSent(initial_seq_num);
        // //(*cs).state.SetSendRwnd(SYN_RCVD);


        // //add new ConnectionToStateMapping to list
        // clist.push_front(new_cs);

        // //send SYN packet
        // ret_p = MakePacket(new_cs, SEND_SYN, 0);
        // MinetSend(mux, ret_p);

        // //send a STATUS to the socket with only error code set

        // response.type = STATUS;
        // response.error = EOK;
        // MinetSend(sock, response);    

        break;

      case ACCEPT:
        cout << "accepting a new connection :D" << endl;
        /* ADD A NEW ACCEPT CONNECTION */

        // first initialize the ConnectionToStateMapping
        //Create a new accept connection - will start at LISTEN
        //the new connection is what's specified by the request from the socket

        //generate new state
        TCPState accept_c(rand(), LISTEN, TIMERTRIES);
        
        //fill out state of ConnectionToStateMapping
        ConnectionToStateMapping<TCPState> new_cs(request.connection, Time(), accept_c, false);

        //add new ConnectionToStateMapping to list
        clist.push_front(new_cs);
        cout << "pushed? :(" << endl;

        //send a STATUS to the socket with only error code set
        response.type = STATUS;
        response.error = EOK;
        MinetSend(sock, response);        
        cout << "exit accept:(" << endl;

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

/* THIS FUNCTION ASSSUMES STATE HAS ALREADY BEEN UPDATED */
Packet MakePacket(ConnectionToStateMapping<TCPState> cs, unsigned int cmd, unsigned short data_len) {
    /* MAKE PACKET */
  Packet ret_p;

  /* MAKE IP HEADER */
  IPHeader ret_iph;

  ret_iph.SetProtocol(IP_PROTO_TCP);
  ret_iph.SetSourceIP(cs.connection.src);
  ret_iph.SetDestIP(cs.connection.dest);
  ret_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH+data_len);
  // push it onto the packet
  ret_p.PushFrontHeader(ret_iph);

  /*MAKE TCP HEADER*/
  TCPHeader ret_tcph;

  //common settings
  ret_tcph.SetSourcePort(cs.connection.srcport, ret_p);
  ret_tcph.SetDestPort(cs.connection.destport, ret_p);
  ret_tcph.SetSeqNum(cs.state.GetLastSent(), ret_p);

  //flags and non-common settings
  unsigned char my_flags;
  switch(cs.state.GetState()) {

    case SEND_SYN:
      SET_SYN(my_flags);
      ret_tcph.SetFlags(my_flags, ret_p);
      break;

    case SEND_SYNACK:
      ret_tcph.SetAckNum(cs.state.GetLastRecvd(), ret_p); 

      SET_SYN(my_flags);
      SET_ACK(my_flags);
      ret_tcph.SetFlags(my_flags, ret_p);
      break;
  }

  ret_tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, ret_p);
  // ret_tcph.SetWinSize(0, ret_p);
  // ret_tcph.SetUrgentPtr(0, ret_p);
  // ret_tcph.SetOptions(0, ret_p);

  //recompute checksum with headers in
  ret_tcph.RecomputeChecksum(ret_p);

  //make sure ip header is in front
  ret_p.PushBackHeader(ret_tcph);

  return ret_p;
}

// /* MAKE SYNACK PACKET */
//           Packet ret_p;

//           /* MAKE IP HEADER */
//           IPHeader ret_iph;

//           ret_iph.SetProtocol(IP_PROTO_TCP);
//           ret_iph.SetSourceIP((*cs).connection.src);
//           ret_iph.SetDestIP((*cs).connection.dest);
//           ret_iph.SetTotalLength(TCP_HEADER_LENGTH+IP_HEADER_BASE_LENGTH);
//           // push it onto the packet
//           ret_p.PushFrontHeader(ret_iph);

//           /*MAKE TCP HEADER*/
//           //variables
//           TCPHeader ret_tcph;
//           unsigned int my_seqnum = rand(); 
//           unsigned char my_flags;

//           ret_tcph.SetSourcePort((*cs).srcport, ret_p);
//           ret_tcph.SetDestPort((*cs).destport, ret_p);
//           ret_tcph.SetSeqNum(my_seqnum, ret_p);
//           ret_tcph.SetAckNum(seqnum+1, ret_p); //set to isn+1

//           //set flags
//           SET_SYN(my_flags);
//           SET_ACK(my_flags);
//           ret_tcph.SetFlags(my_flags, ret_p);

//           ret_tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, ret_p);
//           // ret_tcph.SetWinSize(0, ret_p);
//           // ret_tcph.SetUrgentPtr(0, ret_p);
//           // ret_tcph.SetOptions(0, ret_p);

//           //recompute checksum with headers in
//           ret_tcph.RecomputeChecksum(ret_p);

//           //make sure ip header is in front
//           ret_p.PushBackHeader(ret_tcph);

//           /* end header */