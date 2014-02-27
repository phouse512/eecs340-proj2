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

void TimeHandler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist);
void MuxHandler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist);
void SockHandler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist);
void MakePacket(Packet &ret_p, ConnectionToStateMapping<TCPState> cs, unsigned int cmd, unsigned short data_len);

//for the making of packets
#define SEND_SYN 1
#define SEND_SYNACK 2
#define SEND_ACK 3
#define SEND_FIN 4

//timertries set to 3, rfc default
#define TIMERTRIES 3

//estimated rtt
#define RTT 5

//timeout length
#define TIMEOUT 10

//max size of segment in bytes
#define MSS 536

//gbn max size in bytes
#define GBN MSS*5

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

  while (MinetGetNextEvent(event, TIMEOUT)==0) {
    cout << "****************NEW EVENT*******************" << endl;
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow || event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    // if we received a valid event from Minet, do processing
    } 
    else {
      if (event.eventtype == MinetEvent::Timeout) {
        TimeHandler(mux, sock, clist);
      }
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
  Packet ret_p;
  TCPHeader tcph;
  IPHeader iph;
  unsigned tcphlen_est;
  unsigned char tcphlen;
  unsigned char iphlen;

  //received packet properties
  unsigned short total_len; //length of packet w/ headers
  unsigned short data_len; //length of data
  Buffer data;  
  bool checksumok;
  unsigned char flags; //to hold syn, fin, rst, psh flags of packet p
  unsigned int seqnum;
  unsigned int acknum;
  unsigned short rwnd;


  /* BEGIN */

  //grab packet from ip
  MinetReceive(mux,p);

  //get header length estimates
  tcphlen_est=TCPHeader::EstimateTCPHeaderLength(p);

  //extract headers
  p.ExtractHeaderFromPayload<TCPHeader>(tcphlen_est);

  //store headers in tcph and iph
  tcph=p.FindHeader(Headers::TCPHeader);
  iph=p.FindHeader(Headers::IPHeader);

  //check if checksum is correct 
  checksumok=tcph.IsCorrectChecksum(p);

  //length of headers
  iph.GetTotalLength(total_len); //total length including ip header
  iph.GetHeaderLength(iphlen); //length in 32 bit words ie. num of 4byte chunks
  iphlen <<= 2; //want to multiply by 4 to get byte length
  tcph.GetHeaderLen(tcphlen); //length in 32 bit words ie. num of 4byte chunks
  tcphlen <<= 2; //want to multiply by 4 to get byte length

  //get data
  data_len = total_len - iphlen - tcphlen; //actual data length
  cout << "Incoming data has length " << data_len << endl;
  data = p.GetPayload().ExtractFront(data_len);
  data.Print(cout);
  cout << endl;

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
  tcph.GetWinSize(rwnd);

  cout << "Incoming tcp header: " << endl;
  tcph.Print(cout);
  cout << endl;

  //find ConnectionToStateMapping in list
  ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);

  //fetch state from the ConnectionToStateMapping
  unsigned int state = (*cs).state.GetState();

  if (cs!=clist.end() && checksumok) {
    //initialize variables
    SockRequestResponse response;
    Packet ret_p;
    size_t our_window;

    //set receive window
    (*cs).state.SetSendRwnd(rwnd);

    switch(state) {

      case CLOSED:
        cout << "currently closed :(" << endl;
        break;

      case LISTEN:
        cout << "Current state: LISTEN" << endl;

        //if SYN bit is set
        if(IS_SYN(flags)){

          //set connection
          (*cs).connection = c;

          //update state
          //need to update state after every state
          (*cs).state.SetState(SYN_RCVD);
          //(*cs).state.SetTimerTries(SYN_RCVD);
          //(*cs).state.SetLastAcked(SYN_RCVD);
          (*cs).state.SetLastSent(rand());
          (*cs).state.SetLastRecvd(seqnum); //no data in syn packet

          //timers
          (*cs).bTmrActive = true;
          (*cs).timeout = Time()+RTT;
  
          //make return packet
          MakePacket(ret_p, *cs, SEND_SYNACK, 0);

          //use minetSend for above packet and mux
          MinetSend(mux, ret_p);
        }

        break;

      case SYN_RCVD:
        // Necessary conditions to move into ESTABLISHED: 
        // SYN bit not set, ACK bit set, ack == server_isn+1
        cout << "Current state: SYN_RCVD" << endl;
        if(IS_SYN(flags)==false 
           && IS_ACK(flags)==true
           && acknum==(*cs).state.GetLastSent()+1) {

          //turn off timer
          (*cs).bTmrActive = false;

          //update state
          (*cs).state.SetState(ESTABLISHED);
          cout << "set state to estab in synrcvd" << endl;

          (*cs).state.SetTimerTries(TIMERTRIES);
          (*cs).state.SetLastAcked(acknum-1);          
          //(*cs).state.SetLastSent(my_seqnum);

          /*ADD IN CASE FROM ESTABLISHED IF THERE IS DATA */
          (*cs).state.SetLastRecvd(seqnum, data_len); 

          //send a STATUS to the socket indicating connection
          response.type = WRITE;
          response.connection = c;
          response.error = EOK;
          response.bytes = 0;
          MinetSend(sock, response);        
        }

        break;

      case SYN_SENT:
        cout << "Current state: SYN_SENT" << endl;
        if(IS_SYN(flags)==true 
           && IS_ACK(flags)==true
           && acknum==(*cs).state.GetLastSent()+1) {

          //update state
          (*cs).state.SetState(ESTABLISHED);
          cout << "set state to estab in synsent" << endl;

          (*cs).state.SetLastAcked(acknum-1);          
          (*cs).state.SetLastSent((*cs).state.GetLastSent()+1); //no payload
          (*cs).state.SetLastRecvd(seqnum, data_len); //should be no data

          //reset timer
          (*cs).timeout = Time()+RTT;
          (*cs).bTmrActive = true;
          (*cs).state.SetTimerTries(TIMERTRIES);

          //make return packet
          MakePacket(ret_p, *cs, SEND_ACK, 0);
          //use minetSend for above packet and mux
          MinetSend(mux, ret_p);

          //send a STATUS to the socket indicating connection
          response.type = WRITE;
          response.connection = c;
          response.error = EOK;
          response.bytes = 0;
          MinetSend(sock, response);        
        }        
        break;

      case ESTABLISHED:
        cout << "Current state: ESTABLISHED" << endl;

        //things we need to check
          //is there data
          //is there an ack
          //is there a close

        //if there's an ack
        if (IS_ACK(flags)) {
          //wipe send buffer as needed
          (*cs).state.SendBuffer.Erase(0, acknum - (*cs).state.GetLastAcked() - 1);

          (*cs).state.SetLastAcked(acknum-1);
          //will be overwritten if there was a payload
          (*cs).state.SetLastRecvd(seqnum);

          //timer reset condition 
          if((*cs).state.GetLastAcked() == (*cs).state.GetLastSent()) {
            (*cs).bTmrActive = false;
            (*cs).state.SetTimerTries(TIMERTRIES);
          }
        }

        //if there is data
        if(data_len!=0){     

          /* FORWARD DATA TO SOCKET */
          //stick data in receive buffer
          //check for overflow
          our_window = (*cs).state.TCP_BUFFER_SIZE - (*cs).state.RecvBuffer.GetSize();
          //overflow
          if(our_window < data_len) {
            (*cs).state.RecvBuffer.AddBack(data.ExtractFront(our_window));
            (*cs).state.SetLastRecvd(seqnum + our_window - 1); 
            cout << "Only " << our_window << " bytes out of " << data_len << " able to fit in receive buffer." << endl;
          }
          //no overflow
          else {
            (*cs).state.RecvBuffer.AddBack(data);
            (*cs).state.SetLastRecvd(seqnum + data_len - 1); 
          }

          //assumes a srr can fit an entire receive buffer...
          response.type = WRITE;
          response.connection = c;
          response.data = (*cs).state.RecvBuffer;
          response.bytes = (*cs).state.RecvBuffer.GetSize();
          response.error = EOK;
          MinetSend(sock, response);
        
          // //update ack if there was one
          // if(IS_ACK(flags)){
          //   (*cs).state.SetLastAcked(acknum-1);

          //   //timer reset condition 
          //   if((*cs).state.GetLastAcked() == (*cs).state.GetLastSent()) {
          //     (*cs).bTmrActive = false;
          //     (*cs).state.SetTimerTries(TIMERTRIES);
          //   }
          // }

          //no payload in what we're sending
          (*cs).state.SetLastSent((*cs).state.GetLastSent()+1);

          //reset timer
          if((*cs).bTmrActive == false){
            (*cs).bTmrActive = true;
            (*cs).timeout = Time() + RTT;
          }

          MakePacket(ret_p, *cs, SEND_ACK, 0);
          MinetSend(mux, ret_p);
./struct $
{
  /* data */
};
        }        
        // else if (IS_ACK(flags)) {
        //   //no payload, only an ack
        //   (*cs).state.SetLastAcked(acknum-1);
        //   (*cs).state.SetLastRecvd(seqnum);

        //   //timer reset condition 
        //   if((*cs).state.GetLastAcked() == (*cs).state.GetLastSent()) {
        //     (*cs).bTmrActive = false;
        //     (*cs).state.SetTimerTries(TIMERTRIES);
        //   }
        // }
        else if (IS_FIN(flags)) {
          //no payload
          (*cs).state.SetLastSent((*cs).state.GetLastSent()+1);          
          (*cs).state.SetState(CLOSE_WAIT);
          (*cs).state.SetLastRecvd(seqnum);

          MakePacket(ret_p, *cs, SEND_ACK, 0);
          MinetSend(mux, ret_p);
        }
        break;

      case CLOSE_WAIT:
        cout << "Current state: CLOSE_WAIT" << endl;
        //no payload
        (*cs).state.SetLastSent((*cs).state.GetLastSent()+1);        
        (*cs).state.SetState(LAST_ACK);
        (*cs).state.SetLastRecvd(seqnum);

        MakePacket(ret_p, *cs, SEND_FIN, 0);
        MinetSend(mux, ret_p);
        break;

      case FIN_WAIT1:
        cout << "Current state: FIN_WAIT1" << endl;

        break;

      case CLOSING:
        cout << "Current state: CLOSING" << endl;

        break;

      case LAST_ACK:
            //HOW DOES IT GET HERE
        cout << "Current state: LAST_ACK" << endl;

        break;

      case FIN_WAIT2:
        cout << "Current state: FIN_WAIT2" << endl;

        break;

      case TIME_WAIT:
        cout << "Current state: TIME_WAIT" << endl;

        break;


    }//switch

  }//if (cs!=clist.end())


}//muxhandler


void SockHandler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist) {
  cout << "in SockHandler" << endl;
    //variables
    SockRequestResponse request;
    SockRequestResponse response;
    Packet ret_p;
    size_t sendbuf_space;

    //grab request from socket
    MinetReceive(sock, request);

    ConnectionList<TCPState>::iterator cs = clist.FindMatching(request.connection);
    unsigned int state = (*cs).state.GetState();

    //switch based on what socket wants to do
    switch(request.type){

      case CONNECT: {
          cout << "Current state: CONNECT" << endl;

          //generate new state
          TCPState connect_c(rand(), SYN_SENT, TIMERTRIES);

          //fill out state of ConnectionToStateMapping
          ConnectionToStateMapping<TCPState> new_cs(request.connection, Time(), connect_c, false);

          //add new ConnectionToStateMapping to list
          clist.push_front(new_cs);

          //set state
          //new_cs.state.SetLastSent(initial_seq_num);
          //(*cs).state.SetSendRwnd(SYN_RCVD);

          //add new ConnectionToStateMapping to list
          clist.push_front(new_cs);

          //send SYN packet
          MakePacket(ret_p, new_cs, SEND_SYN, 0);
          MinetSend(mux, ret_p);

          //send a STATUS to the socket with only error code set
          response.bytes = 0;
          response.type = STATUS;
          response.error = EOK;
          MinetSend(sock, response);    
        }
        break;

      case ACCEPT: {
          cout << "Current state: ACCEPT" << endl;
          /* ADD A NEW ACCEPT CONNECTION */

          //generate new state
          TCPState accept_c(rand(), LISTEN, TIMERTRIES);

          //fill out state of ConnectionToStateMapping
          ConnectionToStateMapping<TCPState> new_cs(request.connection, Time(), accept_c, false);

          //add new ConnectionToStateMapping to list
          clist.push_front(new_cs);

          //send a STATUS to the socket with only error code set
          response.type = STATUS;
          response.error = EOK;
          MinetSend(sock, response);        
        }
        break;

      case WRITE: {
          cout << "Current state: WRITE" << endl;

          //make sure there's a pre-existing connection and state is ESTABLISHED
          if (cs!=clist.end() && state == ESTABLISHED) {

            /*PUT DATA IN BUFFER */
            //stick data in buffer
            //overflow case
            sendbuf_space = (*cs).state.TCP_BUFFER_SIZE - (*cs).state.SendBuffer.GetSize();
            if(sendbuf_space < request.bytes) {
              (*cs).state.SendBuffer.AddBack(request.data.ExtractFront(sendbuf_space));
              
              cout << "Only " << sendbuf_space << " bytes out of " << request.bytes << " able to fit in send buffer." << endl;
            
              //response fields
              response.bytes = sendbuf_space;
              response.error = EBUF_SPACE;
            }
            //no overflow
            else {
              (*cs).state.SendBuffer.AddBack(request.data);
              //response fields
              response.bytes = request.bytes;
              response.error = EOK;
            }

            //send response to socket
            response.type = STATUS;
            response.connection = request.connection;
            MinetSend(sock, response); 

            /* NOW SEND STUFF FROM THE BUFFER */
            //we'll send N packets worth and have establish send the rest
            //right now just one packet
            //if sendbuffer contents is less than mss, send everything

            while()

            //six cases on what the segment size should be
            int rwnd = (*cs).state.GetRwnd();
            size_t sendbuf_size = (*cs).state.SendBuffer.GetSize();
            //send < mss < rwnd
            //send < rwnd < mss
            if((sendbuf_size < MSS && MSS << rwnd) || (sendbuf_size < rwnd && rwnd < MSS)){
              ret_p = Packet((*cs).state.SendBuffer.ExtractFront(sendbuf_size));
              (*cs).state.SetLastSent((*cs).state.GetLastSent() + sendbuf_size);
              MakePacket(ret_p, *cs, SEND_ACK, sendbuf_size);

            }
            //mss < rwnd < semd
            //mss < send < rwmd
            else if((MSS < rwnd && rwnd << sendbuf_size) || (MSS < sendbuf_size && sendbuf_size < rwnd)){
              ret_p = Packet((*cs).state.SendBuffer.ExtractFront(MSS));
              (*cs).state.SetLastSent((*cs).state.GetLastSent() + MSS);
              MakePacket(ret_p, *cs, SEND_ACK, MSS);
            }
            //rwnd < mss < sendbuf
            //rwnd < sendbuf < mss
            else {
              ret_p = Packet((*cs).state.SendBuffer.ExtractFront(rwnd));
              (*cs).state.SetLastSent((*cs).state.GetLastSent() + rwnd);
              MakePacket(ret_p, *cs, SEND_ACK, rwnd);
            }

            MinetSend(mux, ret_p);

          }
          //fail case
          else {
            cout << "Write failed. No such connection." << endl;
            
            response.type = STATUS;
            response.connection = request.connection;
            response.data = request.data;
            response.bytes = request.bytes;
            response.error = ENOMATCH;
            MinetSend(sock, response); 
          }

        }
        break;

      case FORWARD:
        cout << "Current state: FORWARD" << endl;

        break;

      case CLOSE:
        cout << "Current state: CLOSE" << endl;

        break;

      case STATUS:
        cout << "Current state: STATUS" << endl;

        //if established, we need to check if everything was read
        //from the buffer and then wipe it so it stops reading from it
        if(state == ESTABLISHED){
          //check if everything from buffer was read
          cout << request.bytes << " out of " << (*cs).state.RecvBuffer.GetSize() << " read." << endl;
          if(request.bytes == (*cs).state.RecvBuffer.GetSize()){
            cout << "All data written to socket." << endl;
            (*cs).state.RecvBuffer.Clear(); 
          }
          else{
            cout << "Rewriting data to socket." << endl;
            (*cs).state.RecvBuffer.Erase(0, request.bytes); 
            response.type = WRITE;
            response.connection = request.connection;
            response.data = (*cs).state.RecvBuffer;
            response.bytes = (*cs).state.RecvBuffer.GetSize();
            response.error = EOK;
            MinetSend(sock, response);   
          }
        }

        break;

    }//switch
}//sockhandler

/* THIS FUNCTION ASSSUMES STATE HAS ALREADY BEEN UPDATED */
void MakePacket(Packet &ret_p, ConnectionToStateMapping<TCPState> cs, unsigned int cmd, unsigned short data_len) {
    /* MAKE PACKET */

  /* MAKE IP HEADER */
  IPHeader ret_iph;
  ret_iph.SetProtocol(IP_PROTO_TCP);
  ret_iph.SetSourceIP(cs.connection.src);
  ret_iph.SetDestIP(cs.connection.dest);
  ret_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH+data_len);
  ret_p.PushFrontHeader(ret_iph);

  /*MAKE TCP HEADER*/
  TCPHeader ret_tcph;
  ret_tcph.SetSourcePort(cs.connection.srcport, ret_p);
  ret_tcph.SetDestPort(cs.connection.destport, ret_p);
  ret_tcph.SetSeqNum(cs.state.GetLastSent(), ret_p);
  ret_tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH/4, ret_p);
  ret_tcph.SetAckNum(cs.state.GetLastRecvd()+1, ret_p); 


  //tell other guy what our receive window is
  unsigned short our_window = cs.state.TCP_BUFFER_SIZE - cs.state.RecvBuffer.GetSize();
  ret_tcph.SetWinSize(our_window, ret_p);

  //flags and non-common settings
  unsigned char my_flags = 0;
  switch(cmd) {

    case SEND_SYN:
      ret_tcph.SetAckNum(0, ret_p); 
      SET_SYN(my_flags);
      break;

    case SEND_SYNACK:
      SET_SYN(my_flags);
      SET_ACK(my_flags);
      break;

    case SEND_ACK:
      SET_ACK(my_flags);
      break;

    case SEND_FIN:
      SET_FIN(my_flags);
      break;
  }
  ret_tcph.SetFlags(my_flags, ret_p);

  //recompute checksum with headers in
  ret_tcph.RecomputeChecksum(ret_p);

  //print header stats
  ret_tcph.Print(cout);
  cout << endl;

  //make sure ip header is in front
  ret_p.PushBackHeader(ret_tcph);

}

void TimeHandler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist){

  //get current time
  Time current_time = Time();
  //loop through connections to check for timeouts
  for(ConnectionList<TCPState>::iterator cs = clist.begin(); cs!=clist.end(); cs++) {
    //check the ones that have their timers active
    if((*cs).bTmrActive == true && (*cs).timeout < current_time){
      //if tried three times, kill
      //remember expire timer tries decrements and returns true if zero
      if((*cs).state.ExpireTimerTries()){
        //close the connection
        //does this mean setting it to close?
      }


    }

  }//for

}


            // //six cases on what the segment size should be
            // int rwnd = (*cs).state.GetRwnd();
            // size_t sendbuf_size = (*cs).state.SendBuffer.GetSize();
            // //send < mss < rwnd
            // //send < rwnd < mss
            // if((sendbuf_size < MSS && MSS << rwnd) || (sendbuf_size < rwnd && rwnd < MSS)){
            //   ret_p = Packet((*cs).state.SendBuffer.ExtractFront(sendbuf_size));
            //   (*cs).state.SetLastSent((*cs).state.GetLastSent() + sendbuf_size);
            //   MakePacket(ret_p, *cs, SEND_ACK, sendbuf_size);

            // }
            // //mss < rwnd < semd
            // //mss < send < rwmd
            // else if((MSS < rwnd && rwnd << sendbuf_size) || (MSS < sendbuf_size && sendbuf_size < rwnd)){
            //   ret_p = Packet((*cs).state.SendBuffer.ExtractFront(MSS));
            //   (*cs).state.SetLastSent((*cs).state.GetLastSent() + MSS);
            //   MakePacket(ret_p, *cs, SEND_ACK, MSS);
            // }
            // //rwnd < mss < sendbuf
            // //rwnd < sendbuf < mss
            // else {
            //   ret_p = Packet((*cs).state.SendBuffer.ExtractFront(rwnd));
            //   (*cs).state.SetLastSent((*cs).state.GetLastSent() + rwnd);
            //   MakePacket(ret_p, *cs, SEND_ACK, rwnd);
            // }

            // MinetSend(mux, ret_p);