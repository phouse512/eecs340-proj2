/* rich chang rhc197
basil huang bhu984*/

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
#include <list>
#include "Minet.h"
#include "tcpstate.h"

using namespace std;

void MakePacket(Packet &pack, ConnectionToStateMapping<TCPState> &a_mapping, int size_of_data, int header, bool customSeq = false, int sequence=0);

void set_reply(SockRequestResponse &reply);

static bool firstSend = true;

void printState(ConnectionList<TCPState>::iterator cs){
    cout<<"TCP CONNECTION STATE: "<<cs->state.GetState()<<endl;
}

// Mux_handler function
void mux_handler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist){
  Packet p, out_p;
  unsigned int ackNum;
  unsigned int seqNum;
  TCPHeader tcp;
  IPHeader ip;
  bool checkSum;
  Connection conn;
  SockRequestResponse repl, req;
  unsigned short length;
  unsigned short winSize;
  unsigned short urgentPointer;
  unsigned char tcp_header_len;
  unsigned char ip_header_len;
  unsigned char flags;
  unsigned int currentState;
  Buffer buff;

  cout << "receiving packet in mux handler"<<endl;
  MinetReceive(mux, p);
  p.ExtractHeaderFromPayload<TCPHeader>(TCPHeader::EstimateTCPHeaderLength(p));
  tcp = p.FindHeader(Headers::TCPHeader);

  ip = p.FindHeader(Headers::IPHeader);
  ip.GetSourceIP(conn.dest);
  ip.GetDestIP(conn.src);
  ip.GetProtocol(conn.protocol);
  tcp.GetSourcePort(conn.destport);
  tcp.GetDestPort(conn.srcport);
  tcp.GetFlags(flags);
  tcp.GetWinSize(winSize);
  tcp.GetSeqNum(seqNum);
  tcp.GetAckNum(ackNum);
  tcp.GetUrgentPtr(urgentPointer);

  ip.GetTotalLength(length);
  ip.GetHeaderLength(ip_header_len);
  ip_header_len<<=2;
  tcp.GetHeaderLen(tcp_header_len);
  tcp_header_len<<=2;
  length = length - tcp_header_len - ip_header_len;
  cout<<"IP length w/o header lengths :"<<length<<endl;
  buff = p.GetPayload().ExtractFront(length);

  checkSum = tcp.IsCorrectChecksum(p);
  if (checkSum) {
    cout << "Checksum is okay" << endl;
  }
  else {
    cout << "Checksum is not okay." << endl;
  }

  ConnectionList<TCPState>::iterator cs = clist.FindMatching(conn);
  
  // if cnxn already exists
  if (cs != clist.end()){
    cout<<"Connection exists!"<<endl;
    cout<<"Connection information: " << conn <<endl;
    currentState = cs->state.GetState();
    printState(cs);
    cs->state.rwnd = winSize;// Update other's recv window size
    if(winSize <= cs->state.GetN()) { // Check recieving window size against our window size
      cs->state.N = winSize/TCP_MAXIMUM_SEGMENT_SIZE*TCP_MAXIMUM_SEGMENT_SIZE;
    }


  switch(currentState){
    case CLOSED:
      cout<<"mux handler, closed state"<<endl;
      break;
    
    case LISTEN: {
      cout<<"mux handler, listen state"<<endl;
      if(IS_SYN(flags)){
        (*cs).state.SetState(SYN_RCVD);
        cout<<"set state to synrcvd"<<endl;
        (*cs).state.last_acked = (*cs).state.last_sent-1;
        (*cs).state.SetLastRecvd(seqNum+1);
        (*cs).bTmrActive = true;
        //set timeout, waiting for the ack
        cout << "start timeout " << endl;
        (*cs).timeout=Time() + 0.2;
        (*cs).connection = conn;
        MakePacket(out_p, *cs, 0, 3);
        cout << "SYN ACK packet created." << endl;
        MinetSend(mux, out_p);
        // Timeout, send again
        if(firstSend) {
          sleep(2);
          MinetSend(mux, out_p);
          firstSend = false;
        }
        break;
      }
      else if(IS_FIN(flags)) {
        // FIN pkt
        MakePacket(out_p, *cs, 0, 6);
        // Send pkt
        MinetSend(mux, out_p);
      }
      break;
      }
      
      case SYN_SENT: {
      cout<<"mux handler, SYN_SENT state"<<endl;
        if(IS_SYN(flags) && IS_ACK(flags)){
          cs->state.SetLastRecvd(seqNum+1);
          cout<<"Set ACKed "<<((cs->state.SetLastAcked(ackNum))?"yes":"no")<<endl;
          cs->state.SetSendRwnd(winSize);
          // Create an ACK p
          MakePacket(out_p, *cs, 0, 2);
          MinetSend(mux, out_p);
          cs->state.SetState(ESTABLISHED);
          cout<<"sent ack packet and set state to ESTABLISHED"<<endl;

          cs->bTmrActive = false; //turn timer off
          SockRequestResponse write (WRITE, cs->connection, buff, 0, EOK);
          MinetSend(sock, write);
          MinetSend(sock, write);//try sending twice?
        }
        else if (IS_SYN(flags)) {
          cs->state.SetLastRecvd(seqNum);
          // Create an ACK p
          MakePacket(out_p, *cs, 0, 2);
          cout << "ACK packet created" << endl;
          MinetSend(mux, out_p);
          cs->state.SetState(SYN_RCVD);
          cout<<"set state to SYN RCVD"<<endl;
          cs->state.SetLastSent(cs->state.GetLastSent()+1);
        }
        else if(IS_FIN(flags) && IS_ACK(flags)) {
          cs->state.SetLastRecvd(seqNum+1);

          MakePacket(out_p, *cs, 0, 6);
          MinetSend(mux, out_p);

          cs->state.SetState(CLOSE_WAIT);
          cout<<"set state to CLOSE_WAIT"<<endl;

          repl.connection=req.connection;
          repl.type=STATUS;
          if (cs==clist.end()) {
            repl.error=ENOMATCH;
          }
          else {
            repl.error=EOK;
            clist.erase(cs);
          }
          MinetSend(sock,repl);
          }
          break;
        }
      
    case SYN_RCVD: {
      cout<<"mux handler, syn-rcvd state"<<endl;
      if(IS_ACK(flags)){
        if(cs->state.GetLastSent()+1 == ackNum){
          cout<<"Is ACK: Connection established!"<<endl;
          cs->state.SetState(ESTABLISHED);
          cout<<"set state to established"<<endl;
          cs->state.SetLastAcked(ackNum);
          cs->state.SetSendRwnd(winSize);
          cs->bTmrActive = false;
          repl.type = WRITE;
          repl.connection = conn;
          repl.error = EOK;
          repl.bytes = 0;
          MinetSend(sock, repl);
        }
      }
      else {
      cout<<"mux handler, didnt get ack"<<endl;
      }
    }
    break;
      
    case SYN_SENT1: {
      cout<<"mux handler, syn-sent1 state"<<endl;
      break;
    }
    
    case ESTABLISHED: {
      cout<<"mux handler, ESTABLSIHED state"<<endl;//rich you can't spell
      if (length!=0) {
        if(!(seqNum == cs->state.GetLastRecvd() && checkSum)) {
          cout << "bad seq num or bad checksum" << endl;
          MakePacket(out_p, *cs, 0, 2);
          MinetSend(mux,out_p);
        }
        else {
          cout<<"received data's checksum is good and seqnum is good"<<endl;
          cs->state.SetLastRecvd(seqNum+length);
          cout<<"Set ACKed "<<((cs->state.SetLastAcked(ackNum))?"yes":"no")<<endl;
          if(cs->state.GetRwnd() < length) {
            cout << "Not enough space in buffer to rcv packet" << endl;
            cs->state.SetLastRecvd(seqNum);
          }
          else {
            cs->state.RecvBuffer.AddBack(buff);
            SockRequestResponse write (WRITE, cs->connection, cs->state.RecvBuffer,cs->state.RecvBuffer.GetSize(), EOK);
            MinetSend(sock,write);
          }

          MakePacket(out_p, *cs, 0, 2);
          MinetSend(mux, out_p);
          cout<<"sent ack"<<endl;
        }
      }
      else if (IS_FIN(flags)) {
        cs->state.SetLastRecvd(seqNum+1);//add 1 to make sure it doesnt overlap
        //create fin ack
        MakePacket(out_p, *cs, 0, 6);
        MinetSend(mux, out_p);
        cout<<"send finack packet"<<endl;
        cs->state.SetState(LAST_ACK);//set state to last ack
        cout<<"set state to last ack"<<endl;

      }
      else if (IS_ACK(flags)) {
        cout<<"Only ACK. ";
        if (ackNum <= cs->state.GetLastAcked()+1) {// DOUBLE ACK
          cout<<"double ACK : "<<ackNum<<", Last ACKed: "<<cs->state.GetLastAcked() << endl;
          cout << "Timeout will occur." << endl;
        }
        else {
          cs->state.SetLastRecvd((unsigned int)seqNum);
          cs->state.SetLastAcked(ackNum);
          if(cs->state.GetLastAcked() == cs->state.GetLastSent()-1) {
            cout<<"Timer off. ";
            cs->bTmrActive = false;
          }
          else {
            cout<<"New timer set.";
            cs->bTmrActive = true;
            cs->timeout = Time()+5;
            cs->state.tmrTries = 3;
            cout << "3 send tries" << endl;
          }
        }
      }
      break;
    }
    
    case LAST_ACK:
      cout<<"mux handler, last-ack state"<<endl;
      if(IS_ACK(flags)) {
        cout<<"Last ACK is coming. "<<endl;
        repl.connection = conn;
        repl.type = WRITE;
        repl.bytes = 0;
        if (cs==clist.end()) {
          cout << "Connection error." << endl;
          repl.error=ENOMATCH;
        }
        else {
          cout<<"Connection is ok."<<endl;
          repl.error=EOK;
        }
        MinetSend(sock,repl);
        cs->state.SetState(CLOSED);
        cout<<"set state to closed"<<endl;
        clist.erase(cs);
        cout<<"CLOSING: Sending close to socket."<<endl;
        cout << repl << endl;
        
      }
      break;
      
    case FIN_WAIT1: {
      cout<<"mux handler, finwait1 state, sending last ack"<<endl;
      if(IS_FIN(flags) && IS_ACK(flags)) {
        cs->state.SetLastRecvd(seqNum+1);
        cs->state.SetLastAcked(ackNum);
        MakePacket(out_p, *cs, 0, 2);
        MinetSend(mux,out_p);
        cout << "activate timer" << endl;
        cs->bTmrActive = true;
        cs->timeout = Time()+5;
        cs->state.SetState(TIME_WAIT);
        cout<<"set state to timewait"<<endl;
      }
    }
    break;
    
    default:
      // Default, do nothing
      cout<<"mux handler, default state"<<endl;
      break;
    }
    cout << endl;
    }
  else { //NO CONNECTION
    cout<<"mux handler, no connection"<<endl;
    if(IS_FIN(flags)) {
    cout<<"mux handler, fin connection"<<endl;
      TCPState newState(1, CLOSED, 3);
      newState.SetLastRecvd(seqNum);
      newState.last_acked = (ackNum-1);
      ConnectionToStateMapping<TCPState> newMap(conn, Time(), newState, false);
      MakePacket(out_p, newMap, 0, 2);
      MinetSend(mux, out_p);
      firstSend = false;
      cout<<"FIN ACK sent."<<endl<<endl;
    }
    else if(IS_SYN(flags)) {
      cout<<"SYN."<<endl<<endl;
      cout << "Connection: " << conn << endl;
    }
  }
}//end muxhandler

void set_reply(SockRequestResponse &reply, SockRequestResponse req) {
  reply.type = STATUS;
  reply.connection = req.connection;
  reply.bytes = 0;
}

// Sock_handler function
void sock_handler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist) {
  cout<<"just entered sock handler"<<endl;
  Packet out_p;
  SockRequestResponse req,reply;
  Buffer buff;
  
  
  cout<<"In sock handler."<<endl;
  MinetReceive(sock, req);
  cout << "Socket request received." << endl;
  ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);

  cout<<"connection request: " << req<<endl;
    if(cs == clist.end()){//connection doesnt exist
    cout<<"Connection doesnt exist, entering first switch in sockhandler"<<endl;
    switch(req.type) {
      
      case ACCEPT:{//passive open
        cout<<"sockhander, no connection, accept case-PASSIVE OPEN"<<endl;
        TCPState newState(1, LISTEN, 3);
        ConnectionToStateMapping<TCPState> newMap(req.connection, Time(), newState, false);
        clist.push_back(newMap);
        set_reply(reply, req);
        reply.error = EOK;
        MinetSend(sock, reply);
      }
      break;
      
      case CONNECT:{//ACTIVEPIZZAINGMNSADA OPEN
        //set state to synsent
        //send syn packet
        cout<<"sockhandler, no connection, connect case - ACTIVE OPEn"<<endl;
        TCPState newState(1, SYN_SENT, 3);//change state to SYN_SENT
        ConnectionToStateMapping<TCPState> newMap(req.connection, Time()+.2, newState, true);
        MakePacket(out_p, newMap, 0, 1);//1 = SYN
        cout << "SYN packet created"<<endl;
        MinetSend(mux, out_p);


        newMap.state.SetLastSent(newMap.state.GetLastSent()+1);
        clist.push_back(newMap);
        set_reply(reply, req);
        reply.error = EOK;
        MinetSend(sock, reply);
      }
      break;
      
      case WRITE: {
        cout << "sockhandler, no connection, write case" << endl;
        set_reply(reply, req);
        reply.error = ENOMATCH;
        // Send to sock.
        MinetSend(sock, reply);
      }
      break;
    
      case STATUS: {
        cout<<"sockhandler, no connection, status case"<<endl;
      }
      break;
      
      case FORWARD: {
        cout<<"sockhandler, no connection, fwd case"<<endl;
      }
      break;
      
      case CLOSE: {
        cout<<"sockhandler, no connection, CLOSE case"<<endl;
        set_reply(reply, req);
        reply.error = ENOMATCH;
        // Send to sock
        MinetSend(sock, reply);
      }
      break;
      
      default:
      break;
    }
    cout << endl;
  }
    
 //theres a connection
  else {
    cout<<"Connection exists!"<< endl;
    // extract state of connection
    int state = cs->state.GetState();
    cout<<(*cs)<<endl;
    printState(cs);
    Buffer buff;
    
    cout << "in sockhandler, connection exists, entering switch" << endl;
    switch (req.type) {
      
      case STATUS: {
        cout<<"sockhandler, yes connection, status case"<<endl;
        if(ESTABLISHED == state) {
          // Number of bytes sent
          unsigned datasend = req.bytes;
          cs->state.RecvBuffer.Erase(0,datasend);
          if(0 != cs->state.RecvBuffer.GetSize()) {
                     // ERRORR!! didnt write
            cout << "data didn't write correctly" << endl;
            SockRequestResponse write (WRITE, cs->connection, cs->state.RecvBuffer, cs->state.RecvBuffer.GetSize(), EOK);
            MinetSend(sock,write);
          }
          else {
            cout << "data was successfully written!!!!" << endl;
          }
        }
      }
      break;
      
      case CONNECT:{
        cout<<"sockhandler, yes connection, connect case"<<endl;
      }
      break;
      
      case ACCEPT:{
        cout<<"sockhandler, yes connection, accept case"<<endl;
      }
      break;
      
      case WRITE: {
        cout<<"sockhandler, yes connection, WRITE case"<<endl;
        if(state == ESTABLISHED) {
          if(cs->state.SendBuffer.GetSize()+req.data.GetSize() > cs->state.TCP_BUFFER_SIZE) { // Send buff doesn't have enough space
            set_reply(reply, req);
            reply.error = EBUF_SPACE;
            MinetSend(sock, reply);
          }
          else { // There is enough space in send buff
            cs->state.SendBuffer.AddBack(req.data);
          }
          if(cs->state.last_sent - cs->state.last_acked < cs->state.rwnd) {
            if(cs->state.last_sent == cs->state.last_acked) { // No data on transition
              // Activate timer
              cout << "timer activated" << endl;
              cs->bTmrActive = true;
              cs->timeout = Time()+5;
              cs->state.tmrTries = 3;
            }
            unsigned int totalsend = 0;
            Buffer buff = cs->state.SendBuffer;
            buff.ExtractFront(cs->state.last_sent-cs->state.last_acked);
            unsigned int totaleft = buff.GetSize();
            // Max amount of data able to send
            unsigned int MAX_SENT = cs->state.GetN()-(cs->state.last_sent-cs->state.last_acked)-TCP_MAXIMUM_SEGMENT_SIZE;
            printf("data to be sent: %d,%d, max sent: %d\n",totaleft,totalsend,MAX_SENT);
            while(totaleft!=0 && totalsend < MAX_SENT) {
              unsigned int bytes = min(totaleft,TCP_MAXIMUM_SEGMENT_SIZE);// Data we send this time
              cout<<"Total data sent: " << totalsend<<", Number of bytes: "<<bytes<<endl;
              out_p = buff.Extract(0,bytes);
              MakePacket(out_p, *cs, bytes, 4,true,
              cs->state.GetLastAcked()+1+totalsend);

              MinetSend(mux, out_p);
              cs->state.SetLastSent(cs->state.GetLastSent()+bytes);
              totalsend += bytes;
              totaleft -= bytes;
            }
            reply.type = STATUS;
            reply.connection = req.connection;
            reply.bytes = totalsend;
            reply.error = EOK;
            MinetSend(sock, reply);
          }
        }
        else {
          cout<<"Invalid state."<<endl;
        }
      }
    break;
  
    case CLOSE: {
        cout<<"sockhandler, yes connection, CLOSE case"<<endl;
      if(ESTABLISHED == state) {
        cout<<"Established. User initiates the close action."<<endl;
        MakePacket(out_p, *cs, 0, 5);// Create FIN p
        cout << "FIN pkt created. " <<endl;
        MinetSend(mux,out_p);
        cs->state.SetLastSent(cs->state.GetLastSent()+1);
        cs->state.SetState(FIN_WAIT1);
        cout<<"set state to finwait1"<<endl;
      }
      else if(CLOSED == state) {
        set_reply(reply, req);
        reply.error = EOK;
        MinetSend(sock, reply);
        clist.erase(cs);
      }
      else {
        cout<<"Invalid state."<<endl;
      }
    }
    break;
    
    case FORWARD: {
        cout<<"sockhandler, yes connection, fwd case"<<endl;
    }
    break;
    
    default:
            cout<<"sockhandler, yes connection, DEFAULT case - dis a sad place to be"<<endl;
    break;
    }
  }
}

// Timeout_handler function
void timeout_handler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist) {
  Time now; // Current time
  list<ConnectionList<TCPState>::iterator> dellist;
  for(ConnectionList<TCPState>::iterator cs = clist.begin(); cs!=clist.end(); cs++) {
    if(!cs->bTmrActive) // Enter this conditional if timeout is not yet activated
      continue;
      if(now > cs->timeout || now == cs->timeout) { // Timeout occured
        cout<<"TIMEOUT :["<<endl;
      
        switch (cs->state.GetState()) {
          
          case SYN_RCVD: { // Waiting for last ACK
            if(cs->state.ExpireTimerTries()) { // Run out of tries, close the connection
              cout<<"reached max tries, close."<<endl<<endl;
              Buffer buff;
              SockRequestResponse reply(WRITE, cs->connection, buff, 0, ECONN_FAILED);
              MinetSend(sock, reply);
              cs->bTmrActive = false;
              cs->state.SetState(LISTEN);
            cout<<"set state to listen"<<endl;
            }

            else {
              cout<<"failed, resend synack"<<endl<<endl;
              Packet out_p;
              MakePacket(out_p, *cs, 0, 3);// Create SYN ACK p
              MinetSend(mux, out_p);
              cs->timeout = now+0.2;
            }
          }
          break;
          
          case SYN_SENT: {
            cout << "send syn, wait for synack" << endl;
            if(cs->state.ExpireTimerTries()) {// Run out of tries, close the connection
              cout<<"reached max tries, close the connection"<<endl;

              Buffer buff;
              SockRequestResponse reply(WRITE, cs->connection, buff, 0, ECONN_FAILED);
              MinetSend(sock, reply);
              cs->bTmrActive = false;
              cs->state.SetState(CLOSING);
              cout<<"set state to cloosing"<<endl;
            }
            else {
              cout<<"resend the syn"<<endl;;
              Packet out_p;
              MakePacket(out_p, *cs, 0, 1);
              MinetSend(mux, out_p);
              cout << "Set timer" << endl;
              cs->timeout = now+0.2;
            }
          }
          break;
          
          case TIME_WAIT: {
            cout<<"in timeout handler, timewait case, add connect to delete list"<<endl;
            dellist.push_back(cs);
          }
          break;
          
          case ESTABLISHED: {
            cout<<"in timeout handler, establsihed case"<<endl;
            if(cs->state.last_acked < cs->state.last_sent) {
              if(!cs->state.ExpireTimerTries()) {
                cout << "activate timer" << endl;
                cs->bTmrActive = true;
                cs->timeout = Time()+5;// Expires in 5 seconds
                unsigned int totalsend = 0;// Total data sent this time
                Buffer buff = cs->state.SendBuffer;// Copy buff
                // extract rid of data already sent
                buff = buff.ExtractFront(cs->state.last_sent-cs->state.last_acked);
                unsigned int totaleft = buff.GetSize();
                Packet out_p;
                // max sent is the max data b4 overflow in packet
                unsigned int maxSent = cs->state.GetN()-(cs->state.last_sent-cs->state.last_acked)-TCP_MAXIMUM_SEGMENT_SIZE;
                cs->state.SetLastSent(cs->state.GetLastAcked());
                while(totaleft!=0 && totalsend < maxSent) {
                  unsigned int bytes = min(totaleft,TCP_MAXIMUM_SEGMENT_SIZE);
                  cout<<"Total data sent: " << totalsend<<", Number of bytes: "<<bytes<<endl;
                  out_p = buff.Extract(0,bytes);
                  MakePacket(out_p, *cs, bytes, 4,true,cs->state.GetLastAcked()+1+totalsend);
                  MinetSend(mux, out_p);
                  cs->state.SetLastSent(cs->state.GetLastSent()+bytes);
                  totalsend += bytes;
                  totaleft -= bytes;
                }
              }
              else { // Already tried to retransmit 3 times and timed out 3 times
                cs->bTmrActive = false;
                cout<<"tried to retransmit 3 times. FAILED. timing out/closing="<<endl;
                SockRequestResponse reply(WRITE, cs->connection, Buffer(), 0, ECONN_FAILED); // Close connection
                MinetSend(sock, reply);
                dellist.push_back(cs);
              }
            }
            else { // No outstanding ACKs
              cout << "turn off the timer." << endl;
              cs->bTmrActive = false;
            }
          }
          break;
          
          default:
          break;
        }
        cout << endl;
      }
    }

    for(list<ConnectionList<TCPState>::iterator>::iterator it = dellist.begin(); it!=dellist.end();it++) {
      clist.erase(*it);
    }
}

void set_ip_header(IPAddress dest, IPAddress source, int pLength, IPHeader &ip_header, Packet &p) {
  // Set IP header
  ip_header.SetDestIP(dest);
  ip_header.SetSourceIP(source);
  ip_header.SetTotalLength(pLength);
  ip_header.SetProtocol(IP_PROTO_TCP);
  p.PushFrontHeader(ip_header);
}

void set_tcp_header(unsigned short source_port, unsigned short destination_port, unsigned char flags, ConnectionToStateMapping<TCPState> &a_mapping, Packet &p, bool customSeq, TCPHeader &tcp_header) {
  // Set TCP
  tcp_header.SetSourcePort(source_port, p);
  tcp_header.SetDestPort(destination_port, p);
  tcp_header.SetHeaderLen((TCP_HEADER_BASE_LENGTH / 4), p);//preventing overflow
  tcp_header.SetFlags(flags, p);
  tcp_header.SetAckNum(a_mapping.state.GetLastRecvd(), p);
  if(customSeq) {
    tcp_header.SetSeqNum(a_mapping.state.GetLastSent()+1, p);
  }
  else {
    tcp_header.SetSeqNum(a_mapping.state.GetLastAcked()+1, p);
  }
  tcp_header.SetUrgentPtr(0, p);
  tcp_header.SetWinSize(a_mapping.state.GetRwnd(), p);
  tcp_header.RecomputeChecksum(p);
  p.PushBackHeader(tcp_header);
  cout << "TCP Header information: ";
  tcp_header.Print(cout) << endl;
}


// MakePacket function
void MakePacket(Packet &p, ConnectionToStateMapping<TCPState> &a_mapping, int sizeOfData, int header, bool customSeq, int sequence) {
  
  cout<<"In IP Packet function: Creating a new IP p."<<endl;

  unsigned char flags = 0;
  int pLength = sizeOfData + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH;
  IPAddress source = a_mapping.connection.src;
  IPAddress destination = a_mapping.connection.dest;
  IPHeader ip_header;
  TCPHeader tcp_header;
  unsigned short source_port = a_mapping.connection.srcport;
  unsigned short destination_port = a_mapping.connection.destport;

  switch (header){
  
  case 1:
    cout << "Setting SYN only." << endl;
    SET_SYN(flags);
    break;
    
  case 2:
    cout << "Setting ACK only." << endl;
    SET_ACK(flags);
    break;

  case 3:
    cout << "Setting ACK ";
    SET_ACK(flags);
    cout << "and setting SYN." << endl;
    cout << "TCP header length: " << TCP_HEADER_BASE_LENGTH << endl;
    SET_SYN(flags);
    break;
    
  case 4:
    cout << "Setting PSH and ACK." << endl;
    SET_PSH(flags);
    SET_ACK(flags);
    break;

  case 5:
    cout << "Setting FIN only." << endl;
    SET_FIN(flags);
    break;

  case 6:
    cout << "Setting FIN ACK." << endl;
    SET_FIN(flags);
    SET_ACK(flags);
    break;

  case 7:
    SET_RST(flags);
    break;

  default:
    break;
  }
  
  set_ip_header(destination, source, pLength, ip_header, p);
  set_tcp_header(source_port, destination_port, flags, a_mapping, p, customSeq, tcp_header);

}

// Main function
int main(int argc, char * argv[]) {
  MinetHandle mux;
  MinetHandle sock;

  // Store connection information
  ConnectionList<TCPState> clist;

  MinetInit(MINET_TCP_MODULE);

  mux = MinetIsModuleInConfig(MINET_IP_MUX) ?
    MinetConnect(MINET_IP_MUX) :
    MINET_NOHANDLE;

  sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ?
    MinetAccept(MINET_SOCK_MODULE) :
    MINET_NOHANDLE;

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

while (MinetGetNextEvent(event) == 0) {
    cout<<endl<<endl<<"##########TCP#THE COOL PIZZA##################################################"<<endl;
    cout<<"############# PIZZA DELIVERY FOR YOU, SIR ####################################"<<endl;
    cout<<"##############################################################################"<<endl<<endl;
    if ((event.eventtype!=MinetEvent::Dataflow) || (event.direction!=MinetEvent::IN)) {
      MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
    }
    
    else {
      if (event.handle == mux) {
        // IP pkt arrival
        cout << "in main, going into muxhandler" << endl;
        // Call muxhandler function
        mux_handler(mux, sock, clist);
        cout << "in main, leaving mux handler "<< endl;
      }
      if (event.handle == sock) {
        // Sock request or response arrival
        cout << "in main, going into sockhandler" << endl;
        // Call sockhandler function
        sock_handler(mux, sock, clist);
        cout << "in main, leaving sockhandler "<< endl;
      }
      if (event.eventtype == MinetEvent::Timeout) {
        // Timeout
        cout << "in main, enter timeout handler "<< endl;
        // Call time_out handler function
        timeout_handler(mux, sock, clist);
        cout << "in main, leaving timeout handler "<< endl;
      }
    }
  }

  MinetDeinit();
  return 0;
}











// #include <sys/time.h>
// #include <sys/types.h>
// #include <unistd.h>

// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <arpa/inet.h>
// #include <sys/types.h>
// #include <sys/stat.h>
// #include <fcntl.h>
// #include <errno.h>
// #include "tcpstate.h"


// #include <iostream>

// #include "Minet.h"


// using std::cout;
// using std::endl;
// using std::cerr;
// using std::string;

// void MuxHandler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist);
// void SockHandler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist);
// Packet MakePacket(ConnectionToStateMapping<TCPState> cs, unsigned int cmd, unsigned short data_len);

// //for the making of packets
// #define SEND_SYNACK 1
// #define SEND_SYN 2

// int main(int argc, char *argv[])
// {
//   MinetHandle mux, sock;

//   ConnectionList<TCPState> clist;


//   MinetInit(MINET_TCP_MODULE);

//   mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
//   sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

//   if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
//     MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
//     return -1;
//   }

//   if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
//     MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
//     return -1;
//   }

//   MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

//   MinetEvent event;

//   while (MinetGetNextEvent(event)==0) {
//     // if we received an unexpected type of event, print error
//     if (event.eventtype!=MinetEvent::Dataflow 
// 	|| event.direction!=MinetEvent::IN) {
//       MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
//     // if we received a valid event from Minet, do processing
//     } else {
//       //  Data from the IP layer below  //
//       if (event.handle==mux) {
//       	MuxHandler(mux, sock, clist);
//       }
//       //  Data from the Sockets layer above  //
//       if (event.handle==sock) {
//         SockHandler(mux, sock, clist);
//       }
//     }
//   }
//   return 0;
// }

// void MuxHandler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist) {

//   /* VARIABLES */
//   //packet and headers
//   Packet p;
//   TCPHeader tcph;
//   IPHeader iph;
//   unsigned tcphlen;
//   unsigned iphlen;

//   //received packet properties
//   unsigned short total_len; //length of packet w/ headers
//   unsigned short data_len; //length of data
//   Buffer data;  
//   bool checksumok;
//   unsigned char flags; //to hold syn, fin, rst, psh flags of packet p
//   unsigned int seqnum;
//   unsigned int acknum;


//   /* BEGIN */

//   //grab packet from ip
//   MinetReceive(mux,p);

//   //get header length estimates
//   tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
//   iphlen=IPHeader::EstimateIPHeaderLength(p);

//   //extract headers...
//   p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
//   p.ExtractHeaderFromPayload<IPHeader>(iphlen);

//   //store headers in tcph and iph
//   tcph=p.FindHeader(Headers::TCPHeader);
//   iph=p.FindHeader(Headers::IPHeader);

//   //check if checksum is correct 
//   checksumok=tcph.IsCorrectChecksum(p);

//   //length of headers
//   iph.GetTotalLength(total_len); //total length including ip header
//   data_len = total_len - iphlen - tcphlen; //actual data length
  
//   //get data
//   data = p.GetPayload().ExtractFront(data_len);

//   //fill out a blank reference connection object
//   Connection c;

//   // note that this is flipped around because
//   // "source" is interepreted as "this machine"

//   //info from iph
//   iph.GetDestIP(c.src);
//   iph.GetSourceIP(c.dest);
//   iph.GetProtocol(c.protocol);

//   //info from tcph
//   tcph.GetDestPort(c.srcport);
//   tcph.GetSourcePort(c.destport);
//   tcph.GetFlags(flags);
//   tcph.GetSeqNum(seqnum);
//   tcph.GetAckNum(acknum);
//   // tcph.GetWinSize();
//   // tcph.GetUrgentPtr();
//   // tcph.GetOptions();

//   //find ConnectionToStateMapping in list
//   ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);

//   //fetch state from the ConnectionToStateMapping
//   unsigned int state = (*cs).state.GetState();

//   if (cs!=clist.end() && checksumok) {
//     SockRequestResponse response;
//     Packet ret_p;
//     switch(state) {

//       case CLOSED:
//         cout << "currently closed :(" << endl;
//         break;

//       case LISTEN:
//         cout << "listening wheee" << endl;

//         //if SYN bit is set
//         if(IS_SYN(flags)){

//           /*NOTE THAT WE ARE DOING STOP AND WAIT ATM. 
//           COMMENTED OUT SET COMMANDS ARE FOR GBN */    



// /* MAKE SYNACK PACKET */
//           Packet ret_p;
//           IPHeader ret_iph;
//           TCPHeader ret_tcph;
//           unsigned char my_flags;
//           unsigned int my_seqnum; 
//           TCPOptions ops;

//           /* MAKE IP HEADER */

//           ret_iph.SetProtocol(IP_PROTO_TCP);
//           ret_iph.SetSourceIP((*cs).connection.src);
//           ret_iph.SetDestIP((*cs).connection.dest);
//           ret_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH);
//           // push it onto the packet
//           ret_p.PushFrontHeader(ret_iph);

//           /*MAKE TCP HEADER*/
//           //variables
//           my_seqnum = rand(); 

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
//           ops.len = TCP_HEADER_OPTION_MAX_LENGTH
//           ret_tcph.SetOptions(0, ret_p);

//           //recompute checksum with headers in
//           ret_tcph.RecomputeChecksum(ret_p);

//           //make sure ip header is in front
//           ret_p.PushBackHeader(ret_tcph);

//           /* end header */













//           //update state
//           //need to update state after every state
//           (*cs).state.SetState(SYN_RCVD);
//           //(*cs).state.SetTimerTries(SYN_RCVD);
//           //(*cs).state.SetLastAcked(SYN_RCVD);
//           (*cs).state.SetLastSent(my_seqnum);
//           //(*cs).state.SetSendRwnd(SYN_RCVD);
//           (*cs).state.SetLastRecvd(seqnum, 0); //no data in syn packet

//           //make return packet
//           //ret_p = MakePacket(*cs, SEND_SYNACK, 0);

//           //use minetSend for above packet and mux
//           MinetSend(mux, ret_p);
//         }

//         break;

//       case SYN_RCVD:
//         // Necessary conditions to move into ESTABLISHED: 
//         // SYN bit not set, ACK bit set, seqnum == client_isn+1, ack == server_isn+1
//         cout << "currently in syn_rcvd" << endl;
//         // if(IS_SYN(flags)==false 
//         //   && IS_ACK(flags)==true
//         //   && seqnum==(*cs).state.GetLastRecvd()+1 
//         //   && acknum==(*cs).state.GetLastSent()+1) {

//           // /* FORWARD DATA TO SOCKET */
//           // cout << "inside the logic" << endl;
//           // response.type = WRITE;
//           // response.connection = c;
//           // response.data = data;
//           // response.bytes = data_len; 
//           // MinetSend(sock, response);

//           /* ACK PACKET - IMPLEMENT AFTER TIMERS ARE IN? */

//           //update state
//           (*cs).state.SetState(ESTABLISHED);
//                   cout << "set state to estab in synrcvd" << endl;

//           //(*cs).state.SetTimerTries(SYN_RCVD);
//           (*cs).state.SetLastAcked(acknum-1);
//           //(*cs).state.SetLastSent(my_seqnum);
//           //(*cs).state.SetSendRwnd(SYN_RCVD);
//           (*cs).state.SetLastRecvd(seqnum, data_len); //account for length of data


//        // }

//         break;

//       case SYN_SENT:
//         cout << "currently at syn_sent" << endl;
//         break;

//       case ESTABLISHED:
//         cout << "current state: established" << endl;

//         /* FORWARD DATA TO SOCKET */
//         response.type = WRITE;
//         response.connection = c;
//         response.data = data;
//         response.bytes = data_len; 
//         MinetSend(sock, response);

//         /* ACK PACKET - IMPLEMENT AFTER TIMERS ARE IN? */

//         //update state
//         //(*cs).state.SetState(ESTABLISHED);
//         //(*cs).state.SetTimerTries(SYN_RCVD);
//         if(IS_ACK(flags)){
//           (*cs).state.SetLastAcked(acknum-1);
//         }
//         //(*cs).state.SetLastSent(my_seqnum);
//         //(*cs).state.SetSendRwnd(SYN_RCVD);
//         (*cs).state.SetLastRecvd(seqnum, data_len); //account for length of data

//         break;

//       case SEND_DATA:

//         break;

//       case CLOSE_WAIT:

//         break;

//       case FIN_WAIT1:

//         break;

//       case CLOSING:

//         break;

//       case LAST_ACK:

//         break;

//       case FIN_WAIT2:

//         break;

//       case TIME_WAIT:

//         break;


//     }//switch

//   }//if (cs!=clist.end())


// }//muxhandler


// void SockHandler(const MinetHandle &mux, const MinetHandle &sock, ConnectionList<TCPState> &clist) {

//     //variables
//     SockRequestResponse request;
//     SockRequestResponse response;
//     ConnectionToStateMapping<TCPState> new_cs;
//     unsigned int timertries;
//     unsigned int initial_seq_num;
//     TCPState accept_c; //the new state we add to the list
//     Packet ret_p;

//     //grab request from socket
//     MinetReceive(sock, request);

//     //ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);

//     //switch based on what socket wants to do
//     switch(request.type){

//       case CONNECT:
//         cout << "attempting to add a new connection :(" << endl;
//         /* ADD A NEW CONNECT CONNECTION */

//         // first initialize the ConnectionToStateMapping
//         //Create a new accept connection - will start at SYN_sent
//         //the new connection is what's specified by the request from the socket
//         new_cs.connection = request.connection;

//         //generate new state
//         //implement timertries eventually, right now set to 1?
//         timertries = 1;
//         initial_seq_num = rand();
//         accept_c = TCPState(initial_seq_num, SYN_SENT, timertries);
        
//         //fill out state of ConnectionToStateMapping
//         new_cs.state = accept_c;

//         //set state
//         new_cs.state.SetLastSent(initial_seq_num);
//         //(*cs).state.SetSendRwnd(SYN_RCVD);


//         //add new ConnectionToStateMapping to list
//         clist.push_front(new_cs);

//         //send SYN packet
//         ret_p = MakePacket(new_cs, SEND_SYN, 0);
//         MinetSend(mux, ret_p);

//         //send a STATUS to the socket with only error code set

//         response.type = STATUS;
//         response.error = EOK;
//         MinetSend(sock, response);    

//         break;

//       case ACCEPT:
//         cout << "accepting a new connection :D" << endl;
//         /* ADD A NEW ACCEPT CONNECTION */

//         // first initialize the ConnectionToStateMapping
//         //Create a new accept connection - will start at LISTEN
//         //the new connection is what's specified by the request from the socket
//         new_cs.connection = request.connection;

//         //generate new state
//         //implement timertries eventually, right now set to 1?
//         timertries = 1;
//         accept_c = TCPState(rand(), LISTEN, timertries);
        
//         //fill out state of ConnectionToStateMapping
//         new_cs.state = accept_c;
//         cout << "attempting to push :(" << endl;

//         //add new ConnectionToStateMapping to list
//         clist.push_front(new_cs);
//         cout << "pushed? :(" << endl;

//         //send a STATUS to the socket with only error code set
//         response.type = STATUS;
//         response.error = EOK;
//         MinetSend(sock, response);        
//         cout << "exit accept:(" << endl;

//         break;

//       case WRITE:

//         break;

//       case FORWARD:

//         break;

//       case CLOSE:

//         break;

//       case STATUS:

//         break;

//     }//switch
// }//sockhandler

// /* THIS FUNCTION ASSSUMES STATE HAS ALREADY BEEN UPDATED */
// Packet MakePacket(ConnectionToStateMapping<TCPState> cs, unsigned int cmd, unsigned short data_len) {
//     /* MAKE PACKET */
//   Packet ret_p;

//   /* MAKE IP HEADER */
//   IPHeader ret_iph;

//   ret_iph.SetProtocol(IP_PROTO_TCP);
//   ret_iph.SetSourceIP(cs.connection.src);
//   ret_iph.SetDestIP(cs.connection.dest);
//   ret_iph.SetTotalLength(TCP_HEADER_BASE_LENGTH+IP_HEADER_BASE_LENGTH+data_len);
//   // push it onto the packet
//   ret_p.PushFrontHeader(ret_iph);

//   /*MAKE TCP HEADER*/
//   TCPHeader ret_tcph;

//   //common settings
//   ret_tcph.SetSourcePort(cs.connection.srcport, ret_p);
//   ret_tcph.SetDestPort(cs.connection.destport, ret_p);
//   ret_tcph.SetSeqNum(cs.state.GetLastSent(), ret_p);

//   //flags and non-common settings
//   unsigned char my_flags;
//   switch(cs.state.GetState()) {

//     case SEND_SYN:
//       SET_SYN(my_flags);
//       ret_tcph.SetFlags(my_flags, ret_p);
//       break;

//     case SEND_SYNACK:
//       ret_tcph.SetAckNum(cs.state.GetLastRecvd()+1, ret_p); 

//       SET_SYN(my_flags);
//       SET_ACK(my_flags);
//       ret_tcph.SetFlags(my_flags, ret_p);
//       break;
//   }

//   ret_tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, ret_p);
//   // ret_tcph.SetWinSize(0, ret_p);
//   // ret_tcph.SetUrgentPtr(0, ret_p);
//   // ret_tcph.SetOptions(0, ret_p);

//   //recompute checksum with headers in
//   ret_tcph.RecomputeChecksum(ret_p);

//   //make sure ip header is in front
//   ret_p.PushBackHeader(ret_tcph);

//   return ret_p;
// }

// // /* MAKE SYNACK PACKET */
// //           Packet ret_p;

// //           /* MAKE IP HEADER */
// //           IPHeader ret_iph;

// //           ret_iph.SetProtocol(IP_PROTO_TCP);
// //           ret_iph.SetSourceIP((*cs).connection.src);
// //           ret_iph.SetDestIP((*cs).connection.dest);
// //           ret_iph.SetTotalLength(TCP_HEADER_LENGTH+IP_HEADER_BASE_LENGTH);
// //           // push it onto the packet
// //           ret_p.PushFrontHeader(ret_iph);

// //           /*MAKE TCP HEADER*/
// //           //variables
// //           TCPHeader ret_tcph;
// //           unsigned int my_seqnum = rand(); 
// //           unsigned char my_flags;

// //           ret_tcph.SetSourcePort((*cs).srcport, ret_p);
// //           ret_tcph.SetDestPort((*cs).destport, ret_p);
// //           ret_tcph.SetSeqNum(my_seqnum, ret_p);
// //           ret_tcph.SetAckNum(seqnum+1, ret_p); //set to isn+1

// //           //set flags
// //           SET_SYN(my_flags);
// //           SET_ACK(my_flags);
// //           ret_tcph.SetFlags(my_flags, ret_p);

// //           ret_tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH, ret_p);
// //           // ret_tcph.SetWinSize(0, ret_p);
// //           // ret_tcph.SetUrgentPtr(0, ret_p);
// //           // ret_tcph.SetOptions(0, ret_p);

// //           //recompute checksum with headers in
// //           ret_tcph.RecomputeChecksum(ret_p);

// //           //make sure ip header is in front
// //           ret_p.PushBackHeader(ret_tcph);

// //           /* end header */