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

#include <ctime>
#include <cstdlib>
#include <iostream>

#include "Minet.h"
#include "tcpstate.h"
#include "tcp.h"
#include "sockint.h"

using std::cout;
using std::endl;
using std::cerr;
using std::string;

//Prototype
//create packet
void sendPacket(const MinetHandle &mux, ConnectionToStateMapping<TCPState>& constate, int dataLen, int signal, bool sender = false);
void receivePacket(const MinetHandle &mux, const MinetHandle &sock, Buffer recv_data, unsigned char flags, unsigned int ackNum, unsigned int seqNum, unsigned short tcpLen, ConnectionToStateMapping<TCPState>& constate, Connection c);
void writeToApplication( const MinetHandle & sock, Connection c, const Buffer &b );
void EmptyWriteToApplication( const MinetHandle & sock, Connection c);
//void testPacket(Packet &packet);//test use only
void hardCodeListen(ConnectionToStateMapping<TCPState>& constate, unsigned short srcport, Time timeout);
unsigned int generateISN(void);
//My signal representation for createPacket();
const int SIG_SYN_ACK = 0;
const int SIG_ACK = 1;
const int SIG_SYN = 2;
const int SIG_FIN = 3;
const int SIG_FIN_ACK = 4;
const int SIG_RST = 5;
bool handshake = true; // before establish connection
//Connection state representation for server&client
enum StateMapping
{
  CLOSE_CONNECTION,
  OPEN_CONNECTION,
  TIME_WAIT_CONNECTION
};

int main(int argc, char *argv[])
{
  MinetHandle mux, sock;//Multiplexor and Socket

  ConnectionList<TCPState> clist; //Open connections
  ConnectionList<TCPState> clisten_list; //Listening connections
  MinetInit(MINET_TCP_MODULE);//initialize tcp module

  //MinetIsModuleConfig(): Check to see if lower module is on the run time configuration
  //if its in configuration, issue MinetConnect() for this module
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
  double timeout = 1; //now we handle timeout

  cerr<<"TCP start working now"<<endl;//test

  while (MinetGetNextEvent(event, timeout)==0) {
    // if we received an unexpected type of event, print error
    if (event.eventtype!=MinetEvent::Dataflow
|| event.direction!=MinetEvent::IN) {
      MinetSendToMonitor(MinetMonitoringEvent("[Unknown event] Ignored!"));
    // if we received a valid event from Minet, do processing
    } else if (event.eventtype == MinetEvent::Timeout) {
//TODO handle timeout
}
     else{
      cerr<<"Now start hande mux or sock!"<<endl;
      if (event.handle==mux) {
Packet p;
        unsigned short packetLen;
unsigned short segmentLen; //segment length (actual data + tcp header)
unsigned short tcpLen;
        unsigned char ipHeaderLen;
        unsigned char tcpHeaderLen;
unsigned int ackNum;
unsigned int seqNum;
short unsigned int srcPort;
short unsigned int destPort;
unsigned char flags;
unsigned short windowSize;

        //receive packet
MinetReceive(mux,p);
        cerr<<endl<<"Package received from below!"<<endl;
//estimate tcp header length
unsigned tcpHeaderlenEst=TCPHeader::EstimateTCPHeaderLength(p);
p.ExtractHeaderFromPayload<TCPHeader>(tcpHeaderlenEst);

//Find IP header and judge if we need to drop packet
IPHeader ipHeader=p.FindHeader(Headers::IPHeader);
ipHeader.GetTotalLength(packetLen);
ipHeader.GetHeaderLength(ipHeaderLen);
ipHeaderLen<<=2;// *= 4;

if((unsigned)(packetLen - ipHeaderLen) < (unsigned)TCP_HEADER_BASE_LENGTH)
{
cerr << "[Short packet]" << packetLen << " bytes dropped!" << endl;
return -1;
}

TCPHeader tcpHeader=p.FindHeader(Headers::TCPHeader);

if( !ipHeader.IsChecksumCorrect() || !tcpHeader.IsCorrectChecksum(p) )
{
cerr << "[Bad checksum] Packet dropped!" << endl;
return -1;
}

        Connection c;

//Extract data from packet
tcpHeader.GetSourcePort(srcPort);
tcpHeader.GetDestPort(destPort);

tcpHeader.GetSeqNum(seqNum);

tcpHeader.GetAckNum(ackNum);

tcpHeader.GetFlags(flags);//now we know what we need to do

tcpHeader.GetWinSize(windowSize);

tcpHeader.GetHeaderLen(tcpHeaderLen);
tcpHeaderLen<<=2; //*= 4;

tcpLen = packetLen - ipHeaderLen - tcpHeaderLen + ( ( IS_FIN(flags) || IS_SYN(flags) ) ? 1 : 0 );
//segmentLen = packetLen - ipHeaderLen - tcpHeaderLen;
segmentLen = packetLen - tcpHeaderLen - ipHeaderLen;//IP_HEADER_BASE_LENGTH;
cout << "Ip len = "<<segmentLen<<endl;
//cerr << "TCP Packet: IP Header is "<<ipHeader<<endl; //TEST
//cerr << "TCP Header is "<<tcpHeader <<endl; //TEST

//Flip around, change source to "this machine", destination is the machine we receive packet from
//Handle IP header
ipHeader.GetDestIP(c.src);
ipHeader.GetSourceIP(c.dest);
ipHeader.GetProtocol(c.protocol);
tcpHeader.GetDestPort(c.srcport);
tcpHeader.GetSourcePort(c.destport);
Buffer &recvdata = p.GetPayload().ExtractFront(segmentLen);
        cout << "ACK: "<<ackNum<<". Seq: "<<seqNum<<endl;
//Demultiplexing packet, first search open connection list
        ConnectionList<TCPState>::iterator cs;
//server first bind to and listen at a port if receive SYN only
if(IS_SYN(flags)&&!IS_ACK(flags))
{
          Connection listen;
listen.src = MyIPAddr;
listen.srcport = c.srcport;//itself
listen.destport = 0;//nothing
listen.dest = IP_ADDRESS_LO; //0.0.0.0
listen.protocol = IP_PROTO_TCP;

TCPState newState(generateISN(), LISTEN, 3);
ConnectionToStateMapping<TCPState> newMapping(listen, Time()+5, newState, false);
newMapping.bTmrActive = false; //stop timer
//newMapping.state.SetLastRecvd(seqNum);
clist.push_front(newMapping);
cerr<<"[SYN RCVD]We bind a port to listen! First handshake OK"<<endl;
if(tcpHeader.IsCorrectChecksum(p)) {
cs = clist.FindMatchingSource(c);
cerr<<"Searching for the listening port!"<<endl;
if(cs != clist.end()) {
if(cs->state.GetState() == LISTEN)
{
cerr<<"[First] Now we handle listen!"<<endl;
(*cs).state.SetState(SYN_RCVD);
(*cs).state.last_acked = (*cs).state.last_sent-1;
(*cs).state.SetLastRecvd(seqNum+1);
(*cs).bTmrActive = true;
(*cs).timeout=Time() + 5;
(*cs).connection =c;
//TCPState newState(generateISN(), SYN_RCVD, 3);
//newState.last_recvd = seqNum + 1;
             //newState.SetSendRwnd(windowSize);
             ConnectionToStateMapping<TCPState> &newMapping = *cs;//(c, Time()+80, newState, true);//start timeout feature
//2nd handshake
sendPacket(mux, newMapping, 0, SIG_SYN_ACK);
cerr<<" [SYN_ACK sent] 2nd handshake OK, last received: "<<newState.last_recvd<<endl;
//clist.push_back(newMapping);
}
}
} else cerr<<"Packet error!"<<endl;
}

//if(cs == clist.end())
//cerr<<"connection not found!"<<endl;
else
{
cerr<<"Now we start searching connectionlist!"<<endl;
          //Demultiplexing packet, first search open connection list
          cs = clist.FindMatching(c);//if source matchs(server ip etc), then continue
if (cs!=clist.end()) {
cerr<<"Now start to working on mux states"<<endl;
//Now handle connection state for open connection list
ConnectionToStateMapping<TCPState> &connState = *cs;
unsigned int currentState = connState.state.GetState();
//StateMapping state_map = CLOSE_CONNECTION;
connState.state.rwnd = windowSize;
//cerr<<"Current state number: "<<currentState;
connState.state.SetLastRecvd(seqNum, segmentLen); //update lastrecvd
switch (currentState) {
case CLOSED:
{
cerr<< "Receiver wait to be open"<<endl;
}
break;


case LISTEN:
{
cerr<<"Now we handle listen!"<<endl;
             //reset first
/* connState.state.SetLastSent(0);
connState.state.SetLastRecvd(0);
connState.state.SetLastAcked(0);

if (IS_ACK(flags))
{
//TODO: RST
}
else if (IS_SYN(flags))
{
cerr<<"[SYN received]"<<endl;
connState.state.SetState(SYN_RCVD);
connState.connection =c;
//Handle timer
//connState.bTmrActive = true;
//connState.timeout = time()+80;
connState.state.SetLastRecvd(seqNum);
connState.state.SetSendRwnd(windowSize); //sender window size
// "2nd" handshake, from server to client
sendPacket(mux, connState, 0, SIG_SYN_ACK);
cerr<<"[SYN_ACK Sent]"<<endl;
//Update last sent
connState.state.SetLastSent(connState.state.GetLastSent()+1);
cerr<<"[LastSent: "<<connState.state.GetLastSent()<<"]"<<endl;
}*/
}
break;

case SYN_RCVD:
{
cerr<<"Handle SYN_RCVD state"<<endl;
if(IS_ACK(flags)){
if(connState.state.GetLastSent()+1 == ackNum)
{
//receivePacket(mux, sock,recvdata, flags, ackNum, seqNum, tcpLen, connState, c);
cerr<<" [Recieved ACK] Connection transitioned from SYN_RCVD to ESTABLISHED!"<<endl;
connState.state.SetState(ESTABLISHED);
connState.state.SetLastAcked(ackNum);
connState.state.SetSendRwnd(windowSize);
connState.bTmrActive = false; //close timer
EmptyWriteToApplication(sock,c);
//state_map = OPEN_CONNECTION;
}
}
/* else if(IS_RST(flags)){ //reset flag
cerr<<" [Reset] Connection transitioned from SYN_RCVD to LISTEN"<<endl;
connState.state.SetState(LISTEN);
connState.bTmrActive = false;
}*/
}
break;

case SYN_SENT:
{
cerr<<"Handle SYN_SENT state"<<endl;
sendPacket(mux, connState, 0, SIG_ACK);
if (IS_SYN(flags) && IS_ACK(flags)){
connState.state.SetLastRecvd(seqNum+1);
cout<<" Set last ACKed: "<<((connState.state.SetLastAcked(ackNum))? "Succeed!":"Failed!")<<endl;
connState.state.SetSendRwnd(windowSize);//setup sender window size
sendPacket(mux,connState,0,SIG_ACK);
//3rd HandShake
cerr<<" [ACK Sent] Succeed! Connection transitioned from SYN_SET to ESTABLISHED!"<<endl;
connState.bTmrActive = false;//close timer
connState.state.SetState(ESTABLISHED);
EmptyWriteToApplication(sock,c);
EmptyWriteToApplication(sock,c);//in case drop packet!
//state_map = OPEN_CONNECTION;
}
else if (IS_SYN(flags)&&!IS_ACK(flags)){
connState.state.SetLastRecvd(seqNum); //update last received
sendPacket(mux, connState, 0, SIG_ACK); //send an ack
cerr<<" [Recieved SYN] Connection transitioned from SYN_SENT to SYN_RCVD!"<<endl;
                      connState.state.SetState(SYN_RCVD);
connState.state.SetLastSent(connState.state.GetLastSent()+1); //update last sent
}
else if(IS_FIN(flags) && IS_ACK(flags)){
//TODO: close
}
}
break;

case CLOSE_WAIT:
{
receivePacket(mux, sock,recvdata, flags, ackNum, seqNum, tcpLen, connState, c);//TODO: ignore data
//state_map = OPEN_CONNECTION;
}

case SYN_SENT1:
{
cerr<<"Handle SYN_SENT1 state: nothing to do"<<endl;
}
break;

case ESTABLISHED:
{
cerr<<"Handle ESTABLISHED state"<<endl;
receivePacket(mux, sock,recvdata, flags, ackNum, seqNum, tcpLen, connState, c);
//state_map = OPEN_CONNECTION;
if (IS_PSH(flags))//push data to app level immediately
{
if(seqNum == connState.state.GetLastRecvd()&&tcpHeader.IsCorrectChecksum(p)) {
cout<<" [Receive data succeed] Ready to push!"<<endl;
connState.state.SetLastRecvd(seqNum+segmentLen);
connState.state.SetLastAcked(ackNum);
if(connState.state.GetRwnd() >= segmentLen) {//sufficient space in receive buffer
connState.state.RecvBuffer.AddBack(recvdata);
writeToApplication(sock, c, recvdata);
}
else {
connState.state.SetLastRecvd(seqNum); //go back
}
sendPacket(mux,connState, 0, SIG_ACK);
}
else { //abnormal packet
sendPacket(mux,connState, 0, SIG_ACK);
}
}
else if(IS_FIN(flags))
{
connState.state.SetLastRecvd(seqNum+1);
sendPacket(mux, connState, 0, SIG_FIN_ACK);
//EmptyWriteToApplication(sock,c);
cerr<<" [Received FIN] transfer from ESTABLISHED to LAST_ACK"<<endl;
connState.state.SetState(LAST_ACK);
}
else if (IS_ACK(flags))
{
cerr<<" [Received only ACK]" << endl;
if (ackNum == connState.state.GetLastAcked()+1){
cerr<<" [DUPLICATE]" << endl;
}
else { //turn off timer
connState.state.SetLastRecvd((unsigned int)seqNum+segmentLen);
if(connState.state.SetLastAcked(ackNum)) {
cout<<" [Correct ACK] Turn off timer!"<<endl;
connState.bTmrActive = false;
}
}
}
}
break;

case FIN_WAIT1:
{
//receivePacket(mux, sock,recvdata, flags, ackNum, seqNum, tcpLen, connState, c);

// if(IS_ACK(flags) && (ackNum==conState.state.last_recvd));

}
break;
case SEND_DATA:
{
;
}

case FIN_WAIT2:
{
;
}

case CLOSING:
{
if (IS_FIN(flags))
;
}
break;

case LAST_ACK:
{
cerr<<"Handle LAST_ACK state!"<<endl;
//receivePacket(mux, sock,recvdata, flags, ackNum, seqNum, tcpLen, connState, c);// ignore data
if (!IS_FIN(flags)&&IS_ACK(flags))//&&connState.state.last_recvd)
{
EmptyWriteToApplication(sock,c);
connState.state.SetState(CLOSED);
clist.erase(cs); //erase
//state_map=CLOSE_CONNECTION;
cerr<<"[Recieved ACK] Connection transitioned from LAST_ACK to CLOSED, erased!"<<endl;
//No need to send anything, just "CLOSE".
//since this is the "last" ack
}
}
break;

case TIME_WAIT:
{
cerr<<"[Error] Not a valid connection state!";
}
default:
cerr<<"[Error] Not a valid connection state!";
}//end of switch
//handle connection
/* !not in use! we combing two list into one
ConnectionToStateMapping<TCPState> newMapping;

switch (state_map)
{
case CLOSE_CONNECTION:
break;
case OPEN_CONNECTION:
newMapping = ConnectionToStateMapping<TCPState>(c, Time() + 80, connState.state, false);
clist.push_back(newMapping);
break;
case TIME_WAIT_CONNECTION:
break;
}

*/
/*cs = ctime_wait_list.FindMatching(c);
if (cs!= ctime_wait_list.end())
{
continue;//TODO:handle time wait connection process
}*/

//If search failed, go to listening connection
//cs = clisten_list.FindMatchingSource(c);
        //cs = clisten_list.FindMatching(c);
/*!not in use! we combine two list into one
if(cs!= clisten_list.end())
{
cerr<<"Now we handle listen!"<<endl;
ConnectionToStateMapping<TCPState> &connState = *cs;
unsigned int currentState = connState.state.GetState();
if (currentState == LISTEN)
{
//reset first
connState.state.SetLastSent(0);
connState.state.SetLastRecvd(0);
connState.state.SetLastAcked(0);

if (IS_ACK(flags))
{
;//TODO:RST
}
else if (IS_SYN(flags))
{
cerr<<"[SYN received]"<<endl;

TCPState newState(generateISN(), SYN_RCVD, 3); //generate a new state
//turn on timer
//newState.bTmrActive = true;

newState.last_recvd = seqNum;
newState.SetSendRwnd(windowSize);
ConnectionToStateMapping<TCPState> newMapping(c, Time()+80, newState, false);

//2nd handshake, from server to client
sendPacket(mux, newMapping, 0, SIG_SYN_ACK);
cerr<<"[SYN_ACK Sent]"<<endl;
//add the new mapping to open connection list
clist.push_back(newMapping);
//connState.state.SetState(SYN_RCVD); //we just received a SYN, change state
}
}
continue;
}*/
//else
//{
/*MinetSendToMonitor(MinetMonitoringEvent("Unknown port, sending ICMP error message"));
IPAddress source;
ipHeader.GetSourceIP(source);
ICMPPacket error(source,DESTINATION_UNREACHABLE,PORT_UNREACHABLE,p);
MinetSendToMonitor(MinetMonitoringEvent("ICMP error message has been sent to host"));
MinetSend(mux, error);*/
}//end of connection list handling
       }//end of else
//else cerr<<"Cannot find port"<<endl;
      }//end of handling mux

      // Data from the Sockets layer above //
      if (event.handle==sock) {
//A SockRequestResponse
//contains a request type, a Connection , a Buffer containing data,
//a byte count, and an error code.
cerr <<"App level request response!"<<endl;
SockRequestResponse s;//first handle unserialization
MinetReceive(sock,s);
cerr << "Received Socket Request:" << s << endl;

ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);
        //if(cs == clist.end())
        // cs = clisten_list.FindMatching(s.connection);

switch (s.type) {
case CONNECT: //active open to remote, client
{
cerr<<"Handle socket request state CONNECT"<<endl;
unsigned int timeTries = 3; //try 3 times, default

TCPState newState = TCPState(generateISN(), SYN_SENT, timeTries);

//Connection c = s.connection;
//ConnectionToStateMapping<TCPState> connState(c, Time()+80, newState, false);
ConnectionToStateMapping<TCPState> connState;
connState.connection = s.connection;
connState.state = newState;
connState.state.SetLastSent(connState.state.GetLastSent()+1);

//for active open, send a SYN packet
sendPacket(mux, connState, 0, SIG_SYN);

clist.push_front(connState);

//send a status response
SockRequestResponse repl;
repl.connection = s.connection;
repl.type=STATUS;
repl.bytes =0;
repl.error=EOK;
MinetSend(sock,repl);
}
break;

case ACCEPT: //passive open from remote,server listening
{
cerr<<"Handle socket request state ACCEPT";
if ((*cs).state.GetState() != FIN_WAIT1)
{
unsigned int timeTries = 3;
// passive open, new ISN for server side
TCPState newState = TCPState(generateISN(), LISTEN, timeTries);

ConnectionToStateMapping<TCPState> connState(s.connection, Time()+80, newState, false);
clist.push_front(connState);

SockRequestResponse repl;// handle serialization
repl.type=STATUS;
repl.connection=s.connection;
// buffer is zero byte
repl.bytes=0;
repl.error=EOK;
MinetSend(sock,repl);
}
}
break;
// case SockRequestResponse::WRITE:
case WRITE:
{
//TODO: connection refer to previous CONNECT and ACCEPT pp15
unsigned bytes=s.data.GetSize();
// create the payload of the packet
Packet p(s.data.ExtractFront(bytes));
// Make the IP header first since we need it to do the tcp checksum
IPHeader ih;
ih.SetProtocol(IP_PROTO_TCP);
ih.SetSourceIP(s.connection.src);
ih.SetDestIP(s.connection.dest);
//ih.SetTotalLength(bytes+TCP_HEADER_LENGTH+IP_HEADER_BASE_LENGTH);TODO
// push it onto the packet
p.PushFrontHeader(ih);
// Now build the TCP header
// notice that we pass along the packet so that the udpheader can find
// the ip header because it will include some of its fields in the checksum
TCPHeader th;
th.SetSourcePort(s.connection.srcport,p);
th.SetDestPort(s.connection.destport,p);
//th.SetLength(UDP_HEADER_LENGTH+bytes,p);TODO
// Now we want to have the tcp header BEHIND the IP header
p.PushBackHeader(th);
MinetSend(mux,p);
SockRequestResponse repl;
//repl.type=SockRequestResponse::STATUS;
repl.type=STATUS;
repl.connection = s.connection;
repl.bytes=bytes;
repl.error=EOK;
MinetSend(sock,repl);
//TODO: write generate multiple segments instead of only one (compared with UDP)

}
break;
case FORWARD:
{
//ignore this message, resurn error STATUS
SockRequestResponse repl;
repl.type = STATUS;
repl.error = EOK;
MinetSend(sock,repl);
         }
break;
        case CLOSE:
{
ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);
            SockRequestResponse repl;
            repl.connection=s.connection;
            repl.type=STATUS;
            if (cs==clist.end()) {
              repl.error=ENOMATCH;
            } else {
              repl.error=EOK;
              clist.erase(cs);
            }
            MinetSend(sock,repl);
/*TODO:close connection. The connection represents the connection to match on
and all other fields are ignored. If there is a matching connection,
this will close it. Otherwise it is an error. A STATUS with the same connection
and an error code will be returned. STATUS: status update.*/
}
break;
case STATUS:
{
;
/*TODO:status update. This should be sent in response to TCP WRITEs. The
connection should match that in the WRITE. It is important that the byte count
actually reflects the number of bytes read from the WRITE. The TCP module
will resend the remaining bytes at some point in the future.*/
}
default: //treat the status as error
{
SockRequestResponse repl;
repl.type = STATUS;
repl.error=EWHAT;
MinetSend(sock,repl);
}
        }//end of switch
     }//end of "if"
    }//end of "else"
  }//end of "while" loop
  return 0;
}

void sendPacket(const MinetHandle &mux, ConnectionToStateMapping<TCPState>& constate, int dataLen, int signal, bool sender)
{

  unsigned char flags = 0;//temp flag
  Packet packet;
  int packetLen = dataLen + TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH;
  IPHeader iph;
  TCPHeader tcph;
  IPAddress src = constate.connection.src;
  IPAddress dest = constate.connection.dest;

  //create the IP packet
  iph.SetSourceIP(src);
  iph.SetDestIP(dest);
  iph.SetTotalLength(packetLen);
  iph.SetProtocol(IP_PROTO_TCP);

  packet.PushFrontHeader(iph);

  switch (signal){
  case SIG_SYN_ACK:
   {
     SET_SYN(flags);
     SET_ACK(flags);
     //tcph.SetSeqNum(generateISN(), packet);
   }
   break;

 case SIG_RST:
  {
    SET_RST(flags);
  }
  break;

  case SIG_ACK:
   {
    SET_ACK(flags);
    //tcph.SetSeqNum(constate.state.last_sent+1, packet);
   }
  break;
  
  case SIG_SYN:
   {
    SET_SYN(flags);
   }
  case SIG_FIN:
   {
    SET_FIN(flags);
    //tcph.SetSeqNum(constate.state.last_sent+1, packet);
   }
  break;

  case SIG_FIN_ACK:
   {
    SET_FIN(flags);
    SET_ACK(flags);
   }

  default:
  break;
  }
  //Handle TCP header
  tcph.SetSourcePort(constate.connection.srcport,packet);
  tcph.SetDestPort(constate.connection.destport,packet);
  tcph.SetHeaderLen(TCP_HEADER_BASE_LENGTH,packet);
  tcph.SetFlags(flags,packet);
  tcph.SetAckNum(constate.state.GetLastRecvd(), packet);
  if(sender) {
    tcph.SetSeqNum(constate.state.GetLastSent()+1, packet);
  }
  else {
    tcph.SetSeqNum(constate.state.GetLastAcked()+1, packet);
  }
  tcph.SetWinSize(constate.state.GetRwnd(), packet);
  tcph.SetUrgentPtr(0,packet);

  packet.PushBackHeader(tcph);
  MinetSend(mux, packet);
  //constate.state.last_sent++;
}

 
void receivePacket(const MinetHandle &mux, const MinetHandle &sock,Buffer recv_data, unsigned char flags, unsigned int ackNum, unsigned int seqNum, unsigned short tcpLen, ConnectionToStateMapping<TCPState>& constate, Connection c)
{
  if (IS_ACK(flags))
  {
//TODO: Update window
    //ACK duplication check
    if(ackNum <=constate.state.last_acked)
    {
//TODO
    }
    //sender acking new data
    else if ( ((constate.state.last_acked+1) <= ackNum) && (ackNum <= constate.state.last_sent))
    {
constate.state.SendBuffer.Erase(0, ackNum - constate.state.last_acked);
constate.state.last_acked = ackNum;
    }
    //TODO Calculate RTT
  }

  //Process data when connection can receive data (proper state)
  if(tcpLen>0 && (constate.state.stateOfcnx != CLOSING) && (constate.state.stateOfcnx != CLOSE_WAIT)
&& (constate.state.stateOfcnx != LAST_ACK) && (constate.state.stateOfcnx != TIME_WAIT))
  {
if(seqNum != constate.state.last_recvd +1)
{
cerr << "[Receive out of order packet] packet dropped!"<<endl;
}//Process data
else
{
cerr << "[Packet Delivered]"<<recv_data.GetSize() <<" bytes of data to the application" <<endl;
constate.state.last_recvd += recv_data.GetSize();
writeToApplication(sock,c,recv_data);
//send appropriate ACKS
sendPacket(mux,constate, 0, SIG_ACK);
}
  }
}

unsigned int generateISN()
{
  srand((unsigned)time(0));
  unsigned int random;
  unsigned int lowest=100;
  unsigned int highest=1000;
  unsigned int range=(highest-lowest)+1;
  random = lowest+(unsigned int)(range*rand()/(RAND_MAX + 1.0));
  return random;
}

void writeToApplication( const MinetHandle & sock, Connection c, const Buffer &b )
{
    SockRequestResponse repl;
    repl.type = WRITE;
    repl.error = EOK;
    repl.data = b;
    repl.connection = c;
    MinetSend(sock, repl );
}

void EmptyWriteToApplication( const MinetHandle & sock, Connection c )
{
    SockRequestResponse repl;
    repl.type = WRITE;
    repl.error = EOK;
    repl.bytes = 0;
    repl.connection = c;
    MinetSend(sock, repl);
}

    Status
    API
    Training
    Shop
    Blog
    About

    © 2014 GitHub, Inc.
    Terms
    Privacy
    Security
    Contact























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