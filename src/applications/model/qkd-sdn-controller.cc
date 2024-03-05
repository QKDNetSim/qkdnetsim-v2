/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2020 DOTFEESA www.tk.etf.unsa.ba
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@ieee.org>
 */ 

#include "ns3/log.h"
#include "ns3/address.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h" 
#include "ns3/qkd-control.h"
#include "ns3/http.h"
#include "ns3/json.h"

#include <iostream>
#include <fstream> 
#include <string>

#include "qkd-sdn-controller.h"

namespace ns3 {
  
NS_LOG_COMPONENT_DEFINE ("QKDSDNController");

NS_OBJECT_ENSURE_REGISTERED (QKDSDNController);

TypeId
QKDSDNController::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDSDNController")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<QKDSDNController> () 
    //send params
    .AddAttribute ("Protocol", "The type of protocol to use.",
                   TypeIdValue (TcpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&QKDSDNController::m_tid),
                   MakeTypeIdChecker ()) 
    .AddAttribute ("LocalAddress", "The ipv4 address of the application",
                   Ipv4AddressValue (),
                   MakeIpv4AddressAccessor (&QKDSDNController::m_local),
                   MakeIpv4AddressChecker ())
    .AddAttribute ("MaximalKeysPerRequest", 
                   "The maximal number of keys per request (ESTI QKD 014)",
                   UintegerValue (20),
                   MakeUintegerAccessor (&QKDSDNController::m_maxKeyPerRequest),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("MinimalKeySize", 
                   "The minimal size of key QKDApp can request",
                   UintegerValue (32), //in bits 
                   MakeUintegerAccessor (&QKDSDNController::m_minKeySize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaximalKeySize", 
                   "The maximal size of key QKDApp can request",
                   UintegerValue (10240), //in bits 
                   MakeUintegerAccessor (&QKDSDNController::m_maxKeySize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("DefaultKeySize", 
                   "The default size of the key",
                   UintegerValue (512), //in bits 
                   MakeUintegerAccessor (&QKDSDNController::m_defaultKeySize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaliciousRequestBlocking", 
                   "Does SDN detects and blocks malicious get_key_004 request?",
                   UintegerValue (1), //default: YES/TRUE 
                   MakeUintegerAccessor (&QKDSDNController::m_maliciousBlocking),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("QKDLinkUpdateInterval",
                   "Default value of QKD link status update interval (in seconds)",
                   DoubleValue (5.0),
                   MakeDoubleAccessor (&QKDSDNController::m_qkdLinkDefaultUpdateInterval),
                   MakeDoubleChecker<double> ())  


    .AddTraceSource ("Tx", "A new packet is created and is sent to the APP",
                   MakeTraceSourceAccessor (&QKDSDNController::m_txTrace),
                   "ns3::QKDSDNController::Tx")
    .AddTraceSource ("Rx", "A packet from the APP has been received",
                   MakeTraceSourceAccessor (&QKDSDNController::m_rxTrace),
                   "ns3::QKDSDNController::Rx")
    .AddTraceSource ("TxSDNs", "A new packet is created and is sent to the SDN",
                   MakeTraceSourceAccessor (&QKDSDNController::m_txTraceSDNs),
                   "ns3::QKDSDNController::TxSDNs")
    .AddTraceSource ("RxSDNs", "A packet from the APP has been received",
                   MakeTraceSourceAccessor (&QKDSDNController::m_rxTraceSDNs),
                   "ns3::QKDSDNController::RxSDNs")
    //**********************************************************************
    .AddTraceSource ("NewKeyGeneratedEmir", "The trace to monitor key material received from QL",
                     MakeTraceSourceAccessor (&QKDSDNController::m_newKeyGeneratedTraceEmir),
                     "ns3::QKDSDNController::NewKeyGeneratedEmir")
    .AddTraceSource ("KeyServedEmir", "The trace to monitor key material served to QKD Apps",
                     MakeTraceSourceAccessor (&QKDSDNController::m_keyServedTraceEmir),
                     "ns3:QKDSDNController::KeyServedEmir")
    //**********************************************************************
    .AddTraceSource ("NewKeyGenerated", "The trace to monitor key material received from QL",
                     MakeTraceSourceAccessor (&QKDSDNController::m_newKeyGeneratedTrace),
                     "ns3::QKDSDNController::NewKeyGenerated")
 
    .AddTraceSource ("KeyServedEtsi014", "The threce to monitor key usage by etsi 014",
                     MakeTraceSourceAccessor (&QKDSDNController::m_keyServedETSI014Trace),
                     "ns3::QKDSDNController::KeyServedEtsi014")

    .AddTraceSource ("KeyServedEtsi004", "The threce to monitor key usage by etsi 004",
                     MakeTraceSourceAccessor (&QKDSDNController::m_keyServedETSI004Trace),
                     "ns3::QKDSDNController::KeyServedEtsi004")

    .AddTraceSource ("DropKMSRequest", "Drop a request from the queue disc",
                     MakeTraceSourceAccessor (&QKDSDNController::m_dropTrace),
                     "ns3::QKDSDNController::TracedCallback")
  ;
  return tid;
} 

QKDSDNController::QKDSDNController ()
{     
  NS_LOG_FUNCTION (this);
  m_totalRx = 0;    

}

QKDSDNController::~QKDSDNController ()
{
  NS_LOG_FUNCTION (this);
}

uint32_t 
QKDSDNController::GetId(){
  return m_kms_id;
}
 
uint32_t 
QKDSDNController::GetTotalRx () const
{
  NS_LOG_FUNCTION (this);
  return m_totalRx;
}

std::map<Ptr<Socket>, Ptr<Socket> >
QKDSDNController::GetAcceptedSockets (void) const
{
  NS_LOG_FUNCTION (this);
  return m_socketPairs;
}



/**
 * ********************************************************************************************

 *        SOCKET functions
 
 * ********************************************************************************************
 */

Ptr<Socket>
QKDSDNController::GetSocket (void) const
{
  NS_LOG_FUNCTION (this);
  return m_sinkSocket;
}

void
QKDSDNController::SetSocket (std::string type, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << type << socket);
  m_sinkSocket = socket;
}

void
QKDSDNController::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  m_sinkSocket = 0; 
  m_socketPairs.clear (); 
  Application::DoDispose ();
}

void 
QKDSDNController::HandleAccept (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from << InetSocketAddress::ConvertFrom(from).GetIpv4 ()); 
  s->SetRecvCallback (MakeCallback (&QKDSDNController::HandleRead, this));

  std::map<Ptr<Socket>, Ptr<Socket> >::iterator i = m_socketPairs.find ( s );
  if (i == m_socketPairs.end ()){
    
    Ptr<Socket> sendSocket;
    
    if (s->GetSocketType () != Socket::NS3_SOCK_STREAM &&
        s->GetSocketType () != Socket::NS3_SOCK_SEQPACKET)
    {
      NS_LOG_FUNCTION("Create UDP socket!");
      sendSocket = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId () );
    }else{
      NS_LOG_FUNCTION("Create TCP socket!");
      sendSocket = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId () );
    }
    sendSocket->ShutdownRecv ();
    sendSocket->SetConnectCallback (
      MakeCallback (&QKDSDNController::ConnectionSucceeded, this),
      MakeCallback (&QKDSDNController::ConnectionFailed, this)); 
    sendSocket->SetDataSentCallback ( MakeCallback (&QKDSDNController::DataSend, this));  

    InetSocketAddress receiveAddress = InetSocketAddress (
      InetSocketAddress::ConvertFrom(from).GetIpv4 (),
      3060//InetSocketAddress::ConvertFrom(from).GetPort ()
    );
    sendSocket->Bind (); 
    sendSocket->Connect ( receiveAddress );  

    m_socketPairs.insert( std::make_pair(  s ,  sendSocket) );

    NS_LOG_FUNCTION(this 
      << "Create the response socket " << sendSocket 
      << " from SDN to KMS on IP: " << InetSocketAddress::ConvertFrom(from).GetIpv4 () 
      << " and port 3060" //<< InetSocketAddress::ConvertFrom(from).GetPort () 
    );
  }
}
 
void 
QKDSDNController::ConnectionSucceeded (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDSDNController Connection succeeded");

    std::map<Ptr<Socket>, Ptr<Packet> >::iterator j; 
    for (j = m_packetQueues.begin (); !(j == m_packetQueues.end ()); j++){ 
      if(j->first == socket){
        uint32_t response = j->first->Send(j->second); 
        response = j->first->Send(j->second);
        m_txTrace (j->second);
        m_packetQueues.erase (j); 
        NS_LOG_FUNCTION(this << j->first << "Sending packet from the queue!" << response );
      }
    }
}

void 
QKDSDNController::ConnectionFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDSDNController, Connection Failed");
}

void 
QKDSDNController::DataSend (Ptr<Socket>, uint32_t)
{
    NS_LOG_FUNCTION (this);
}

void 
QKDSDNController::HandlePeerClose (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket); 
}

void 
QKDSDNController::HandlePeerError (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDSDNController::SendToSocketPair(Ptr<Socket> socket, Ptr<Packet> packet) 
{
  NS_LOG_FUNCTION( this << socket);
    
  std::map<Ptr<Socket>, Ptr<Socket> >::iterator socketPair = m_socketPairs.find ( socket );
  if (socketPair != m_socketPairs.end ()){
    
    Ptr<Socket> sendingSocket = socketPair->second;
    //check if socket is connected
    //https://www.nsnam.org/doxygen/classns3_1_1_socket.html#a78a3c37a539d2e70869bb82cc60fbb09
    Address connectedAddress;

    //send the packet only if connected!
    if(sendingSocket->GetPeerName(connectedAddress) == 0){
      sendingSocket->Send(packet);
      m_txTrace (packet);
      NS_LOG_FUNCTION(this << packet->GetUid() << "sent via socket " << sendingSocket);

    //otherwise wait in the queue
    }else{
      m_packetQueues.insert( std::make_pair(  sendingSocket ,  packet) );
      NS_LOG_FUNCTION(this << packet->GetUid() << "enqued for socket " << sendingSocket);
    }
  }
}

void 
QKDSDNController::HandleRead (Ptr<Socket> socket)
{
  
  NS_LOG_FUNCTION (this << socket);
 
  Ptr<Packet> packet;
  Address from;      
  while ((packet = socket->RecvFrom (from)))
  {
      if (packet->GetSize () == 0)
      { //EOF
        break;
      }
 
      m_totalRx += packet->GetSize ();
      NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() ); 

      if (InetSocketAddress::IsMatchingType (from))
      {
          NS_LOG_FUNCTION(this << "At time " << Simulator::Now ().GetSeconds ()
                   << "s SDN received packet ID: "
                   <<  packet->GetUid () << " of "
                   <<  packet->GetSize () << " bytes from "
                   << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                   << " port " << InetSocketAddress::ConvertFrom (from).GetPort ()
                   << " total Rx " << m_totalRx << " bytes");          
      } 
 
      m_rxTrace (packet, from); 
      PacketReceived (packet, from, socket);
  }
} 

void
QKDSDNController::PacketReceived (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION ( this << p->GetUid() << p->GetSize() << from );
  std::string receivedStatus = p->ToString();
  NS_LOG_FUNCTION ( this << "\n\n\n" << p->GetUid() << p->GetSize() << receivedStatus << from );

  Ptr<Packet> buffer;
  if (receivedStatus.find("Fragment") != std::string::npos) {
    auto itBuffer = m_buffer.find (from);
    if (itBuffer == m_buffer.end ()){
      itBuffer = m_buffer.insert (
        std::make_pair (from, Create<Packet> (0))
      ).first;
    }
    buffer = itBuffer->second;
    buffer->AddAtEnd (p);
  }else{
    NS_LOG_FUNCTION(this << "Full packet received!");
    buffer = p;
  }

  HTTPMessageParser parser;
  HTTPMessage       request;

  //copy buffer payload to string  
  uint8_t *b1 = new uint8_t[buffer->GetSize ()];
  buffer->CopyData(b1, buffer->GetSize ());
  std::string requestString = std::string((char*)b1); 
  delete[] b1;
 
  //parse HTTP message
  parser.Parse(&request, requestString);
  if(request.IsFragmented() || request.GetStatusMessage() == "Undefined")
  {
    NS_LOG_FUNCTION(this << "HTTP Content Parsed after merge with buffer: " << request.ToString() << "\n ***IsFragmented:" << request.IsFragmented() << "\n\n\n\n"); 
  }else{
    NS_LOG_FUNCTION(this << "Full packet received:" << request.ToString());
  }

  while (buffer->GetSize () >= request.GetSize())
  {
    NS_LOG_DEBUG ("Parsing packet pid(" << p->GetUid() << ") of size " << request.GetSize () << " from buffer of size " << buffer->GetSize ());
    Ptr<Packet> completePacket = buffer->CreateFragment (0, static_cast<uint32_t> (request.GetSize () ));

    uint8_t *b2 = new uint8_t[completePacket->GetSize ()];
    completePacket->CopyData(b2, completePacket->GetSize ());
    std::string s2 = std::string((char*)b2); 

    HTTPMessage request2;
    parser.Parse(&request2, s2);
    delete[] b2;
    
    if(request2.IsFragmented() == false){
      buffer->RemoveAtStart (static_cast<uint32_t> (request2.GetSize () ));
      ProcessRequest(request2, completePacket, socket);    
    }
    NS_LOG_FUNCTION(this << "Croped HTTP message: " << request2.ToString());
    NS_LOG_FUNCTION(this << "Remains in the buffer " << buffer->GetSize () );
    break;
  }
}

/**
 * ********************************************************************************************

 *        APPLICATION functions
 
 * ********************************************************************************************
 */

void 
QKDSDNController::StartApplication (void) // Called at time specified by Start
{
  NS_LOG_FUNCTION(this);
  PrepareSinkSocket();
}

void 
QKDSDNController::PrepareSinkSocket (void) // Called at time specified by Start
{

  NS_LOG_FUNCTION (this); 
  
  // Create the sink socket if not already
  if (!m_sinkSocket){
    m_sinkSocket = Socket::CreateSocket (GetNode (), m_tid);
    NS_LOG_FUNCTION (this << "Create the sink SDN socket!" << m_sinkSocket);
  }

  NS_LOG_FUNCTION (this << "Sink SDN socket listens on " << m_local << " and port " << m_port << " for APP requests" );
  InetSocketAddress sinkAddress = InetSocketAddress (Ipv4Address::GetAny (), m_port);
 
  if (m_sinkSocket->Bind (sinkAddress) == -1)
    NS_FATAL_ERROR ("Failed to bind socket");

  m_sinkSocket->Listen ();
  m_sinkSocket->ShutdownSend ();
  m_sinkSocket->SetRecvCallback (MakeCallback (&QKDSDNController::HandleRead, this));
  m_sinkSocket->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&QKDSDNController::HandleAccept, this)
  );
  m_sinkSocket->SetCloseCallbacks (
    MakeCallback (&QKDSDNController::HandlePeerClose, this),
    MakeCallback (&QKDSDNController::HandlePeerError, this)
  ); 

}

void 
QKDSDNController::StopApplication (void) // Called at time specified by Stop
{
  NS_LOG_FUNCTION (this);
  
  std::map<Ptr<Socket>, Ptr<Socket> >::iterator j;  
  for (
    j = m_socketPairs.begin (); 
    !(j == m_socketPairs.end ()); 
    j++
  ){ 
      if(j->first) { 
        j->first->Close();
        j->first->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
      }
      if(j->second) j->second->Close(); 
  } 

  if (m_sinkSocket) 
  {
    m_sinkSocket->Close ();
    m_sinkSocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
  }
}

/**
 * ********************************************************************************************

 *        Southbound interface functions (ETSI 014 & ETSI 004)
 
 * ********************************************************************************************
 */

void 
QKDSDNController::ProcessRequest (HTTPMessage headerIn, Ptr<Packet> packet, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this);
  uint32_t slave_SAE_ID = 0;
  std::string ksid;
  QKDSDNController::RequestType requestType = NONE;

  std::string s = headerIn.GetUri();
  std::string delimiter = "/";
  
  size_t pos = 0;
  std::string token;
  std::vector<std::string> uriParams;
  while ((pos = s.find(delimiter)) != std::string::npos) {
    token = s.substr(0, pos);
    if(token.length() > 0){
      uriParams.push_back(token);
    }
    s.erase(0, pos + delimiter.length());
  }
  if(s.length() > 0){
    uriParams.push_back(s);
  }

  if( 
    uriParams.size() > 3 && 
    uriParams[1] == "api" &&
    uriParams[2] == "v1" &&
    uriParams[3] == "keys"
  ){
    std::string receivedAddressStr (uriParams[0]);
    Ipv4Address receivedAddress = Ipv4Address(receivedAddressStr.c_str());  //string to IPv4Address
    NS_LOG_FUNCTION(this << "received address" << receivedAddressStr << receivedAddress);
    
    /*
    Due to static routing in the first versions of scripts, IP addresses of SDN controller can differ.
    Therefore, we do not check the address of the SDN controller since we know there is ONLY one SDN controller in the network
    if(receivedAddress != GetAddress())
      NS_FATAL_ERROR ( this << "The request is not for me!\t" << receivedAddress << "\t" << GetAddress() << "\t" << headerIn.GetUri()); 
    */

    std::stringstream tempString (uriParams[4]);
    tempString >> slave_SAE_ID;

    ksid = uriParams[4];
    requestType = FetchRequestType(uriParams[5]);
  }
  NS_LOG_FUNCTION(this << "uri:" << headerIn.GetUri());
  NS_LOG_FUNCTION (this << "slave_SAE_ID: " << slave_SAE_ID << "requestType: " << requestType ); 


  if(requestType ==  REGISTER_QKD_LINK){ //Process status request
  
    uint32_t srcSaeId = 0;
    uint32_t dstSaeId = 0;
    Ipv4Address kmsSrcAddress;
    Ipv4Address kmsDstAddress;
    std::string keyAssociationIdString;

    if(headerIn.GetMethod() == HTTPMessage::HttpMethod::POST){
      std::string payload = headerIn.GetMessageBodyString(); //Read payload 
      try{ 

        //Try parse JSON
        nlohmann::json jrequest; //JSON request structure
        jrequest = nlohmann::json::parse(payload);
        if (jrequest.contains("master_SAE_ID"))      srcSaeId = jrequest["master_SAE_ID"];
        if (jrequest.contains("slave_SAE_ID"))       dstSaeId = jrequest["slave_SAE_ID"];
        if (jrequest.contains("key_association_id")) keyAssociationIdString = jrequest["key_association_id"];

        std::string kmsSrcAddressStr;
        if (jrequest.contains("master_kms_address")) kmsSrcAddressStr = jrequest["master_kms_address"];
        kmsSrcAddress = Ipv4Address(kmsSrcAddressStr.c_str());  //string to IPv4Address

        std::string kmsDstAddressStr;
        if (jrequest.contains("slave_kms_address"))  kmsDstAddressStr = jrequest["slave_kms_address"];
        kmsDstAddress = Ipv4Address(kmsDstAddressStr.c_str());  //string to IPv4Address
          
      }catch(...){
          NS_FATAL_ERROR( this << "JSON parse error of the received payload: " << payload << "\t" << payload.length() );
      }

    }else
        NS_FATAL_ERROR(this << "Invalid HTTP request method" << headerIn.GetMethod()); //@toDo: include HTTP response?

    Ptr<QKDConnectionRegister> lr = GetNode()->GetObject<QKDConnectionRegister> ();
    NS_ASSERT (lr);

    QKDKeyAssociationLinkEntry newEntry(
      srcSaeId,
      dstSaeId,
      dstSaeId,//nextHop
      1,//dirrect p2p connection (number of hops)
      0,// 0-QKD generation link; 1-etsi014; 2-etsi004
      kmsSrcAddress,
      kmsDstAddress,
      0
    );
    newEntry.SetId( UUID{keyAssociationIdString} );
    newEntry.SetUpdateStatusInterval( m_qkdLinkDefaultUpdateInterval );
    lr->AddKeyAssociationEntry(newEntry);

    NS_LOG_FUNCTION (this << "NEW QKD LINK REGISTERED AT SDN CONTROLLER!");
    NS_LOG_FUNCTION (this << "SET STATUS UPDATE TIME TO: " << m_qkdLinkDefaultUpdateInterval);

    nlohmann::json j;
    j["accepted"] = 1; //true
    j["qkd_link_update_interval"] = m_qkdLinkDefaultUpdateInterval; 
    j["key_association_id"] = keyAssociationIdString;
    NS_LOG_FUNCTION( this << "json_response:" << j.dump()  );

    std::string msg = j.dump();

    //create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, msg, {
      {"Content-Type", "application/json; charset=utf-8"}, 
      {"Request URI", headerIn.GetUri() }
    });
    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packet = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT (packet); 
 
    
    NS_LOG_FUNCTION (this 
      << "Sending Response to REGISTER_QKD_LINK\n PacketID: " 
      << packet->GetUid() 
      << " of size: " 
      << packet->GetSize()
    );
    SendToSocketPair(socket, packet);  



  }else if(requestType ==  KEY_ASSOCIATION_STATUS){ //Process status request
  
    double skr = 0;
    double expectedConsumption = 0;
    double effectiveSkr = 0;
    std::string keyAssociationIdString;

    if(headerIn.GetMethod() == HTTPMessage::HttpMethod::POST){
      std::string payload = headerIn.GetMessageBodyString(); //Read payload 
      try{ 

        //Try parse JSON
        nlohmann::json jrequest; //JSON request structure
        jrequest = nlohmann::json::parse(payload); 
        if (jrequest.contains("key_association_id")) keyAssociationIdString = jrequest["key_association_id"];
        if (jrequest.contains("qkdl_performance_skr")) skr = jrequest["qkdl_performance_skr"];
        if (jrequest.contains("qkdl_performance_expected_consumption")) expectedConsumption = jrequest["qkdl_performance_expected_consumption"];
        if (jrequest.contains("qkdl_performance_eskr")) effectiveSkr = jrequest["qkdl_performance_eskr"];

      }catch(...){
          NS_FATAL_ERROR( this << "JSON parse error of the received payload: " << payload << "\t" << payload.length() );
      }

    }else
        NS_FATAL_ERROR(this << "Invalid HTTP request method" << headerIn.GetMethod()); //@toDo: include HTTP response?

    Ptr<QKDConnectionRegister> lr = GetNode()->GetObject<QKDConnectionRegister> ();
    NS_ASSERT (lr);

    QKDKeyAssociationLinkEntry conn;
    lr->LookupKeyAssociationById(UUID{keyAssociationIdString}, conn);
    
    //Secret key rate generation (in bits per second) of the key association link.
    conn.SetSKR(skr);
    //Sum of all the application's bandwidth (in bits per second) on this particular key association link.
    conn.SetExpectedConsumption(expectedConsumption);
    //Effective secret key rate (in bits per second) generation of the key association link available after internal consumption 
    conn.SetEffectiveSKR(effectiveSkr);

    lr->SaveKeyAssociation(conn);

    NS_LOG_FUNCTION (this << "NEW QKD LINK STATS (id: " << keyAssociationIdString << "; eskr:" << effectiveSkr << ") UPDATE RECEIVED AT SDN CONTROLLER!");
    
  }else if(requestType == REGISTER_SAE_LINK){

    std::string srcSaeId;
    std::string dstSaeId;
    std::string nextHopId;
    uint32_t hops = 0;
    uint32_t linkType = 0;
    Ipv4Address kmsSrcAddress;
    Ipv4Address kmsDstAddress;

      if(headerIn.GetMethod() == HTTPMessage::HttpMethod::POST){
        std::string payload = headerIn.GetMessageBodyString(); //Read payload 
        try{ 

          //Try parse JSON
          nlohmann::json jrequest; //JSON request structure
          jrequest = nlohmann::json::parse(payload);
          if (jrequest.contains("master_SAE_ID"))     srcSaeId = jrequest["master_SAE_ID"];
          if (jrequest.contains("slave_SAE_ID"))      dstSaeId = jrequest["slave_SAE_ID"];
          if (jrequest.contains("hops"))              hops = jrequest["hops"];
          if (jrequest.contains("linkType"))          linkType = jrequest["linkType"]; 
          if (jrequest.contains("next_hop_id"))       nextHopId = jrequest["next_hop_id"]; 

          std::string kmsSrcAddressStr;
          if (jrequest.contains("master_kms_address")) kmsSrcAddressStr = jrequest["master_kms_address"];
          kmsSrcAddress = Ipv4Address(kmsSrcAddressStr.c_str());  //string to IPv4Address

          std::string kmsDstAddressStr;
          if (jrequest.contains("slave_kms_address"))  kmsDstAddressStr = jrequest["slave_kms_address"];
          kmsDstAddress = Ipv4Address(kmsDstAddressStr.c_str());  //string to IPv4Address
            
        }catch(...){
            NS_FATAL_ERROR( this << "JSON parse error of the received payload: " << payload << "\t" << payload.length() );
        }

      }else
          NS_FATAL_ERROR(this << "Invalid HTTP request method" << headerIn.GetMethod()); //@toDo: include HTTP response?

    Ptr<QKDConnectionRegister> lr = GetNode()->GetObject<QKDConnectionRegister> ();
    NS_ASSERT (lr);

    NS_LOG_FUNCTION(this << srcSaeId << dstSaeId << nextHopId << hops << linkType);
  
    /*
    QKDLocationRegisterEntry newEntry(
      srcSaeId,
      dstSaeId,
      nextHopId, //nextHop
      hops, //number of hops
      linkType,// 0-QKD generation link; 1-etsi014; 2-etsi004
      kmsSrcAddress,
      kmsDstAddress,
      0
    );
    lr->AddApplicationEntry(newEntry);
    */ 
    
    NS_LOG_FUNCTION (this << "NEW SAE LINK REGISTERED AT SDN CONTROLLER!");

  }
 
}
     

uint32_t
QKDSDNController::GetMaxKeyPerRequest(){
  return m_maxKeyPerRequest;
}

QKDSDNController::RequestType
QKDSDNController::FetchRequestType(std::string s)
{
  NS_LOG_FUNCTION(this << s);
  RequestType output;

  if(s == "status"){

      return ETSI_QKD_014_GET_STATUS;

  } else if(s == "enc_keys") {

      return ETSI_QKD_014_GET_KEY;

  } else if(s == "dec_keys"){

      return ETSI_QKD_014_GET_KEY_WITH_KEY_IDS;

  } else if (s == "open_connect"){

      return ETSI_QKD_004_OPEN_CONNECT;

  } else if (s == "get_key") {

      return ETSI_QKD_004_GET_KEY;

  } else if (s == "close") {

      return ETSI_QKD_004_CLOSE;

  } else if (s == "new_app") {

      return NEW_APP;

  } else if (s == "register") {

      return REGISTER;

  } else if (s == "fill") {

      return FILL;

  } else if (s == "store_pp_key") {

      return STORE_PP_KEYS;

  } else if (s == "transform_keys") {

    return TRANSFORM_KEYS;

  } else if (s == "close_kms") {

    return ETSI_QKD_004_KMS_CLOSE;

  } else if (s == "register_sae_link") {

    return REGISTER_SAE_LINK;

  }  else if (s == "register_qkd_link") {

    return REGISTER_QKD_LINK;
   
  } else if (s == "key_association_status") {

    return KEY_ASSOCIATION_STATUS;
   
  } else {

      NS_FATAL_ERROR ("Unknown Type: " << s);
  }
  
  return output;
}

//function called from QKD Control
//by default srcSaeId == srcNodeId where the link is installed
void 
QKDSDNController::AddNewLink( 
  uint32_t srcSaeId,
  uint32_t dstSaeId,  
  Ipv4Address kmsDstAddress,
  Ptr<QKDBuffer> srcBuffer
){

  NS_LOG_FUNCTION( this << srcSaeId << dstSaeId << m_local << kmsDstAddress );
 
  Ptr<QKDConnectionRegister> lr = GetNode()->GetObject<QKDConnectionRegister> ();
  NS_ASSERT (lr);

  QKDKeyAssociationLinkEntry newEntry(
    srcSaeId,
    dstSaeId,
    dstSaeId,//nextHop
    1,//dirrect p2p connection (number of hops)
    0,// 0-QKD generation link; 1-etsi014; 2-etsi004
    m_local,
    kmsDstAddress,
    srcBuffer
  );
  lr->AddKeyAssociationEntry(newEntry); 
 
  NS_LOG_FUNCTION (this << "Create sink socket to listen requests exchanged between KMSs!" );

} 

/**
 * This function register the pair of QKDApps (srcSaeId, dstSaeId) to use keys that are produced
 * by the QKD systems on nodes srcNode and dstNode via this KMS 
*/
void
QKDSDNController::RegisterSaePair(
    Ptr<Node> srcNode, 
    Ptr<Node> dstNode,
    uint32_t  srcSaeId,
    uint32_t  dstSaeId,
    std::string type // 0-QKD generation link; 1-etsi014; 2-etsi004
){

  NS_LOG_FUNCTION( this << dstNode );

  Ptr<QKDConnectionRegister> lr = GetNode()->GetObject<QKDConnectionRegister> ();
  NS_ASSERT (lr);
  /*
  //By default there should be one LR entry that connects nodes
  //source_SAE and master_SAE of that connection is the ID of nodes
  //we use that entry to fetch details about KMS and the local buffer
  //@toDo: allow much easier way for adding of saes
  QKDLocationRegisterEntry conn = GetConnectionDetailsByNodeId( dstNode->GetId() );

  uint32_t linkType;
  if(type == "etsi014"){
    linkType = 1;
  }else if(type == "etsi004"){
    linkType = 2;
  }

  if(conn.GetSourceSaeId() == srcNode->GetId() && 
     conn.GetDestinationSaeId() == dstNode->GetId()
  ){

    QKDLocationRegisterEntry newEntry(
      srcSaeId,
      dstSaeId,
      conn.GetNextHop(), 
      conn.GetHop(),
      linkType,
      conn.GetSourceKmsAddress(),
      conn.GetDestinationKmsAddress(),
      conn.GetSourceBuffer()
    );
    lr->AddEntry(newEntry);
  }
  */

}

void 
QKDSDNController::SetNode(Ptr<Node> n){
  m_node = n;
}

Ptr<Node> 
QKDSDNController::GetNode(){
  return m_node;
}
 
 
std::string
QKDSDNController::Base64Encode(std::string input)
{
  std::string output;
  CryptoPP::StringSource(input, true,
    new CryptoPP::Base64Encoder(
      new CryptoPP::StringSink(output)
    ) // Base64Encoder
  ); // StringSource
  return output;
}

std::string
QKDSDNController::Base64Decode(std::string input)
{
  std::string output;
  CryptoPP::StringSource(input, true,
    new CryptoPP::Base64Decoder(
      new CryptoPP::StringSink(output)
    ) // Base64Dencoder
  ); // StringSource
  return output;
}
 

} // Namespace ns3
