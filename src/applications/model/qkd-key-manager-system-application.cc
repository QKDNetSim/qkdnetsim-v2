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

#include "qkd-key-manager-system-application.h"

namespace ns3 {
  
NS_LOG_COMPONENT_DEFINE ("QKDKeyManagerSystemApplication");

NS_OBJECT_ENSURE_REGISTERED (QKDKeyManagerSystemApplication);

TypeId
QKDKeyManagerSystemApplication::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDKeyManagerSystemApplication")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<QKDKeyManagerSystemApplication> () 
    //send params
    .AddAttribute ("Protocol", "The type of protocol to use.",
                   TypeIdValue (TcpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&QKDKeyManagerSystemApplication::m_tid),
                   MakeTypeIdChecker ()) 
    .AddAttribute ("LocalAddress", "The ipv4 address of the application",
                   Ipv4AddressValue (),
                   MakeIpv4AddressAccessor (&QKDKeyManagerSystemApplication::m_local),
                   MakeIpv4AddressChecker ())
    .AddAttribute ("MaximalKeysPerRequest", 
                   "The maximal number of keys per request (ESTI QKD 014)",
                   UintegerValue (20),
                   MakeUintegerAccessor (&QKDKeyManagerSystemApplication::m_maxKeyPerRequest),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("MinimalKeySize", 
                   "The minimal size of key QKDApp can request",
                   UintegerValue (32), //in bits 
                   MakeUintegerAccessor (&QKDKeyManagerSystemApplication::m_minKeySize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaximalKeySize", 
                   "The maximal size of key QKDApp can request",
                   UintegerValue (10240), //in bits 
                   MakeUintegerAccessor (&QKDKeyManagerSystemApplication::m_maxKeySize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("DefaultKeySize", 
                   "The default size of the key",
                   UintegerValue (512), //in bits 
                   MakeUintegerAccessor (&QKDKeyManagerSystemApplication::m_defaultKeySize),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaliciousRequestBlocking", 
                   "Does KMS detects and blocks malicious get_key_004 request?",
                   UintegerValue (0), //default: YES/TRUE 
                   MakeUintegerAccessor (&QKDKeyManagerSystemApplication::m_maliciousBlocking),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("ETSI004_DefaultTTL", 
                   "Default value of ETSI004 TTL (in seconds)",
                   UintegerValue (10), //default: YES/TRUE 
                   MakeUintegerAccessor (&QKDKeyManagerSystemApplication::m_default_ttl),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("MaxKeyRate", "The maximal key rate (encryption+authentication) provided by the KMS (QoS settings).",
                   DataRateValue (DataRate ("10kb/s")),
                   MakeDataRateAccessor (&QKDKeyManagerSystemApplication::m_maxKeyRate),
                   MakeDataRateChecker ())
    .AddAttribute ("MinKeyRate", "The minimal key rate (encryption+authentication) provided by the KMS (QoS settings).",
                   DataRateValue (DataRate ("1kb/s")),
                   MakeDataRateAccessor (&QKDKeyManagerSystemApplication::m_minKeyRate),
                   MakeDataRateChecker ())
     .AddAttribute ("QoS_maxrate_threshold",
                   "The treshold for processing low-priority requests",
                   DoubleValue (0.2),
                   MakeDoubleAccessor (&QKDKeyManagerSystemApplication::m_qos_maxrate_threshold),
                   MakeDoubleChecker<double> ())

    .AddTraceSource ("Tx", "A new packet is created and is sent to the APP",
                   MakeTraceSourceAccessor (&QKDKeyManagerSystemApplication::m_txTrace),
                   "ns3::QKDKeyManagerSystemApplication::Tx")
    .AddTraceSource ("Rx", "A packet from the APP has been received",
                   MakeTraceSourceAccessor (&QKDKeyManagerSystemApplication::m_rxTrace),
                   "ns3::QKDKeyManagerSystemApplication::Rx")
    .AddTraceSource ("TxKMSs", "A new packet is created and is sent to the APP",
                   MakeTraceSourceAccessor (&QKDKeyManagerSystemApplication::m_txTraceKMSs),
                   "ns3::QKDKeyManagerSystemApplication::TxKMSs")
    .AddTraceSource ("RxKMSs", "A packet from the APP has been received",
                   MakeTraceSourceAccessor (&QKDKeyManagerSystemApplication::m_rxTraceKMSs),
                   "ns3::QKDKeyManagerSystemApplication::RxKMSs")
    //**********************************************************************
    .AddTraceSource ("NewKeyGeneratedEmir", "The trace to monitor key material received from QL",
                     MakeTraceSourceAccessor (&QKDKeyManagerSystemApplication::m_newKeyGeneratedTraceEmir),
                     "ns3::QKDKeyManagerSystemApplication::NewKeyGeneratedEmir")
    .AddTraceSource ("KeyServedEmir", "The trace to monitor key material served to QKD Apps",
                     MakeTraceSourceAccessor (&QKDKeyManagerSystemApplication::m_keyServedTraceEmir),
                     "ns3:QKDKeyManagerSystemApplication::KeyServedEmir")
    //**********************************************************************
    .AddTraceSource ("NewKeyGenerated", "The trace to monitor key material received from QL",
                     MakeTraceSourceAccessor (&QKDKeyManagerSystemApplication::m_newKeyGeneratedTrace),
                     "ns3::QKDKeyManagerSystemApplication::NewKeyGenerated")
 
    .AddTraceSource ("KeyServedEtsi014", "The thece to monitor key usage by etsi 014",
                     MakeTraceSourceAccessor (&QKDKeyManagerSystemApplication::m_keyServedETSI014Trace),
                     "ns3::QKDKeyManagerSystemApplication::KeyServedEtsi014")

    .AddTraceSource ("KeyServedEtsi004", "The thece to monitor key usage by etsi 004",
                     MakeTraceSourceAccessor (&QKDKeyManagerSystemApplication::m_keyServedETSI004Trace),
                     "ns3::QKDKeyManagerSystemApplication::KeyServedEtsi004")

    .AddTraceSource ("DropKMSRequest", "Drop a request from the queue disc",
                     MakeTraceSourceAccessor (&QKDKeyManagerSystemApplication::m_dropTrace),
                     "ns3::QKDKeyManagerSystemApplication::TracedCallback")

    .AddTraceSource ("ProvidedQoSResponse", "Provide QoS response to key material request",
                     MakeTraceSourceAccessor (&QKDKeyManagerSystemApplication::m_providedQoS),
                     "ns3::QKDKeyManagerSystemApplication::ProvidedQoSResponse")
  ;
  return tid;
}

uint32_t QKDKeyManagerSystemApplication::nKMS = 0;

QKDKeyManagerSystemApplication::QKDKeyManagerSystemApplication ()
{     
  NS_LOG_FUNCTION (this);
  m_totalRx = 0; 
  m_kms_id = ++nKMS+8000;
  m_kms_key_id = 0;
  connectedToSDN = false;

  m_queueLogic = CreateObject<QKDKMSQueueLogic> ();
  m_random = CreateObject<UniformRandomVariable> (); 
  m_sdnSupportEnabled = false;

}

QKDKeyManagerSystemApplication::~QKDKeyManagerSystemApplication ()
{
  NS_LOG_FUNCTION (this);
}

uint32_t 
QKDKeyManagerSystemApplication::GetId(){
  return m_kms_id;
}
 
uint32_t 
QKDKeyManagerSystemApplication::GetTotalRx () const
{
  NS_LOG_FUNCTION (this);
  return m_totalRx;
}

std::map<Ptr<Socket>, Ptr<Socket> >
QKDKeyManagerSystemApplication::GetAcceptedSockets (void) const
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
QKDKeyManagerSystemApplication::GetSocket (void) const
{
  NS_LOG_FUNCTION (this);
  return m_sinkSocket;
}

void
QKDKeyManagerSystemApplication::SetSocket (std::string type, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << type << socket);
  m_sinkSocket = socket;
}

void
QKDKeyManagerSystemApplication::DoDispose (void)
{
  NS_LOG_FUNCTION (this);
  m_sinkSocket = 0; 
  m_socketPairs.clear (); 
  Application::DoDispose ();
}

void 
QKDKeyManagerSystemApplication::HandleAccept (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from << InetSocketAddress::ConvertFrom(from).GetIpv4 ()); 
  s->SetRecvCallback (MakeCallback (&QKDKeyManagerSystemApplication::HandleRead, this));

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
      MakeCallback (&QKDKeyManagerSystemApplication::ConnectionSucceeded, this),
      MakeCallback (&QKDKeyManagerSystemApplication::ConnectionFailed, this)); 
    sendSocket->SetDataSentCallback ( MakeCallback (&QKDKeyManagerSystemApplication::DataSend, this));  

    InetSocketAddress receiveAddress = InetSocketAddress (
      InetSocketAddress::ConvertFrom(from).GetIpv4 (),
      82//InetSocketAddress::ConvertFrom(from).GetPort ()
    );
    sendSocket->Bind (); 
    sendSocket->Connect ( receiveAddress );  

    m_socketPairs.insert( std::make_pair(  s ,  sendSocket) );

    NS_LOG_FUNCTION(this 
      << "Create the response socket " << sendSocket 
      << " from KMS to " << InetSocketAddress::ConvertFrom(from).GetIpv4 () 
      << " and port " << InetSocketAddress::ConvertFrom(from).GetPort () 
    );
  }
}
 
void 
QKDKeyManagerSystemApplication::HandleAcceptKMSs (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this 
    << s 
    << from 
    << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
    << InetSocketAddress::ConvertFrom(from).GetPort () 
  );

  s->SetRecvCallback (MakeCallback (&QKDKeyManagerSystemApplication::HandleReadKMSs, this));

  //Check is it necessary to create response socket
  Ipv4Address destKMS = InetSocketAddress::ConvertFrom(from).GetIpv4 ();
  std::map<Ipv4Address, std::pair<Ptr<Socket>, Ptr<Socket> > >::iterator it = m_socketPairsKMS.find(destKMS);
  if ( it != m_socketPairsKMS.end () )
      it->second.first = s; //Set receiving socket
  
  CheckSocketsKMS(destKMS);

}

void 
QKDKeyManagerSystemApplication::HandleAcceptSDN (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this 
    << s 
    << from 
    << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
    << InetSocketAddress::ConvertFrom(from).GetPort () 
  );

  s->SetRecvCallback (MakeCallback (&QKDKeyManagerSystemApplication::HandleReadSDN, this));
}

 
void 
QKDKeyManagerSystemApplication::ConnectionSucceeded (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDKeyManagerSystemApplication Connection succeeded");

    std::map<Ptr<Socket>, Ptr<Packet> >::iterator j; 
    for (j = m_packetQueues.begin (); !(j == m_packetQueues.end ());){ 
      if(j->first == socket){
        uint32_t response = j->first->Send(j->second); 
        response = j->first->Send(j->second);
        m_txTrace (j->second);
        m_packetQueues.erase (j++); 
        NS_LOG_FUNCTION(this << j->first << "Sending packet from the queue!" << response );
      }else{
        ++j;
      }
    }
}

void 
QKDKeyManagerSystemApplication::ConnectionSucceededKMSs (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDKeyManagerSystemApplication KMSs Connection succeeded");
}
 
void 
QKDKeyManagerSystemApplication::ConnectionFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDKeyManagerSystemApplication, Connection Failed");
}

void 
QKDKeyManagerSystemApplication::ConnectionFailedKMSs (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  NS_LOG_FUNCTION (this << "QKDKeyManagerSystemApplication, Connection Failed");
}

void 
QKDKeyManagerSystemApplication::DataSend (Ptr<Socket>, uint32_t)
{
    NS_LOG_FUNCTION (this);
}
 
void 
QKDKeyManagerSystemApplication::DataSendKMSs (Ptr<Socket>, uint32_t)
{
    NS_LOG_FUNCTION (this);
} 

void 
QKDKeyManagerSystemApplication::ConnectionToSDNSucceeded (Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << socket << m_sendSocketToSDN);
    NS_LOG_FUNCTION (this << "QKDKeyManagerSystemApplication KMS-SDN Connection succeeded");
    connectedToSDN = true;

    if(socket == m_sendSocketToSDN){
      NS_LOG_FUNCTION(this << "Check packets in queue!");
      std::map<Ptr<Socket>, Ptr<Packet> >::iterator j; 
      for (j = m_packetQueuesToSDN.begin (); !(j == m_packetQueuesToSDN.end ());){ 
        //it can happen that packet was not sent because socket was not connected
        if(j->first == socket || !j->first){
          uint32_t response = m_sendSocketToSDN->Send(j->second); 
          m_packetQueuesToSDN.erase (j++); 
          NS_LOG_FUNCTION(this << m_sendSocketToSDN << "Sending packet from the queue to SDN!" << response );
        }else{
          ++j;
        }
      }
    }
}
 
void 
QKDKeyManagerSystemApplication::ConnectionToSDNFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDKeyManagerSystemApplication KMS-SDN Connection failed");
}

void 
QKDKeyManagerSystemApplication::DataToSDNSend (Ptr<Socket>, uint32_t)
{
    NS_LOG_FUNCTION (this);
} 

void 
QKDKeyManagerSystemApplication::HandlePeerClose (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket); 
}

void 
QKDKeyManagerSystemApplication::HandlePeerCloseKMSs (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDKeyManagerSystemApplication::HandlePeerCloseSDN (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDKeyManagerSystemApplication::HandlePeerError (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDKeyManagerSystemApplication::HandlePeerErrorKMSs (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDKeyManagerSystemApplication::HandlePeerErrorSDN (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDKeyManagerSystemApplication::SendToSocketPair(Ptr<Socket> socket, Ptr<Packet> packet) 
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
QKDKeyManagerSystemApplication::SendToSocketPairKMS (Ptr<Socket> socket, Ptr<Packet> packet) 
{
    NS_LOG_FUNCTION( this << socket );

    std::map<Ipv4Address, std::pair<Ptr<Socket>, Ptr<Socket> > >::iterator it;
    for ( it = m_socketPairsKMS.begin (); !(it == m_socketPairsKMS.end ());  it++ )  
      //we do not have info about KMS destination address ?
      if ( it->second.first == socket )
      {
        Ptr<Socket> sendingSocket = it->second.second;
        sendingSocket->Send(packet);
        NS_LOG_FUNCTION( this << "Packet ID" << packet->GetUid() << "Sending socket" << sendingSocket );
      }
}

void
QKDKeyManagerSystemApplication::CheckSocketsKMS (Ipv4Address kmsDstAddress)
{
  NS_LOG_FUNCTION( this << m_local << kmsDstAddress );

  //Local KMS should create socket to send data to peer KMS 
  //Local KMS should check if the socket for this connection already exists?
  //Local KMS can have connections to multiple KMS systems - neighbor and distant KMSs
  std::map<Ipv4Address, std::pair<Ptr<Socket>, Ptr<Socket> > >::iterator i = m_socketPairsKMS.find ( kmsDstAddress );
 
  if (i == m_socketPairsKMS.end ()){
    NS_FATAL_ERROR ( this << "No connection between KMS defined!"); //@toDo: include HTTP response!
  }else{

    std::pair<Ptr<Socket>, Ptr<Socket> > pair = i->second;
    if(!pair.second){

      NS_LOG_FUNCTION(this << "Let's create a new send socket to reach KMS!"); 
  
      Ptr<Socket> sendSocket;
      Ptr<Socket> sinkSocket = pair.first;
    
      if (sinkSocket->GetSocketType () != Socket::NS3_SOCK_STREAM &&
          sinkSocket->GetSocketType () != Socket::NS3_SOCK_SEQPACKET)
      {
        NS_LOG_FUNCTION("Create UDP socket!");
        sendSocket = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId () );
      }else{
        NS_LOG_FUNCTION("Create TCP socket!");
        sendSocket = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId () );
      }
      sendSocket->ShutdownRecv ();
      sendSocket->SetConnectCallback (
        MakeCallback (&QKDKeyManagerSystemApplication::ConnectionSucceededKMSs, this),
        MakeCallback (&QKDKeyManagerSystemApplication::ConnectionFailedKMSs, this)); 
      sendSocket->SetDataSentCallback ( MakeCallback (&QKDKeyManagerSystemApplication::DataSendKMSs, this));  

      InetSocketAddress peerAddress = InetSocketAddress (
        kmsDstAddress,
        8080
      );
      sendSocket->Bind (); 
      sendSocket->Connect ( peerAddress );  

      //update socket pair entry
      i->second.second = sendSocket;

      NS_LOG_FUNCTION(this 
        << "Create the send socket " << sendSocket 
        << " from KMS to KMS which is on " << kmsDstAddress 
      );

    }else{
      NS_LOG_FUNCTION(this << "Socket to peer KMS exist. No action required");      
    }

  } 
}

Ptr<Socket>
QKDKeyManagerSystemApplication::GetSendSocketKMS (Ipv4Address kmsDstAddress)
{
  NS_LOG_FUNCTION( this << kmsDstAddress );
  //Local KMS should create socket to send data to peer KMS 
  //Local KMS should check if the socket for this connection already exists?
  //Local KMS can have connections to multiple KMS systems - neighbor and distant KMSs
  std::map<Ipv4Address, std::pair<Ptr<Socket>, Ptr<Socket> > >::iterator i = m_socketPairsKMS.find ( kmsDstAddress );

  if (i == m_socketPairsKMS.end ()){

    NS_FATAL_ERROR ( this << "No connection between KMS defined!"); //@toDo: include HTTP response!
    return NULL;

  } else {

    std::pair<Ptr<Socket>, Ptr<Socket> > pair = i->second;
    NS_ASSERT (pair.first);
    NS_ASSERT (pair.second);
    Ptr<Socket> sendSocket = pair.second;

    return sendSocket;
  }
}


void 
QKDKeyManagerSystemApplication::HandleRead (Ptr<Socket> socket)
{
  
  NS_LOG_FUNCTION (this << socket);
 
  Ptr<Packet> packet;
  Address from;      
  while ((packet = socket->RecvFrom (from)))
  {
      if (packet->GetSize () == 0) break;
 
      m_totalRx += packet->GetSize ();
      NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() ); 

      if (InetSocketAddress::IsMatchingType (from))
      {
          NS_LOG_FUNCTION(this << "At time " << Simulator::Now ().GetSeconds ()
                   << "s KMS received packet ID: "
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
QKDKeyManagerSystemApplication::HandleReadKMSs (Ptr<Socket> socket)
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
 
      m_totalRxKMSs += packet->GetSize ();
      NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() ); 

      if (InetSocketAddress::IsMatchingType (from))
      {
          NS_LOG_FUNCTION(this << "At time " << Simulator::Now ().GetSeconds ()
                   << "s KMS received packet ID: "
                   <<  packet->GetUid () << " of "
                   <<  packet->GetSize () << " bytes from KMS "
                   << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                   << " port " << InetSocketAddress::ConvertFrom (from).GetPort ()
                   << " total Rx " << m_totalRx << " bytes");          
      } 
 
      m_rxTraceKMSs (packet, from); 
      PacketReceivedKMSs (packet, from, socket);
  }
}

void 
QKDKeyManagerSystemApplication::HandleReadSDN (Ptr<Socket> socket)
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
 
      m_totalRxKMSs += packet->GetSize ();
      NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() ); 

      if (InetSocketAddress::IsMatchingType (from))
      {
          NS_LOG_FUNCTION(this << "At time " << Simulator::Now ().GetSeconds ()
                   << "s KMS received packet ID: "
                   <<  packet->GetUid () << " of "
                   <<  packet->GetSize () << " bytes from KMS "
                   << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                   << " port " << InetSocketAddress::ConvertFrom (from).GetPort ()
                   << " total Rx " << m_totalRx << " bytes");

        PacketReceivedSDN(packet, from, socket);
        m_rxTraceSDN (packet, from);           
      } 
 
  }
}
void
QKDKeyManagerSystemApplication::PacketReceived (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  std::string receivedStatus = p->ToString();
  NS_LOG_FUNCTION ( this << "\n\n\n" << p->GetUid() << p->GetSize() << receivedStatus << from );

  Ptr<Packet> buffer;
  if (receivedStatus.find("Fragment") != std::string::npos) {
    auto itBuffer = m_bufferKMS.find (from);
    if (itBuffer == m_bufferKMS.end ()){
      itBuffer = m_bufferKMS.insert (
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

void
QKDKeyManagerSystemApplication::PacketReceivedKMSs (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION ( this << p->GetUid() << p->GetSize() << from );
  std::string receivedStatus = p->ToString();
  NS_LOG_FUNCTION ( this << "\n\n\n" << p->GetUid() << p->GetSize() << receivedStatus << from );

  Ptr<Packet> buffer;
  if (receivedStatus.find("Fragment") != std::string::npos) {
    auto itBuffer = m_bufferKMS.find (from);
    if (itBuffer == m_bufferKMS.end ()){
      itBuffer = m_bufferKMS.insert (
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
      ProcessPacketKMSs(request2, completePacket, socket);
    }
    NS_LOG_FUNCTION(this << "Croped HTTP message: " << request2.ToString());
    NS_LOG_FUNCTION(this << "Remains in the buffer " << buffer->GetSize () );
    break;
  } 
}


void
QKDKeyManagerSystemApplication::PacketReceivedSDN (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION ( this << p->GetUid() << p->GetSize() << from );
  std::string receivedStatus = p->ToString();
  NS_LOG_FUNCTION ( this << "\n\n\n" << p->GetUid() << p->GetSize() << receivedStatus << from );

  Ptr<Packet> buffer;
  if (receivedStatus.find("Fragment") != std::string::npos) {
    auto itBuffer = m_bufferKMS.find (from);
    if (itBuffer == m_bufferKMS.end ()){
      itBuffer = m_bufferKMS.insert (
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

  NS_LOG_FUNCTION(this << "aaaaa: \t" << buffer->GetSize() << request.GetSize());

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

      NS_LOG_FUNCTION(this << " xxxxx: " << request2.GetUri() );
      if(request2.GetUri() != ""){
        ProcessRequestSDN(request2, completePacket, socket);
      }else{
        ProcessResponseSDN(request2, completePacket, socket);
      }
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
QKDKeyManagerSystemApplication::StartApplication (void) // Called at time specified by Start
{
  NS_LOG_FUNCTION(this);
  PrepareSinkSocket();
  if(m_sdnControllerAddress.IsInvalid() == 0 && m_sdnSupportEnabled) 
    ConnectToSDNController();
}

void 
QKDKeyManagerSystemApplication::PrepareSinkSocket (void) // Called at time specified by Start
{
  NS_LOG_FUNCTION (this); 
  
  // Create the sink socket if not already
  if (!m_sinkSocket){
    m_sinkSocket = Socket::CreateSocket (GetNode (), m_tid);
    NS_LOG_FUNCTION (this << "Create the sink KMS socket!" << m_sinkSocket);
  }

  NS_LOG_FUNCTION (this << "Sink KMS socket listens on " << m_local << " and port " << m_port << " for APP requests" );
  InetSocketAddress sinkAddress = InetSocketAddress (m_local, m_port);

  m_sinkSocket->Bind (sinkAddress);
  m_sinkSocket->Listen ();
  m_sinkSocket->ShutdownSend ();
  m_sinkSocket->SetRecvCallback (MakeCallback (&QKDKeyManagerSystemApplication::HandleRead, this));
  m_sinkSocket->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&QKDKeyManagerSystemApplication::HandleAccept, this)
  );
  m_sinkSocket->SetCloseCallbacks (
    MakeCallback (&QKDKeyManagerSystemApplication::HandlePeerClose, this),
    MakeCallback (&QKDKeyManagerSystemApplication::HandlePeerError, this)
  ); 
}

void
QKDKeyManagerSystemApplication::ConnectToSDNController(){

  NS_LOG_FUNCTION(this 
    << m_sdnControllerAddress.IsInvalid() 
    << m_sdnControllerAddress 
    << InetSocketAddress::ConvertFrom(m_sdnControllerAddress).GetIpv4 () 
    << InetSocketAddress::ConvertFrom(m_sdnControllerAddress).GetPort ()
  );

  if(m_sdnControllerAddress.IsInvalid() == 0) {

    if(!m_sendSocketToSDN){
      Address sdnAddr = InetSocketAddress(
        InetSocketAddress::ConvertFrom(m_sdnControllerAddress).GetIpv4 (),
        InetSocketAddress::ConvertFrom(m_sdnControllerAddress).GetPort ()
      );
      m_sendSocketToSDN = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId () );
      m_sendSocketToSDN->Bind ();
      m_sendSocketToSDN->ShutdownRecv ();
      m_sendSocketToSDN->SetConnectCallback (
        MakeCallback (&QKDKeyManagerSystemApplication::ConnectionToSDNSucceeded, this),
        MakeCallback (&QKDKeyManagerSystemApplication::ConnectionToSDNFailed, this)); 
      m_sendSocketToSDN->SetDataSentCallback (
        MakeCallback (&QKDKeyManagerSystemApplication::DataToSDNSend, this));  
      m_sendSocketToSDN->Connect ( sdnAddr );
      NS_LOG_FUNCTION (this << "Create new APP socket " << m_sendSocketToSDN << " to reach SDN Controller!");
    }else{
       NS_LOG_FUNCTION (this << "Socket to reach SDN Controller exists!" << m_sendSocketToSDN);
    }

    if(!m_sinkSocketFromSDN){

      // Create the sink socket if not already 
      m_sinkSocket = Socket::CreateSocket (GetNode (), m_tid);
      NS_LOG_FUNCTION (this << "Create the sink KMS socket!" << m_sinkSocketFromSDN); 

      uint32_t sdnPort = InetSocketAddress::ConvertFrom(m_sdnControllerAddress).GetPort ();
      NS_LOG_FUNCTION (this 
        << "Sink KMS socket listens on " 
        << m_local 
        << " and port " << sdnPort
        << " for SDN packets" 
      );
     // InetSocketAddress sinkAddress = InetSocketAddress (m_local, sdnPort);
      InetSocketAddress sinkAddress = InetSocketAddress (Ipv4Address::GetAny (), sdnPort);

      m_sinkSocket->Bind (sinkAddress);
      m_sinkSocket->Listen ();
      m_sinkSocket->ShutdownSend ();
      m_sinkSocket->SetRecvCallback (MakeCallback (&QKDKeyManagerSystemApplication::HandleReadSDN, this));
      m_sinkSocket->SetAcceptCallback (
        MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
        MakeCallback (&QKDKeyManagerSystemApplication::HandleAcceptSDN, this)
      );
      m_sinkSocket->SetCloseCallbacks (
        MakeCallback (&QKDKeyManagerSystemApplication::HandlePeerCloseSDN, this),
        MakeCallback (&QKDKeyManagerSystemApplication::HandlePeerErrorSDN, this)
      ); 

    }

  }
}

void 
QKDKeyManagerSystemApplication::StopApplication (void) // Called at time specified by Stop
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

uint32_t
QKDKeyManagerSystemApplication::ScheduleCheckAssociation(Time t, std::string action, std::string ksid)
{
    NS_LOG_FUNCTION(this << "Scheduling new event in an attempt to fill association buffer " << ksid << " ...");
    uint32_t scheduleID {0};
    EventId event;
    if(action == "CheckAssociation"){
        event = Simulator::Schedule (t, &QKDKeyManagerSystemApplication::CheckAssociation, this, ksid);
        //scheduleID = event.GetUid();
        //m_scheduledChecks.insert( std::make_pair( scheduleID ,  event) );
        NS_LOG_FUNCTION(this << "Event successfully scheduled!");
    }else
        NS_FATAL_ERROR(this << "Invalid action as the function input recived " << action);

    return scheduleID;
}

/**
 * ********************************************************************************************

 *        Southbound interface functions (ETSI 014 & ETSI 004)
 
 * ********************************************************************************************
 */

void 
QKDKeyManagerSystemApplication::ProcessRequest (HTTPMessage headerIn, Ptr<Packet> packet, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this);
  
  std::string ksid;
  std::string slave_SAE_ID;
  QKDKeyManagerSystemApplication::RequestType requestType = NONE;
  std::vector<std::string> uriParams = ProcessUriParams(headerIn.GetUri());

  if( 
    uriParams.size() > 3 && 
    uriParams[1] == "api" &&
    uriParams[2] == "v1" &&
    uriParams[3] == "keys"
  ){
    
    std::string receivedAddressStr (uriParams[0]);
    Ipv4Address receivedAddress = Ipv4Address(receivedAddressStr.c_str());  //string to IPv4Address
    NS_LOG_FUNCTION(this << "received address" << receivedAddressStr << receivedAddress);
    if(receivedAddress != GetAddress()){
      NS_FATAL_ERROR ( this << "The request is not for me!\t" << receivedAddress << "\t" << GetAddress() << "\t" << headerIn.GetUri()); 
      //@toDo: redirect to top-level KMS
    }
    slave_SAE_ID = uriParams[4];
    ksid = uriParams[4];
    requestType = FetchRequestType(uriParams[5]);
  }

  NS_LOG_FUNCTION(this << "uri:" << headerIn.GetUri());
  NS_LOG_FUNCTION (this << "slave_SAE_ID: " << slave_SAE_ID << "requestType: " << requestType ); 
  if(requestType ==  ETSI_QKD_014_GET_STATUS){ //Process status request
      
      /*********************************
       * PROCESS GET_STATUS
       *********************************/

      NS_LOG_FUNCTION ( this << "Fetch status from QKD buffers for connection to destination node" << slave_SAE_ID );
      
      QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid );
      NS_ASSERT(appConnection.IsValid());
      appConnection.PrintRegistryInfo();

      QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
      NS_ASSERT(conn.IsValid());
      conn.PrintRegistryInfo();
 
      Ipv4Address srcKmsAddress = GetAddress();
      std::ostringstream srcKmsAddressTemp; 
      srcKmsAddress.Print(srcKmsAddressTemp); //IPv4Address to string
      std::string srcKME = srcKmsAddressTemp.str ();

      Ipv4Address dstKmsAddress = conn.GetDestinationKmsAddress();
      std::ostringstream dstKmsAddressTemp; 
      dstKmsAddress.Print(dstKmsAddressTemp); //IPv4Address to string
      std::string dstKME = dstKmsAddressTemp.str ();
 
      //Status data format (ETSI014) of response!
      nlohmann::json j;
      j["source_KME_ID"] = srcKME;
      j["target_KME_ID"] = dstKME;
      j["master_SAE_ID"] = GetNode()->GetId();
      j["slave_SAE_ID"] = slave_SAE_ID;
      j["key_size"] = m_defaultKeySize; //conn.bufferAlice->GetKeySize();

      Ptr<QKDBuffer> buffer = conn.GetSourceBuffer();
      if(buffer){
          j["stored_key_count"] = buffer->GetKeyCountBit();
          j["max_key_count"] = buffer->GetMaxKeyCount();
      }else{
          j["stored_key_count"] = 0;
          j["max_key_count"] = 0;
      }

      j["max_key_per_request"] = GetMaxKeyPerRequest();
      j["max_key_size"] = m_maxKeySize; //conn.bufferAlice->GetMaxKeySizeBit();
      j["min_key_size"] = m_minKeySize; //conn.bufferAlice->GetMinKeySizeBit();
      j["max_SAE_ID_count"] = 0;
      NS_LOG_FUNCTION( this << "json_response:" << j.dump() ); 
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
            
      NS_LOG_FUNCTION (this << "Sending Response to ETSI_QKD_014_GET_STATUS\n PacketID: " << packet->GetUid() << " of size: " << packet->GetSize() << hMessage  );
      SendToSocketPair(socket, packet);   
 
  }else if(requestType == ETSI_QKD_014_GET_KEY){

      /*********************************
       * PROCESS GET_KEY
       ********************************/ 

      NS_LOG_FUNCTION ( this << "Processing ETSI 014 get_key request" );
      uint32_t keyNumber = 1; //Default value
      uint32_t keySize = m_defaultKeySize; //Default value
      nlohmann::json jrequest; //JSON request structure
      nlohmann::json errorDataStructure; //JSON error response

      QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid );
      NS_ASSERT(appConnection.IsValid());
      appConnection.PrintRegistryInfo();

      QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
      NS_ASSERT(conn.IsValid());
      conn.PrintRegistryInfo();

      NS_LOG_FUNCTION(this << conn.GetId() << headerIn.GetUri());

      if(headerIn.GetMethod() == HTTPMessage::HttpMethod::GET){
          int k = 5;
          while(k < int(uriParams.size())){ //Read number and size from URI
              if(uriParams[k] == "number")
                keyNumber = std::stoi(uriParams[k+1]);
              else if(uriParams[k] == "size")
                keySize = std::stoi(uriParams[k+1]); //Key size in bits!
              k += 2;
          }
          jrequest = {{"number", keyNumber}, {"size", keySize}}; //Create jrequest based on URI
      
      }else if(headerIn.GetMethod() == HTTPMessage::HttpMethod::POST){
          std::string payload = headerIn.GetMessageBodyString(); //Read payload 
          try{ //Try parse JSON
              jrequest = nlohmann::json::parse(payload);
              if (jrequest.contains("number"))
                  keyNumber = jrequest["number"];
              if (jrequest.contains("size"))
                  keySize = uint32_t(jrequest["size"]); //Key size in bits!
          }catch(...){
              NS_FATAL_ERROR( this << "JSON parse error of the received payload: " << payload << "\t" << payload.length() );
          }

      }else
          NS_FATAL_ERROR(this << "Invalid HTTP request method" << headerIn.GetMethod()); //@toDo: include HTTP response?

      errorDataStructure = Check014GetKeyRequest(jrequest, conn); //Check get_key request!
      if(!errorDataStructure.empty()){ //Respond with error!

        NS_LOG_FUNCTION( this << "Get key request error" << errorDataStructure.dump() ); 
        HTTPMessage::HttpStatus statusCode = HTTPMessage::HttpStatus::BadRequest; //Response status code!
        if(errorDataStructure.contains("message")){
            if(errorDataStructure["message"] == "keys are being transformed"){
                statusCode = HTTPMessage::HttpStatus::ServiceUnavailable;
                conn.GetSourceBuffer()->RecordTargetSize(keySize);
                TransformKeys(keySize, keyNumber, UUID{ksid} ); //Transform keys
            }else if(errorDataStructure["message"] == "insufficient amount of key material")
                statusCode = HTTPMessage::HttpStatus::ServiceUnavailable;
        }
        errorDataStructure["ksid"] = ksid;
        std::string msg = errorDataStructure.dump();

        //create packet
        HTTPMessage httpMessage; 
        httpMessage.CreateResponse(statusCode, msg, {
          {"Content-Type", "application/json; charset=utf-8"}, 
          {"Request URI", headerIn.GetUri() }
        });
        std::string hMessage = httpMessage.ToString(); 
        Ptr<Packet> packet = Create<Packet> (
          (uint8_t*) (hMessage).c_str(),
          hMessage.size()
        );
        NS_ASSERT (packet); 

        NS_LOG_FUNCTION (this << "1185 Sending Response to ETSI_QKD_014_GET_KEY\n PacketID: " << packet->GetUid() << " of size: " << packet->GetSize() << hMessage  );
        SendToSocketPair(socket, packet);

      }else{ //Respond to get_key request!
          
        std::vector<Ptr<QKDKey>> keys {}; //Vector of QKD keys!
        Ptr<QKDBuffer> buffer = conn.GetSourceBuffer(); //Obtain the object of the corresponding QKD buffer!
        if(buffer){
          buffer->RecordTargetSize(keySize);
          for(uint32_t i = 0; i < keyNumber; i++){ 
            keys.push_back(buffer->FetchKeyBySize(keySize)); //Obtain keys!
          }
        }else {
          NS_FATAL_ERROR( this << "Buffer not found! ");
        }
        
        NS_ASSERT(keys.size() == keyNumber); //Unexpected error
        nlohmann::json jkeys = CreateKeyContainer(keys);
        jkeys["ksid"] = ksid;
        std::string msg = jkeys.dump();
        NS_LOG_FUNCTION( this << "json_response:" << msg );

        //@toDo: reserve these keys on peer KMS -> KMS to KMS reserve_keys

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
 
        NS_LOG_FUNCTION( this << "1221 Sending Response to ETSI_QKD_014_GET_KEY\n PacketID: " << packet->GetUid() << " of size: " << packet->GetSize() << hMessage  );
        SendToSocketPair(socket, packet);

        //FIRE TRACE SOURCES 
        for(uint32_t i=0; i<keys.size(); i++){
          m_keyServedETSI014Trace(ksid, keys[i]);
        }

        m_keyServedTraceEmir (keyNumber * keySize);
        //m_keyServedTrace(dstSaeId, keySizeServed); //Record amount of served key to the end-user application
        //m_keyServedWithKSIDTrace(ksid, dstSaeId, keySizeServed); //Record amount of served key to the end-user application
      }    

  }else if(requestType == ETSI_QKD_014_GET_KEY_WITH_KEY_IDS){

      /*********************************
       * PROCESS GET_KEY_WITH_KEYIDs
       *********************************/
      
      NS_LOG_FUNCTION( this << "Processing ETSI 014 get_key_with_key_ids request" );
      
      QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid );
      NS_ASSERT(appConnection.IsValid());
      appConnection.PrintRegistryInfo();

      QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
      NS_ASSERT(conn.IsValid());
      conn.PrintRegistryInfo();

      std::string payload = headerIn.GetMessageBodyString(); //Read payload
      nlohmann::json jkeyIDs;
      try{
          jkeyIDs = nlohmann::json::parse(payload); //Parse packet payload to JSON structure
      }catch(...){
          NS_FATAL_ERROR( this << "JSON parse error!" );
      }

      std::vector<std::string> keyIDs; //Vector containing keyIDs
      for (nlohmann::json::iterator it = jkeyIDs["key_IDs"].begin(); it != jkeyIDs["key_IDs"].end(); ++it)
          keyIDs.push_back((it.value())["key_ID"]); //keyIDs read from JSON

      NS_LOG_FUNCTION( this << "Requested key with key IDs:" << keyIDs);
      //Fetch keys with defined keyIDs from buffer
      Ptr<QKDBuffer> buffer = conn.GetSourceBuffer();
      std::vector<Ptr<QKDKey>> keys {};
      if(buffer){
          for(uint32_t i = 0; i < keyIDs.size(); i++){
              Ptr<QKDKey> k = buffer->FetchKeyByID(keyIDs[i]);
              keys.push_back(k);
              if(!keys[i]){
                  keys = {}; //Only complete acceptence or refusal supported for now!
                  break;
              }
          }
      }else{
          NS_FATAL_ERROR( this << "No QKD key buffer defined!");
      }

      if(!keys.empty()){ //Respond to get_key_with_key_ids request
          
          uint32_t number = keys.size(); //number of keys
          uint32_t size = keys[0]->GetSizeInBits(); //size of key

          nlohmann::json jkeys = CreateKeyContainer(keys);
          NS_LOG_FUNCTION( this << "json_response:" << jkeys.dump() );
          std::string msg = jkeys.dump();  

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
   
          NS_LOG_FUNCTION (this << "Sending Response to ETSI_QKD_014_GET_KEY\n PacketID: " << packet->GetUid() << " of size: " << packet->GetSize() << hMessage  );
          SendToSocketPair(socket, packet);

          //FIRE TRACE SOURCE
          for(uint32_t i=0; i<keys.size(); i++){
            m_keyServedETSI014Trace(ksid, keys[i]);
          }

          m_keyServedTraceEmir(number * size);
                    
        }else{ //Respond with error massage
            nlohmann::json errorDataStructure = {{"messsage", "key access error"}}; //@toDo: response includes details: keyIds that are non existing
            std::string msg = errorDataStructure.dump();

            //create packet
            HTTPMessage httpMessage; 
            httpMessage.CreateResponse(HTTPMessage::HttpStatus::BadRequest, msg, {
              {"Content-Type", "application/json; charset=utf-8"}, 
              {"Request URI", headerIn.GetUri() }
            });
            std::string hMessage = httpMessage.ToString(); 
            Ptr<Packet> packet = Create<Packet> (
              (uint8_t*) (hMessage).c_str(),
              hMessage.size()
            );
            NS_ASSERT (packet); 

            NS_LOG_FUNCTION(this << "Sending Response to ETSI_QKD_014_GET_KEY\n PacketID: " << packet->GetUid() << " of size: " << packet->GetSize() << hMessage );
            SendToSocketPair(socket, packet);
        }
  
  } else if (requestType == ETSI_QKD_004_OPEN_CONNECT) {

      QKDKMSQueueLogic::QKDKMSQueueEntry entry;
      entry.socket = socket;
      entry.httpMessage = headerIn;
      entry.packet = packet;
      entry.ksid = ksid;

      if(m_queueLogic->Enqueue(entry) == false){
        Address adr;
        socket->GetPeerName(adr);
        InetSocketAddress iaddr = InetSocketAddress::ConvertFrom (adr);
        Ipv4Address ipAdr = iaddr.GetIpv4();
        m_dropTrace(ipAdr, packet);
      }
      entry = m_queueLogic->Dequeue();
      ProcessOpenConnectRequest(entry.httpMessage, entry.socket);

  } else if (requestType == ETSI_QKD_004_GET_KEY) {

      QKDKMSQueueLogic::QKDKMSQueueEntry entry;
      entry.socket = socket;
      entry.httpMessage = headerIn;
      entry.packet = packet;
      entry.ksid = ksid;

      /*
      Address adr;
      socket->GetPeerName(adr);
      InetSocketAddress iaddr = InetSocketAddress::ConvertFrom (adr);
      Ipv4Address ipAdr = iaddr.GetIpv4();
      NS_LOG_FUNCTION (this << "Sender IP address" << ipAdr);

      std::map<Ipv4Address, uint32_t>::iterator it = m_flagedIPAdr.find(ipAdr);
      if(it != m_flagedIPAdr.end() && it->second >= 2 && m_maliciousBlocking){
        m_dropTrace(ipAdr, packet);
        return; //Do not proceed to process this request!
      }
      NS_LOG_FUNCTION (this << "Sender IP address" << ipAdr << "\t maliciousCount:" << it->second);
      */

      if(m_queueLogic->Enqueue(entry) == false){
        std::cout << "packet dropped! \n";
        
        Address adr;
        socket->GetPeerName(adr);
        InetSocketAddress iaddr = InetSocketAddress::ConvertFrom (adr);
        Ipv4Address ipAdr = iaddr.GetIpv4();
        m_dropTrace(ipAdr, packet);
      }
      entry = m_queueLogic->Dequeue();
      ProcessGetKey004Request(entry.ksid, entry.httpMessage, entry.socket);

  } else if (requestType == ETSI_QKD_004_CLOSE) {
      ProcessCloseRequest(ksid, headerIn, socket);

  } else if (requestType == STORE_PP_KEYS) {
    
    //Read payload 
    std::string payload = headerIn.GetMessageBodyString(); 
    try {
      
      //Parse packet payload to JSON structure
      nlohmann::json payloadContent = nlohmann::json::parse(payload);
      std::string keyId = payloadContent["key_id"];
      std::string keyValue = payloadContent["key"];
      uint32_t srcNodeId = payloadContent["src_id"];
      uint32_t dstNodeId = payloadContent["dst_id"];
 
      NS_LOG_FUNCTION(this << "\nKeyID:\t" << keyId << "\n");
      //NS_LOG_FUNCTION(this << "\nKeyValue:\t" << keyValue << "\n"); 
  
      Ptr<QKDKey> newKey = Create<QKDKey> (keyId, keyValue);
      AddNewKey(newKey, srcNodeId, dstNodeId);

      m_newKeyGeneratedTrace(dstNodeId, newKey->GetSizeInBits());
      m_newKeyGeneratedTraceEmir(newKey->GetSizeInBits());
      
    } catch(...) {
      NS_LOG_FUNCTION( this << "JSON parse error!");
    }

  }
}

void 
QKDKeyManagerSystemApplication::ProcessPacketKMSs (HTTPMessage headerIn, Ptr<Packet> packet, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this);
    if(headerIn.GetUri() != "") //Process request!
        ProcessRequestKMS(headerIn, socket);
    else //Process response!
        ProcessResponseKMS(headerIn, packet, socket);
} 

void
QKDKeyManagerSystemApplication::ProcessResponseSDN (HTTPMessage headerIn, Ptr<Packet> packet, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << "Processing answer from SDN" );
    
    if(headerIn.GetStatusCode() == 200)
    {
      std::vector<std::string> uriParams = ProcessUriParams(headerIn.GetRequestUri());
      if( 
        uriParams.size() > 3 && 
        uriParams[1] == "api" &&
        uriParams[2] == "v1" &&
        uriParams[3] == "keys" &&
        uriParams[5] == "register_qkd_link"
      ){
        NS_LOG_FUNCTION(this << "Processing register_qkd_link reponse!");

        std::string payload = headerIn.GetMessageBodyString();
        nlohmann::json sdnResponse;
        try{

          sdnResponse = nlohmann::json::parse(payload);
          double QKDLinkStatsUpdateInterval = 0;
          std::string keyAssociationIdString;
          uint32_t registrationAccepted = 0;

          if (sdnResponse.contains("accepted"))                      registrationAccepted = sdnResponse["accepted"];
          if (sdnResponse.contains("qkd_link_update_interval"))      QKDLinkStatsUpdateInterval = sdnResponse["qkd_link_update_interval"];
          if (sdnResponse.contains("key_association_id"))            keyAssociationIdString = sdnResponse["key_association_id"];
          
          NS_ASSERT(QKDLinkStatsUpdateInterval > 1);
          NS_LOG_FUNCTION(this << keyAssociationIdString << registrationAccepted << QKDLinkStatsUpdateInterval);
          UUID keyAssociationId = UUID{keyAssociationIdString};

          if(registrationAccepted){

            QKDKeyAssociationLinkEntry keyAssociation = GetKeyAssociationById( UUID{keyAssociationId} );
            NS_ASSERT(keyAssociation.IsValid());
            keyAssociation.PrintRegistryInfo();
            keyAssociation.SetUpdateStatusInterval(QKDLinkStatsUpdateInterval);
            SaveKeyAssociation(keyAssociation);

            NS_LOG_FUNCTION(this << "SDN approved registration of QKD LINK between nodes " << keyAssociationId);
            EventId event = Simulator::Schedule (
              Seconds(QKDLinkStatsUpdateInterval), 
              &QKDKeyManagerSystemApplication::SendQKDLinkStatusToSDN, 
              this, 
              keyAssociationId, 
              QKDLinkStatsUpdateInterval
            );

          }else{

            NS_LOG_FUNCTION(this << "SDN FORBIDES registration of QKD LINK between nodes " << keyAssociationId);

          }

        }catch(...) {
            NS_FATAL_ERROR( this << "JSON parse error!" );
        }        

      }

    //Status indicating error!
    }else{ 

    }     
}

void
QKDKeyManagerSystemApplication::SendQKDLinkStatusToSDN(UUID linkId, double updatePeriod)
{
  NS_LOG_FUNCTION(this << linkId << updatePeriod);
 

  QKDKeyAssociationLinkEntry keyAssociation = GetKeyAssociationById( linkId );
  NS_ASSERT(keyAssociation.IsValid());
  keyAssociation.PrintRegistryInfo();

  Ptr<QKDBuffer> buffer = keyAssociation.GetSourceBuffer();
  if(buffer){  

    //Secret key rate generation (in bits per second) of the key association link.
    keyAssociation.SetSKR(buffer->GetAverageKeyGenerationRate());

    //Sum of all the application's bandwidth (in bits per second) on this particular key association link.
    keyAssociation.SetExpectedConsumption(buffer->GetAverageKeyConsumptionRate());

    //Effective secret key rate (in bits per second) generation of the key association link available after internal consumption
    double ratio = buffer->GetAverageKeyGenerationRate() - buffer->GetAverageKeyConsumptionRate();
    //if(ratio < 0) ratio = buffer->GetAverageKeyGenerationRate();
    //if ratio is negative, it means old keys are taken from the buffer (not from the newly secret key rate)
    keyAssociation.SetEffectiveSKR(ratio);

    SaveKeyAssociation(keyAssociation);
  }

  //Notify SDN Controller about the new QKD LINK
  //send the packet only if connected!
  if(m_sdnSupportEnabled && connectedToSDN){

    nlohmann::json j;
    j["key_association_id"] = keyAssociation.GetId().string();
    
    //save to variable since GetSkr or other call sometimes return "null"
    //saving to variables convert these values to 0
    double skr = keyAssociation.GetSKR();
    NS_ASSERT(skr >=0 );
    j["qkdl_performance_skr"] = skr;

    double expectedConsumption = keyAssociation.GetExpectedConsumption();
    NS_ASSERT(expectedConsumption >=0 );
    j["qkdl_performance_expected_consumption"] = expectedConsumption;
    
    double eskr = keyAssociation.GetEffectiveSKR();
    NS_ASSERT(eskr >=0 );
    j["qkdl_performance_eskr"] = eskr;

    NS_LOG_FUNCTION( this << "Prepared JSON_PACKET_TO_SDN:" << j.dump() << skr << expectedConsumption << eskr );

    std::string msg = j.dump();
    HTTPMessage httpHead;

    Ipv4Address sdnAddress = InetSocketAddress::ConvertFrom(m_sdnControllerAddress).GetIpv4 ();
    std::ostringstream sdnAddressTemp; 
    sdnAddress.Print(sdnAddressTemp); //IPv4Address to string 

    std::ostringstream skmsAddressTemp; 
    keyAssociation.GetDestinationKmsAddress().Print(skmsAddressTemp); //IPv4Address to string
    std::string skmsAddressString = skmsAddressTemp.str(); //Uri starts with destination KMS address

    std::string headerUri = "http://" + sdnAddressTemp.str ();
    headerUri += "/api/v1/keys/" + skmsAddressString + "/key_association_status";

    //Create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateRequest(headerUri, "POST", msg);
    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packet = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    ); 
    NS_ASSERT (packet);
    
    NS_LOG_FUNCTION (this << "Sending KEY_ASSOCIATION_STATUS to SDN CONTROLLER\n PacketID: " 
      << packet->GetUid() << " of size: " << packet->GetSize() 
      << hMessage
    );
    m_sendSocketToSDN->Send(packet);
  
  }

  if(m_sdnSupportEnabled){

    EventId event = Simulator::Schedule (
      Seconds(updatePeriod), 
      &QKDKeyManagerSystemApplication::SendQKDLinkStatusToSDN, 
      this, 
      keyAssociation.GetId(), 
      keyAssociation.GetUpdateStatusInterval()
    );
  }
  

}

void
QKDKeyManagerSystemApplication::ProcessRequestSDN (HTTPMessage headerIn, Ptr<Packet> packet, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << "Processing request from SDN" );
    
    //Status OK
    if(headerIn.GetStatusCode() == 200)
    {
      std::vector<std::string> uriParams = ProcessUriParams(headerIn.GetRequestUri());
      if( 
        uriParams.size() > 3 && 
        uriParams[1] == "api" &&
        uriParams[2] == "v1" &&
        uriParams[3] == "keys" &&
        uriParams[5] == "register_qkd_link"
      ){
        NS_LOG_FUNCTION(this << "Processing register_qkd_link reponse!");
      }

    //Status indicating error!
    }else{ 

    }   
}

std::vector<std::string>
QKDKeyManagerSystemApplication::ProcessUriParams(std::string s)
{
  NS_LOG_FUNCTION(this << s);
  std::vector<std::string> uriParams;
  
  if(s.length() > 0){
    std::string delimiter = "/";  
    size_t pos = 0;
    std::string token;
    while ((pos = s.find(delimiter)) != std::string::npos) {
      token = s.substr(0, pos);
      if(token.length() > 0){
        uriParams.push_back(token);
      }
      s.erase(0, pos + delimiter.length());
    }
    if(s.length() > 0)
      uriParams.push_back(s);
   
    NS_LOG_FUNCTION(this << uriParams[0]);
  }

  return uriParams;
}
 

void
QKDKeyManagerSystemApplication::ProcessRequestKMS (HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << "Processing request from peer KMS ... " );
    QKDKeyManagerSystemApplication::RequestType requestType = NONE;
    std::vector<std::string> uriParams = ProcessUriParams(headerIn.GetUri());

    NS_LOG_FUNCTION( this << "krecA" << uriParams[0] << uriParams[1] << uriParams[2] << uriParams[3] );
    if( 
        uriParams.size() > 3 &&  //@toDo for etsi 004 functions add KMS address in URI!
        uriParams[1] == "api" &&
        uriParams[2] == "v1" &&
        (uriParams[3] == "associations" ||
        uriParams[3] == "keys")
    ){
        requestType = FetchRequestType(uriParams[4]); // new_app, register, fill, transform_keys, close
    }

    if(requestType == NEW_APP)
        ProcessNewAppRequest(headerIn, socket);
    else if(requestType == REGISTER){
        std::string ksid = uriParams[5];
        NS_ASSERT ( !ksid.empty() );
        ProcessRegisterRequest(headerIn, ksid, socket);
    }else if(requestType == FILL){
        std::string ksid = uriParams[5];
        NS_ASSERT ( !ksid.empty() );
        ProcessAddKeysRequest(headerIn, socket, ksid); //Process proposal of keys!
    }else if(requestType == TRANSFORM_KEYS){
        ProcessTransformRequest(headerIn, socket);
    }else if(requestType == ETSI_QKD_004_KMS_CLOSE){
        std::string ksid = uriParams[5];
        NS_ASSERT ( !ksid.empty() );
        ProcessKMSCloseRequest(headerIn, socket, ksid);
    }else
        NS_FATAL_ERROR( this << "Invalid request made to this KMS!" );
}

void
QKDKeyManagerSystemApplication::ProcessResponseKMS (HTTPMessage headerIn, Ptr<Packet> packet, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION( this << "Processing peer KMS response" );
  Ipv4Address dstKMS = GetDestinationKmsAddress(socket);
  QKDKeyManagerSystemApplication::RequestType methodType = HttpQueryMethod(dstKMS);

  if(methodType == NEW_APP)
      ProcessNewAppResponse(headerIn, socket);
  else if(methodType == REGISTER)
      ProcessRegisterResponse(headerIn, socket);
  else if(methodType == FILL)
      ProcessAddKeysResponse(headerIn, socket);
  else if(methodType == TRANSFORM_KEYS)
      ProcessTransformResponse(headerIn, socket);
  else if(methodType == ETSI_QKD_004_KMS_CLOSE)
      ProcessKMSCloseResponse(headerIn, socket);
  else
    NS_FATAL_ERROR( this << "Invalid request method!" );

}


/**
 * ********************************************************************************************

 *        ETSI004 APP-KMS functions
 
 * ********************************************************************************************
 */

bool
QKDKeyManagerSystemApplication::CheckDoSAttack(HTTPMessage headerIn, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION(this);

  //Get the address of the application node making this malicious request
  Address adr;
  socket->GetPeerName(adr);
  InetSocketAddress iaddr = InetSocketAddress::ConvertFrom (adr);
  Ipv4Address ipAdr = iaddr.GetIpv4();
  NS_LOG_FUNCTION (this << "Sender IP address" << ipAdr);

  if(m_maliciousBlocking){
    std::map<Ipv4Address, uint32_t>::iterator it = m_flagedIPAdr.find(ipAdr);
    if(it == m_flagedIPAdr.end()){
      m_flagedIPAdr.insert(std::make_pair(ipAdr, 1));
      NS_LOG_FUNCTION (this << "This request has been flaged as potentialy malicious!"
                            << "This IPAddress" << ipAdr << "will be penalized after the next offense!"); 
    }else{
      NS_LOG_FUNCTION (this << "KMS identified request coming from" << ipAdr << "as malicious request."
                            << "This IPAddress is now blocked!");
      it->second++;
      return true;
    }
  }
  return false;
}

/**
 * Here we check whether new OPEN_CONNECT was received before the previoulsy established 
 * session expired. If yes, we remove KSID from the m_session_list. 
 * If not, we incerment value in m_session_list for KSID
 * \param std::string KSID
 */
void
QKDKeyManagerSystemApplication::CheckSessionList(std::string ksid)
{
  NS_LOG_FUNCTION(this << ksid);

  NS_LOG_FUNCTION(this << "Checking the state of the association " << ksid << " ...");
  std::map<std::string, Association004>::iterator it = m_associations004.find(ksid);
  if(it == m_associations004.end()){
    NS_LOG_DEBUG( this << " Key stream association identified with " << ksid << " does not exists!" );
  }else{
    if(
      (it->second).tempBuffer.empty() && 
      ((it->second).buffer.empty() || !(it->second).buffer.begin()->second.ready)
    ){  
      NS_LOG_FUNCTION(this << ksid << "SESSION EXPIRED!");
      std::map<std::string, uint32_t>::iterator it2 = m_sessionList.find(ksid);
      if(it2 != m_sessionList.end()){
        it2->second++;
        NS_LOG_FUNCTION(this << "SESSION with KSID " << ksid << " was favored in the m_session_list!");
      }else{
        NS_LOG_FUNCTION(this << "SESSION with KSID " << ksid << " was not located in m_session_list!");
      }
    }else{
      NS_LOG_FUNCTION(this << ksid << "SESSION DID NOT EXPIRE!"); 
      std::map<std::string, uint32_t>::iterator it2 = m_sessionList.find(ksid);
      if(it2 != m_sessionList.end()){
        m_sessionList.erase(it2);
        NS_LOG_FUNCTION(this << "SESSION with KSID " << ksid << " was removed from the m_session_list!");
      }else{
        NS_LOG_FUNCTION(this << "SESSION with KSID " << ksid << " was not located in m_session_list!");
      } 
    }
  }
}

void
QKDKeyManagerSystemApplication::ProcessOpenConnectRequest (HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << headerIn.GetUri());

    if(CheckDoSAttack(headerIn, socket)) return;

    std::string payload = headerIn.GetMessageBodyString();
    NS_LOG_FUNCTION( this << payload);

    nlohmann::json jOpenConnectRequest;
    try{
        jOpenConnectRequest = nlohmann::json::parse(payload);
    }catch(...) {
        NS_FATAL_ERROR( this << "JSON parse error!" );
    }

    std::string ksid;
    std::string dstSaeId;
    std::string srcSaeId;
    QKDKeyManagerSystemApplication::QoS inQos;
    if(jOpenConnectRequest.contains("Key_stream_ID")) ksid     = jOpenConnectRequest["Key_stream_ID"];
    if(jOpenConnectRequest.contains("Source"))        srcSaeId = jOpenConnectRequest["Source"];
    if(jOpenConnectRequest.contains("Destination"))   dstSaeId = jOpenConnectRequest["Destination"];
    NS_ASSERT (srcSaeId.length() > 0);
    NS_ASSERT (dstSaeId.length() > 0); 

    NS_LOG_FUNCTION(this << ksid << srcSaeId << dstSaeId);

    if(ksid.length() > 0) CheckSessionList(ksid);

    ReadJsonQos(inQos, jOpenConnectRequest);
    
    bool callByMaster {ksid.empty()};
    if(callByMaster){

        std::vector<std::string> uriParams = ProcessUriParams(headerIn.GetUri());
        uint32_t type = std::stoi(uriParams[6]); 

        QKDApplicationEntry::ConnectionType linkType = QKDApplicationEntry::NONE;
        if(type == 0) {
          linkType = QKDApplicationEntry::ETSI_QKD_004_ENCRYPTION;
        }else if(type == 1) {
          linkType = QKDApplicationEntry::ETSI_QKD_004_AUTHENTICATION;
        }
        NS_ASSERT (linkType == QKDApplicationEntry::ETSI_QKD_004_ENCRYPTION || linkType == QKDApplicationEntry::ETSI_QKD_004_AUTHENTICATION);
        //1-etsi014 (encryption); 2-etsi014(auth); 3-etsi004(encryption); 4-etsi004(auth)

        //ksid is empty
        //we need to fetch QKD application entry (if any)
        QKDApplicationEntry appConnection = GetApplicationConnectionDetailsBySaeIDsAndType( srcSaeId, dstSaeId, linkType );
        appConnection.PrintRegistryInfo();

        //there is no connection found in our registry
        //we might connect to other networks (roaming) or ask SDN controller
        //about further actions. However, for now we throw exception!
        //we DO NOT create new SAE connection here since in case of DDoS attack
        // it would be very expensive decision. Registration of SAEs MUST be indidiviual task!
        NS_ASSERT(appConnection.IsValid());

        //now we have connection details. 
        //let's find for associated key association link
        //if multiple links are associated, then randomly selected one!
        QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
        NS_ASSERT(conn.IsValid());
        conn.PrintRegistryInfo();

        NS_LOG_FUNCTION(this << "Processing OPEN_CONNECT request submitted by the primary QKDApp ...");
        Ipv4Address dstKms = conn.GetDestinationKmsAddress();

        //CAC verification
        QKDKeyManagerSystemApplication::QoS providedQoS;
        bool acceptRequest = ProcessQoSRequest(appConnection, conn, inQos, providedQoS, ksid);

        if(acceptRequest){

          //Create association with provided QoS
          CreateNew004Association(
            srcSaeId, 
            dstSaeId, 
            providedQoS, 
            dstKms, 
            ksid,
            appConnection.GetId().string()
          ); //Establish association
          
          if(conn.GetType() == 0){ // Direct point-to-point connection. Respond immediately
              nlohmann::json jOpenConnectResponse;
              jOpenConnectResponse["Key_stream_ID"] = ksid;
              jOpenConnectResponse["QoS"] = {
                {"priority",        providedQoS.priority},
                {"max_bps",         providedQoS.maxRate},
                {"min_bps",         providedQoS.minRate},
                {"jitter",          providedQoS.jitter},
                {"timeout",         providedQoS.timeout},
                {"key_chunk_size",  providedQoS.chunkSize},
                {"TTL",             providedQoS.TTL} 
              }; 
              std::string msg = jOpenConnectResponse.dump();

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

              SendToSocketPair(socket, packet);

              NS_LOG_FUNCTION(this << "KMS providing OK answer to OPEN_CONNECT!" << msg << packet->GetUid() << packet->GetSize());

          }else{ //Wait on NewAppResponse to respond to QKDApp
              Http004AppQuery(UUID{srcSaeId}, socket); //Query this received HTTP request!
          }
          NewAppRequest(ksid); //Send NEW_APP notification
        }else{

          NS_LOG_FUNCTION(this << "KMS is not able to answer to QoS request from the application " << appConnection.GetId().string());

          //create packet
          HTTPMessage httpMessage; 
          httpMessage.CreateResponse(HTTPMessage::HttpStatus::BadRequest, "", { 
            {"Request URI", headerIn.GetUri() }
          });
          std::string hMessage = httpMessage.ToString(); 
          Ptr<Packet> packet = Create<Packet> (
            (uint8_t*) (hMessage).c_str(),
            hMessage.size()
          );
          NS_ASSERT (packet); 
 
          SendToSocketPair(socket, packet);
          
        }

    } else {
      
      NS_LOG_FUNCTION( this << "OPEN_CONNECT by Replica SAE" );
      //Check if ksid has been registered for this SAE
      std::map<std::string, Association004>::iterator it = m_associations004.find(ksid);
      if (it == m_associations004.end()) {
          NS_LOG_DEBUG( this << " Key stream association identified with " << ksid << " does not exists!" );
          return;
      } else if ((it->second).srcSaeId != UUID{srcSaeId}) {
          NS_LOG_FUNCTION( this << "KSID is not registered for this application" << (it->second).dstSaeId << srcSaeId ); 
          //Respond with an error! //@toDo
      } else {
          
          (it->second).peerRegistered = true;
          RegisterRequest(ksid);

          //Respond to OPEN_CONNECT made by SAE

          //create packet
          HTTPMessage httpMessage; 
          httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, "", {
            {"Request URI", headerIn.GetUri() }
          });
          std::string hMessage = httpMessage.ToString(); 
          Ptr<Packet> packet = Create<Packet> (
            (uint8_t*) (hMessage).c_str(),
            hMessage.size()
          );
          NS_ASSERT (packet); 
 
          SendToSocketPair(socket, packet);

      }
    }

}

void
QKDKeyManagerSystemApplication::ProcessGetKey004Request (std::string ksid, HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << "Processing get_key request (ETSI 004)" << ksid );

    std::map<std::string, Association004>::iterator it = m_associations004.find(ksid);
    if(it == m_associations004.end()){

        if(CheckDoSAttack(headerIn, socket)) return;

        NS_LOG_DEBUG( this << " Key stream association identified with " << ksid << " does not exists!" );
        
        //create packet
        HTTPMessage httpMessage; 
        httpMessage.CreateResponse(HTTPMessage::HttpStatus::BadRequest, "", {
          {"Request URI", headerIn.GetUri() }
        });
        std::string hMessage = httpMessage.ToString(); 
        Ptr<Packet> packet = Create<Packet> (
          (uint8_t*) (hMessage).c_str(),
          hMessage.size()
        );
        NS_ASSERT (packet); 

        SendToSocketPair(socket, packet);
        return;
    } 

    //PeerRegistered must be true @toDo - first check this (in case of QKDApp004 this will never happen)
    if( !(it->second).buffer.empty() && (it->second).buffer.begin()->second.ready )
    {

        QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid );
        if(appConnection.IsValid())
        {
          appConnection.PrintRegistryInfo();
        
          uint32_t index;
          std::string key;
          index = (it->second).buffer.begin()->first;
          key = (it->second).buffer.begin()->second.key;
          (it->second).buffer.erase((it->second).buffer.begin()); //Remove the key
          if(it->second.associationDirection == 0){
            CheckAssociation(ksid); //Check if new keys need to be negotiated
          }

          nlohmann::json jresponse;
          jresponse["index"] = index;
          jresponse["Key_buffer"] = key;
          //No Metadata
          std::string msg = jresponse.dump();

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

          SendToSocketPair(socket, packet);
 
          //TEST LINES - @toDo: remove after testing
          QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
          NS_ASSERT(conn.IsValid());
          conn.PrintRegistryInfo();
          NS_LOG_FUNCTION(this 
            << conn.GetId() 
            << headerIn.GetUri()
            << msg
            << "AverageKeyGenerationRate:" << conn.GetSKR()
            << "ExpectedConsumption:" << conn.GetExpectedConsumption()
            << "EffectiveSKR:" << conn.GetEffectiveSKR()
          );
          //end of test lines

          m_keyServedETSI004Trace(ksid, index, key.size()*8 );
          m_keyServedTraceEmir(key.size()*8);

        }else{

          //ASSOCIATION TTL EXPIRED AND REMOVED
          NS_LOG_FUNCTION(this << "Association was not found!" << it->second.dstSaeId.string() );

          //create packet
          HTTPMessage httpMessage; 
          httpMessage.CreateResponse(HTTPMessage::HttpStatus::BadRequest, "", { 
            {"Request URI", headerIn.GetUri() }
          });
          std::string hMessage = httpMessage.ToString(); 
          Ptr<Packet> packet = Create<Packet> (
            (uint8_t*) (hMessage).c_str(),
            hMessage.size()
          );
          NS_ASSERT (packet);

          SendToSocketPair(socket, packet);

        }

    }else{

        //Respond with an error. Currently this is the only error on GetKey004, therefore no message is included. @toDo
        NS_LOG_FUNCTION(this << "No keys available in the association buffer. Responding on the request ...");
        
        //create packet
        HTTPMessage httpMessage; 
        httpMessage.CreateResponse(HTTPMessage::HttpStatus::BadRequest, "", { 
          {"Request URI", headerIn.GetUri() }
        });
        std::string hMessage = httpMessage.ToString(); 
        Ptr<Packet> packet = Create<Packet> (
          (uint8_t*) (hMessage).c_str(),
          hMessage.size()
        );
        NS_ASSERT (packet); 
 
        //TEST LINES - @toDo: remove after testing
        /*
        QKDApplicationEntry appConnection = GetApplicationConnectionDetails( it->second.dstSaeId.string() );
        NS_ASSERT(appConnection.IsValid());
        appConnection.PrintRegistryInfo();
        QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
        NS_ASSERT(conn.IsValid());
        conn.PrintRegistryInfo();
        NS_LOG_FUNCTION(this 
          << conn.GetId() 
          << headerIn.GetUri()
          << "AverageKeyGenerationRate:" << conn.GetSKR()
          << "ExpectedConsumption:" << conn.GetExpectedConsumption()
          << "EffectiveSKR:" << conn.GetEffectiveSKR()
        );
        */
        //end of test lines

        SendToSocketPair(socket, packet);
    }

}

void
QKDKeyManagerSystemApplication::ProcessCloseRequest(std::string ksid, HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << "Processing CLOSE request ... " << ksid );

    std::map<std::string, Association004>::iterator it = m_associations004.find(ksid);
    if(it == m_associations004.end()){
      NS_LOG_DEBUG( this << " Key stream association identified with " << ksid << " does not exists!" );
      return;
    }

    HttpQuery query;
    query.method_type = ETSI_QKD_004_KMS_CLOSE; //Close made to peer KMS
    query.ksid = ksid; //Remember ksid
    if(!it->second.buffer.empty()){
        query.surplus_key_ID = GenerateKeyId(); //Generate keyId to empty key stream association
        query.sync_index = it->second.buffer.begin()->first; //Take the first index in the buffer!
    }

    QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid );
    NS_ASSERT(appConnection.IsValid());
    appConnection.PrintRegistryInfo();

    QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
    NS_ASSERT(conn.IsValid());
    conn.PrintRegistryInfo();
 
    NS_LOG_FUNCTION( this << "Releasing key stream association buffer. Synchronizing with peed KMS ... ");
    CheckSocketsKMS( (it->second).dstKmsNode ); //Check connection to peer KMS!
    Ptr<Socket> sendSocket = GetSendSocketKMS ( (it->second).dstKmsNode );
    NS_ASSERT (sendSocket);

    nlohmann::json msgBody;
    if(!query.surplus_key_ID.empty()){
        msgBody["surplus_key_ID"] = query.surplus_key_ID;
        msgBody["sync_index"] = query.sync_index;
    }
    std::string msg = msgBody.dump();

    std::ostringstream peerkmsAddressTemp; 
    (it->second).dstKmsNode.Print(peerkmsAddressTemp); //IPv4Address to string
    std::string headerUri = "http://" + peerkmsAddressTemp.str(); //Uri starts with destination KMS address
    headerUri += "/api/v1/associations/close_kms/" + ksid;

    //Create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateRequest(headerUri, "POST", msg);
    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packet = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    ); 
    NS_ASSERT (packet);

    HttpKMSAddQuery((it->second).dstKmsNode, query); //Save this query made to the peer KMS!

    sendSocket->Send(packet);
    NS_LOG_FUNCTION( this << "Synchronization information for releasing key stream association sent to peer KMS"
                          << packet->GetUid() << packet->GetSize() );

}


/**
 * ********************************************************************************************

 *        KMS-KMS functions
 
 * ********************************************************************************************
 */
void
QKDKeyManagerSystemApplication::NewAppRequest (std::string ksid)
{
    NS_LOG_FUNCTION( this );
    std::map<std::string, Association004>::iterator it = m_associations004.find(ksid);
    if (it == m_associations004.end()){
      NS_LOG_DEBUG( this << " Key stream association identified with " << ksid << " does not exists!" );
      return;
    }

    CheckSocketsKMS( (it->second).dstKmsNode ); //Check connection to peer KMS!
    Ptr<Socket> sendSocket = GetSendSocketKMS ( (it->second).dstKmsNode );
    NS_ASSERT (sendSocket);

    nlohmann::json msgBody;
    msgBody["Source"]                = (it->second).srcSaeId.string();
    msgBody["Destination"]           = (it->second).dstSaeId.string();
    msgBody["QoS"]["key_chunk_size"] = (it->second).qos.chunkSize;
    msgBody["QoS"]["max_bps"]        = (it->second).qos.maxRate;
    msgBody["QoS"]["min_bps"]        = (it->second).qos.minRate;
    msgBody["QoS"]["jitter"]         = (it->second).qos.jitter;
    msgBody["QoS"]["priority"]       = (it->second).qos.priority;
    msgBody["QoS"]["timeout"]        = (it->second).qos.timeout;
    msgBody["QoS"]["TTL"]            = (it->second).qos.TTL; 
  
      //msgBody["source_kms"] = conn.GetSourceKmsAddress(); For App Advertising
    msgBody["Key_stream_ID"] = ksid;
    std::string msg = msgBody.dump();
    
    std::ostringstream peerkmsAddressTemp; 
    (it->second).dstKmsNode.Print(peerkmsAddressTemp); //IPv4Address to string
    std::string headerUri = "http://" + peerkmsAddressTemp.str(); //Uri starts with destination KMS address
    headerUri += "/api/v1/associations/new_app";
     
    //Create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateRequest(headerUri, "POST", msg);
    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packet = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    ); 
    NS_ASSERT (packet);

    HttpQuery query;
    query.method_type = RequestType::NEW_APP;
    query.source_sae = (it->second).srcSaeId;
    query.destination_sae = (it->second).dstSaeId;
    query.ksid = ksid;
    HttpKMSAddQuery((it->second).dstKmsNode, query);

    sendSocket->Send(packet);
    NS_LOG_FUNCTION( this << "NEW_APP: KMS informs peer KMS on new association established!" );
}

void
QKDKeyManagerSystemApplication::ProcessNewAppRequest (HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << "Processing NEW_APP request!" );
    std::string payload = headerIn.GetMessageBodyString();
    nlohmann::json jNewAppRequest;
    try{
        jNewAppRequest = nlohmann::json::parse(payload);
    }catch (...){
        NS_FATAL_ERROR( this << "JSON parse error!" );
    }

    std::string srcSaeId;
    std::string dstSaeId;
    QKDKeyManagerSystemApplication::QoS inQoS;
    std::string ksid;
    if(jNewAppRequest.contains("Destination")) dstSaeId = jNewAppRequest["Destination"];
    if(jNewAppRequest.contains("Source")) srcSaeId = jNewAppRequest["Source"];
    if(jNewAppRequest.contains("Key_stream_ID")) ksid = jNewAppRequest["Key_stream_ID"];

    ReadJsonQos(inQoS, jNewAppRequest);
    NS_ASSERT(srcSaeId.length()>0 || dstSaeId.length()>0 || !ksid.empty());
    
    bool qosAgreed {true}; //Check if the QoS can be met! @toDo
    if(qosAgreed){

        NS_LOG_FUNCTION(this << srcSaeId << dstSaeId << ksid);

        QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid );
        NS_ASSERT(appConnection.IsValid());
        appConnection.PrintRegistryInfo();

        Ipv4Address dstKms = appConnection.GetDestinationKmsAddress();

        /* If it is not point-to-point connection, msg will carry and source_kms!
        This value will be used instead of dstKms from the conn stats!
        However, the response on the NewAppRequest is sent via same route
        and will carry IP address of this KMS node. @toDoR */
        CreateNew004Association(
          dstSaeId, 
          srcSaeId, 
          inQoS, 
          dstKms, 
          ksid,
          appConnection.GetId().string()
        );

        /* Send positive response on the NEW_APP request! In case where
        it is not point-to-point conncetion between the source and the destination
        msg will carry destination_kms address. @toDoR */

        //create packet
        HTTPMessage httpMessage; 
        httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, "", { 
          {"Request URI", headerIn.GetUri() }
        });
        std::string hMessage = httpMessage.ToString(); 
        Ptr<Packet> packet = Create<Packet> (
          (uint8_t*) (hMessage).c_str(),
          hMessage.size()
        );
        NS_ASSERT (packet); 

        NS_LOG_FUNCTION( this << "NEW_APP request accepted. Association created." );
        SendToSocketPairKMS(socket, packet); //Send Packet to Socket pair

    }else{
        NS_LOG_FUNCTION( this << "QoS requirements can not be satisfied" );
        //@toDoEmir Respond with an error status code (carry new QoS)!
    }

}

void
QKDKeyManagerSystemApplication::ProcessNewAppResponse (HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << "Processing NEW_APP response" );

    Ipv4Address dstKms = GetDestinationKmsAddress(socket);
    std::map<Ipv4Address, std::vector<HttpQuery> >::iterator it = m_httpRequestsQueryKMS.find(dstKms);
    
    if(it == m_httpRequestsQueryKMS.end() || (it->second).empty())
      NS_FATAL_ERROR( this << "Response cannot be mapped! HttpQuery empty!" );

    std::string ksid = it->second[0].ksid;
    
    if(headerIn.GetStatusCode() == 200){ //Status OK

      QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid );
      NS_ASSERT(appConnection.IsValid());
      appConnection.PrintRegistryInfo();

      QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
      NS_ASSERT(conn.IsValid());
      conn.PrintRegistryInfo();

      if(conn.GetHop() == 1) {//dstKms for point-to-point scenario! 
        HttpKMSCompleteQuery(dstKms); //Point-to-point scenario. Response just as acknowledgement!

      } else {//@toDo Trusted relay scenario. QKDApp is waiting for OPEN_CONNECT response!
          bool QoS {true}; //Read QoS from response, calculate its own, and make response!
          if(QoS){
              nlohmann::json jOpenConnectResponse;
              jOpenConnectResponse["Key_stream_ID"] = it->second[0].ksid;
              std::string msg = jOpenConnectResponse.dump();

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

              Ptr<Socket> responseSocket = GetSocketFromHttp004AppQuery(it->second[0].source_sae);
              Http004AppQueryComplete(it->second[0].source_sae);
              HttpKMSCompleteQuery(dstKms);
              SendToSocketPair(responseSocket, packet);
          }else{
              //Respond to the QKDApp with QoS that can be offered! @toDo Trusted relay scenario
          }
      }
  
    }else{ //Status indicating error!

        std::string ksid = it->second[0].ksid;
        QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid );
        NS_ASSERT(appConnection.IsValid());
        appConnection.PrintRegistryInfo();

        QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
        NS_ASSERT(conn.IsValid());
        conn.PrintRegistryInfo();

        if(conn.GetHop() == 1) //dstKms for point-to-point scenario! 
            HttpKMSCompleteQuery(dstKms); //Point-to-point scenario. Response just as acknowledgement!
        else{
            //Check the error! @toDo Respond to peer QKDApp in case of Trusted relay scenario!
            HttpKMSCompleteQuery(dstKms);
        }
        std::map<std::string, Association004>::iterator it = m_associations004.find(ksid);
        if(it != m_associations004.end()){
            m_associations004.erase(it); //Myb not erase, but for a few seconds mark as closed, and then erase! @toDo
        }else{
          NS_FATAL_ERROR(this << "Closing non existing association!");
        }
    }

}

void
QKDKeyManagerSystemApplication::RegisterRequest (std::string ksid)
{
    NS_LOG_FUNCTION( this << ksid );
    std::map<std::string, Association004>::iterator it = m_associations004.find(ksid); //Find association entry identified with ksid
    if(it == m_associations004.end()){
      NS_LOG_DEBUG( this << " Key stream association identified with " << ksid << " does not exists!" );
      return;
    }

    Ipv4Address dstKms = (it->second).dstKmsNode; //Read destination KMS address from the association entry

    CheckSocketsKMS( dstKms ); //Check connection to dstKms
    Ptr<Socket> sendSocket = GetSendSocketKMS ( dstKms ); //Obtain send socket object to reach dstKms

    std::ostringstream peerkmsAddressTemp;
    dstKms.Print(peerkmsAddressTemp); //IPv4Address to string
    std::string headerUri = "http://" + peerkmsAddressTemp.str (); //Read an dstKms IP address to string
    headerUri += "/api/v1/associations/register/" + ksid; //Create an URI for the register request

    //Create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateRequest(headerUri, "GET");
    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packet = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    ); 
    NS_ASSERT (packet);

    HttpQuery query;
    query.method_type = REGISTER;
    query.ksid = ksid;
    HttpKMSAddQuery(dstKms, query); //Remember HTTP query to be able to map response later

    sendSocket->Send(packet); //Send the packet to dstKms
}

void
QKDKeyManagerSystemApplication::ProcessRegisterRequest ( HTTPMessage headerIn , std::string ksid, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION(this << "Processing register request " << ksid << headerIn.GetUri() );
    std::map<std::string, Association004>::iterator it = m_associations004.find(ksid); //Find association entry identified with ksid
    if(it != m_associations004.end() && (it->second).peerRegistered != true){
        (it->second).peerRegistered = true; //Acknowledge register notification, peer QKDApp is connected!
        //Send ack on this notification

        //create packet
        HTTPMessage httpMessage; 
        httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, "", { 
          {"Content-Type", "application/json; charset=utf-8"}, 
          {"Request URI", headerIn.GetUri() }
        });
        std::string hMessage = httpMessage.ToString(); 
        Ptr<Packet> packet = Create<Packet> (
          (uint8_t*) (hMessage).c_str(),
          hMessage.size()
        );
        NS_ASSERT (packet); 
        
        SendToSocketPairKMS(socket, packet); //Sent response on register request 
        CheckAssociation(ksid);

    }else if(it == m_associations004.end()){
      NS_LOG_DEBUG( this << " Key stream association identified with " << ksid << " does not exists!" );
      return;
    }else if((it->second).peerRegistered == true){
      NS_LOG_FUNCTION(this << "The peer application for asscotiation " << ksid << " has already been connected.");
    }
}

void
QKDKeyManagerSystemApplication::ProcessRegisterResponse (HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << "Processing /register response!");
    Ipv4Address dstKms = GetDestinationKmsAddress(socket);
    std::map<Ipv4Address, std::vector<HttpQuery> >::iterator it = m_httpRequestsQueryKMS.find(dstKms);
    if(it == m_httpRequestsQueryKMS.end() || (it->second).empty())
        NS_FATAL_ERROR( this << "Response cannot be mapped! HttpQuery empty!" );

    if (headerIn.GetStatusCode() == HTTPMessage::Ok)
        NS_LOG_FUNCTION( this << "Successful notification REGISTER" );
    else {
        NS_LOG_FUNCTION( this << "/register error! Releasing established association" << it->second[0].ksid );
        std::map<std::string, Association004>::iterator it1 = m_associations004.find(it->second[0].ksid);
        if(it1 != m_associations004.end()){
            m_associations004.erase(it1); //Myb not erase, but for a few seconds mark as closed, and then erase! @toDo
        }else{
          NS_FATAL_ERROR(this << "Closing non existing association!");
        }
    }
    HttpKMSCompleteQuery(dstKms);

}

void
QKDKeyManagerSystemApplication::ProcessAddKeysRequest (HTTPMessage headerIn, Ptr<Socket> socket, std::string ksid)
{
    NS_LOG_FUNCTION( this << "Processing /fill request" << ksid );
    std::string payload = headerIn.GetMessageBodyString();
    
    nlohmann::json jAddKeysRequest;
    try{
        jAddKeysRequest = nlohmann::json::parse(payload);
    }catch (...){
        NS_FATAL_ERROR( this << "JSON parse error!" );
    }

    std::map<std::string, Association004>::iterator it = m_associations004.find(ksid);
    if(it == m_associations004.end()){
        NS_LOG_DEBUG( this << " Key stream association identified with " << ksid << " does not exists!" );
        return;
    }    
    //Ipv4Address dstKms = it->second.dstKmsNode;
    UUID dstSaeId = it->second.dstSaeId;
    QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid );
    NS_ASSERT(appConnection.IsValid());
    appConnection.PrintRegistryInfo();

    QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
    NS_ASSERT(conn.IsValid());
    conn.PrintRegistryInfo();

    Ptr<QKDBuffer> buffer = conn.GetSourceBuffer();

    bool accept = true; //For now, only full acceptance, or rejection!
    for(nlohmann::json::iterator it = jAddKeysRequest["keys"].begin(); it != jAddKeysRequest["keys"].end(); ++it){ 
        if(buffer->ProbeKeyStatus( (it.value())["key_ID"], QKDKey::READY ))
            continue;
        else{
            accept = false;
            break;
        }
    }   
    
    if(accept){
        for(nlohmann::json::iterator it = jAddKeysRequest["keys"].begin(); it != jAddKeysRequest["keys"].end(); ++it){
            Ptr<QKDKey> key = buffer->FetchKeyByID( (it.value())["key_ID"]);
            AddKeyToAssociationDedicatedStore(ksid, key);
        }

        //Create positive response
        NS_LOG_FUNCTION( this << "Replica KMS added keys " << jAddKeysRequest.dump() 
                              << " to dedicated association key store " << ksid );
        
        //create packet
        HTTPMessage httpMessage; 
        httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok, "", {  
          {"Request URI", headerIn.GetUri() }
        });
        std::string hMessage = httpMessage.ToString(); 
        Ptr<Packet> packet = Create<Packet> (
          (uint8_t*) (hMessage).c_str(),
          hMessage.size()
        );
        NS_ASSERT (packet); 
 
        NS_LOG_FUNCTION( this << "Replica KMS sending response on FILL request " 
                              << ksid << packet->GetUid() << packet->GetSize() );
        SendToSocketPairKMS(socket, packet);
    
    }else{ //Keys negotiated to FILL the association key store are not available
        NS_LOG_FUNCTION( this << "Replica KMS reject FILL request " << jAddKeysRequest.dump() 
                              << " for association " << ksid );

        //create packet
        HTTPMessage httpMessage; 
        httpMessage.CreateResponse(HTTPMessage::HttpStatus::BadRequest, "", {  
          {"Request URI", headerIn.GetUri() }
        });
        std::string hMessage = httpMessage.ToString(); 
        Ptr<Packet> packet = Create<Packet> (
          (uint8_t*) (hMessage).c_str(),
          hMessage.size()
        );
        NS_ASSERT (packet); 
 
        NS_LOG_FUNCTION( this << "Replica KMS sending response on FILL request " 
                              << ksid << packet->GetUid() << packet->GetSize() );
        SendToSocketPair(socket, packet);
    }

}

void
QKDKeyManagerSystemApplication::ProcessAddKeysResponse (HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << "Processing FILL response" );
    std::string payload = headerIn.GetMessageBodyString();

    Ipv4Address dstKms = GetDestinationKmsAddress(socket);
    std::map<Ipv4Address, std::vector<HttpQuery> >::iterator it = m_httpRequestsQueryKMS.find(dstKms);
    if(it == m_httpRequestsQueryKMS.end() || (it->second).empty())
        NS_FATAL_ERROR( this << "Response cannot be mapped! HttpQuery empty!" );

    std::string ksid = it->second[0].ksid;
    NS_ASSERT(ksid != "");
    std::map<std::string, Association004>::iterator a = m_associations004.find(ksid);
    if(a == m_associations004.end()){
      NS_LOG_DEBUG( this << " Key stream association identified with " << ksid << " does not exists!" );
      return;
    }
 
    QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid );
    NS_ASSERT(appConnection.IsValid());
    appConnection.PrintRegistryInfo();

    QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
    NS_ASSERT(conn.IsValid());
    conn.PrintRegistryInfo();

    Ptr<QKDBuffer> buffer = conn.GetSourceBuffer();

    if(!buffer)
        NS_FATAL_ERROR( this << "QKDBuffer for this connection cannot be found" );

    if (headerIn.GetStatusCode() == HTTPMessage::Ok){
        NS_LOG_FUNCTION( this << "Filling association dedicated key store" << ksid );
        for(std::vector<std::string>::iterator i = a->second.tempBuffer.begin(); i < a->second.tempBuffer.end(); ++i){
            Ptr<QKDKey> key = buffer->FetchKeyByID(*i);
            NS_ASSERT(key);
            AddKeyToAssociationDedicatedStore(ksid, key);
        }
        a->second.tempBuffer.clear(); //Release keys from tempBuffer

    }else{
      NS_LOG_FUNCTION( this << "Releasing reservation of keys " << a->second.tempBuffer );
      for(std::vector<std::string>::iterator i = a->second.tempBuffer.begin(); i < a->second.tempBuffer.end(); ++i)
          buffer->ReleaseReservation(*i);
      a->second.tempBuffer.clear();
      CheckAssociation(ksid); //Try FILL again
    }
    HttpKMSCompleteQuery(dstKms);

}

void
QKDKeyManagerSystemApplication::TransformKeys (uint32_t keySize, uint32_t keyNumber, UUID ksid)
{
    NS_LOG_FUNCTION( this << "target size" << keySize << "target number" << keyNumber << "ksid SAE" << ksid.string() );

    QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid.string() );
    NS_ASSERT(appConnection.IsValid());
    appConnection.PrintRegistryInfo();

    QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
    NS_ASSERT(conn.IsValid());
    conn.PrintRegistryInfo();
 
    Ptr<QKDBuffer> buffer = conn.GetSourceBuffer();
    buffer->RecordTargetSize(keySize);

    bool transformSetReady = false;
    if(buffer){
        std::vector<std::string> toTransformKeyIDs {}; //Choice of keys to transform
        uint32_t targetSize {keySize*keyNumber};
        while(!transformSetReady){ //Form a transform set!
            Ptr<QKDKey> key = buffer->SearchOptimalKeyToTransform(targetSize);
            NS_ASSERT(key->GetId() != ""); //Check
            NS_ASSERT(key->GetSizeInBits() != 0); //Check
            buffer->ReserveKey(key->GetId()); //Reserve key for transformation! @toDo include reservation_type
            toTransformKeyIDs.push_back(key->GetId());
            if(key->GetSizeInBits() >= targetSize)
                transformSetReady = true;
            else
                targetSize -= key->GetSizeInBits();
            //@toDo: To avoid infinite while loop perform a check on toTransformKeyIDs.size() < m_maxTransformSet - defined by KMS
        }
        //Generate newKeyIds and optionaly suprplus keyIds
        std::vector<std::string> transformKeyIDs;
        uint32_t k {0};
        while(k++<keyNumber){
            transformKeyIDs.push_back(GenerateKeyId());
        }
        std::string surplusKeyId = GenerateKeyId();
        NS_LOG_FUNCTION( this << "transform_key_size" << keySize );
        NS_LOG_FUNCTION( this << "transform_key_number" << keyNumber);
        NS_LOG_FUNCTION( this << "transform_key_IDs" << transformKeyIDs );
        NS_LOG_FUNCTION( this << "surplus_key_ID" << surplusKeyId );
        NS_LOG_FUNCTION( this << "to_transform_key_IDs" << toTransformKeyIDs );

        //Create HTTP message transform
        nlohmann::json jtransform;
        jtransform["ksid"] = ksid.string(); //Must know to find QKDBuffer!
        jtransform["transform_key_size"] = keySize;
        jtransform["transform_key_number"] = keyNumber;
        for(size_t i = 0; i < transformKeyIDs.size(); i++)
            jtransform["transform_key_IDs"].push_back({{"key_ID", transformKeyIDs[i]}});
        jtransform["surplus_key_ID"] = surplusKeyId;
        for(size_t i = 0; i < toTransformKeyIDs.size(); i++)
            jtransform["to_transform_key_IDs"].push_back({{"key_ID", toTransformKeyIDs[i]}});

        std::string msg = jtransform.dump();
        NS_LOG_FUNCTION( this << "Transform payload" << msg );
        Ipv4Address dstKms = conn.GetDestinationKmsAddress(); //Destination KMS adress
        CheckSocketsKMS(dstKms); //Check connection to peer KMS!
        Ptr<Socket> sendSocket = GetSendSocketKMS(dstKms); //Get send socket to peer KMS
        NS_ASSERT (sendSocket); //Check
        
        //Create packet
        HTTPMessage header;
        std::ostringstream peerkmsAddressTemp; 
        dstKms.Print(peerkmsAddressTemp); //IPv4Address to string
        std::string headerUri = "http://" + peerkmsAddressTemp.str ();
        headerUri += "/api/v1/keys/transform_keys";
         
        //Create packet
        HTTPMessage httpMessage; 
        httpMessage.CreateRequest(headerUri, "POST", msg);
        std::string hMessage = httpMessage.ToString(); 
        Ptr<Packet> packet = Create<Packet> (
          (uint8_t*) (hMessage).c_str(),
          hMessage.size()
        ); 
        NS_ASSERT (packet);

        HttpQuery httpRequest;
        httpRequest.ksid = ksid.string(); //Must know to find QKDBuffer!
        httpRequest.method_type = RequestType::TRANSFORM_KEYS;
        httpRequest.transform_key_size = keySize;
        httpRequest.transform_key_number = keyNumber;
        httpRequest.transform_key_IDs = transformKeyIDs;
        httpRequest.to_transform_key_IDs = toTransformKeyIDs;
        httpRequest.surplus_key_ID = surplusKeyId;
        HttpKMSAddQuery(dstKms, httpRequest); //Remember request to properly map response!

        sendSocket->Send(packet);
        NS_LOG_FUNCTION( this << "Transform request sent" << packet->GetUid() << packet->GetSize() );

    }else{
        NS_FATAL_ERROR( this << "QKD buffer for this connection was not found!" );
    }
    
}

void 
QKDKeyManagerSystemApplication::ProcessTransformRequest(HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << socket );
    
    std::string payload = headerIn.GetMessageBodyString();
    nlohmann::json jtransformRequest;
    try {
        jtransformRequest = nlohmann::json::parse(payload);
    } catch (...) {
        NS_FATAL_ERROR( this << "JSON parse error!" );
    }
    //Read JSON parameters
    uint32_t keySize {0}, keyNumber {0};
    std::vector<std::string> toTransformKeyIDs {}, transformKeyIDs {};
    std::string surplusKeyId {};

    std::string ksid;
    if(jtransformRequest.contains("transform_key_size"))
        keySize = jtransformRequest["transform_key_size"];
    if(jtransformRequest.contains("transform_key_number"))
        keyNumber = jtransformRequest["transform_key_number"]; //@toDo why is keyNumber always = 1, jtransformRequest["transform_key_number"] holds correct values, but keyNumber is 1?
    if(jtransformRequest.contains("surplus_key_ID"))
        surplusKeyId = jtransformRequest["surplus_key_ID"];
    if(jtransformRequest.contains("transform_key_IDs")){
        for(
          nlohmann::json::iterator it = jtransformRequest["transform_key_IDs"].begin();
          it != jtransformRequest["transform_key_IDs"].end();
          ++it
        )
            transformKeyIDs.push_back((it.value())["key_ID"]);
    }
    if(jtransformRequest.contains("to_transform_key_IDs")){
        for(
          nlohmann::json::iterator it = jtransformRequest["to_transform_key_IDs"].begin();
          it != jtransformRequest["to_transform_key_IDs"].end();
          ++it
        )
            toTransformKeyIDs.push_back((it.value())["key_ID"]);
    }
    if(jtransformRequest.contains("ksid")){
        ksid = jtransformRequest["ksid"];
    }

    NS_ASSERT(keySize != 0);
    NS_ASSERT(keyNumber =! 0);
    NS_ASSERT(!transformKeyIDs.empty());
    NS_ASSERT(!toTransformKeyIDs.empty());

    NS_LOG_FUNCTION( this << keySize << keyNumber << "\ntransform_key_IDs"<< transformKeyIDs 
        << "\nto_transform_key_IDs" << toTransformKeyIDs << "\nsurplus_key_ID" << surplusKeyId << "\nksid" << ksid );

    if(ksid.size() == 0){
      NS_FATAL_ERROR( this << "No ksid specified!" << jtransformRequest.dump() );
    }

    QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid );
    NS_ASSERT(appConnection.IsValid());
    appConnection.PrintRegistryInfo();

    QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
    NS_ASSERT(conn.IsValid());
    conn.PrintRegistryInfo();


    Ptr<QKDBuffer> buffer = conn.GetSourceBuffer();
    if(buffer){
        bool keysExist {true};
        for(size_t i = 0; i < toTransformKeyIDs.size(); i++){
            keysExist = buffer->ProbeKeyStatus(toTransformKeyIDs[i], QKDKey::READY); //Check if key exists and is READY
            if (!keysExist)
                break;
        }
        if(keysExist){ //Perform transformation and response OK
            NS_LOG_FUNCTION( this << "Performing transformation" );
            uint32_t keySizeInBytes = keySize/8;
            std::string mergedKey {};
            for(size_t i = 0; i < toTransformKeyIDs.size(); i++){
                mergedKey += (buffer->FetchKeyByID(toTransformKeyIDs[i], 1))->GetKeyString(); //Fetching will remove key from QKD buffer!
            }
            for(size_t i = 0; i < transformKeyIDs.size(); i++){ //Should use keyNumber but the previus read is invalid! @toDo
                std::string keyString = mergedKey.substr(0, keySizeInBytes);
                mergedKey.erase(0, keySizeInBytes);
                Ptr<QKDKey> key = CreateObject<QKDKey> (transformKeyIDs[i], keyString);
                buffer->AddNewKey(key,1);
            }
            if(!mergedKey.empty()){
                Ptr<QKDKey> key = CreateObject<QKDKey> (surplusKeyId, mergedKey);
                buffer->AddNewKey(key,1);
            }

            nlohmann::json jResponse;
            jResponse["sae_id"] = appConnection.GetSrcSaeId().string(); //it is destination saeId for the peer KMS
            std::string msg = jResponse.dump();

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

            SendToSocketPairKMS(socket, packet);

        }else{ //Response Error!
            NS_LOG_FUNCTION( this << "Check failed" );
            nlohmann::json jResponse;
            jResponse["sae_id"] = appConnection.GetSrcSaeId().string();
            std::string msg = jResponse.dump();

            //create packet
            HTTPMessage httpMessage; 
            httpMessage.CreateResponse(HTTPMessage::HttpStatus::BadRequest, msg, { 
              {"Content-Type", "application/json; charset=utf-8"}, 
              {"Request URI", headerIn.GetUri() }
            });
            std::string hMessage = httpMessage.ToString(); 
            Ptr<Packet> packet = Create<Packet> (
              (uint8_t*) (hMessage).c_str(),
              hMessage.size()
            );
            NS_ASSERT (packet); 

            SendToSocketPairKMS(socket, packet);
        }

    }else{
        NS_FATAL_ERROR( this << "No QKD buffer found for this connection!" );
    }
    
}

void
QKDKeyManagerSystemApplication::ProcessTransformResponse(HTTPMessage headerIn, Ptr<Socket> socket)
{
    std::string payload = headerIn.GetMessageBodyString(); //Read payload 
    
    NS_LOG_FUNCTION( this << payload );
    
    nlohmann::json jTransformResponse;
    try {
        jTransformResponse = nlohmann::json::parse(payload);
    } catch (...) {
        NS_FATAL_ERROR( this << "JSON parse error! Received payload:" << payload );
    }

    std::string ksid = "";
    if(jTransformResponse.contains("sae_id")) ksid = jTransformResponse["sae_id"]; 
    if(ksid.empty() && jTransformResponse.contains("ksid")) ksid = jTransformResponse["ksid"]; 

    Ipv4Address dstKms = GetDestinationKmsAddress(socket);

    QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid );
    NS_ASSERT(appConnection.IsValid());
    appConnection.PrintRegistryInfo();

    QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
    NS_ASSERT(conn.IsValid());
    conn.PrintRegistryInfo();
 
    Ptr<QKDBuffer> buffer = conn.GetSourceBuffer();
    std::map<Ipv4Address, std::vector<HttpQuery> >::iterator it = m_httpRequestsQueryKMS.find(dstKms);
    HttpQuery transformPar = (it->second)[0];
    if (headerIn.GetStatusCode() == HTTPMessage::Ok){ //Transform keys
        //Read necessery transform parameters from HTTP query
        if(it == m_httpRequestsQueryKMS.end())
            NS_FATAL_ERROR( this << "HTTP response cannot be mapped: HTTP query to destination KMS does not exist!" );
        else if(it->second.empty())
            NS_FATAL_ERROR( this << "HTTP response cannot be mapped: HTTP query is empty!" );
        uint32_t keySize {transformPar.transform_key_size}, keyNumber {transformPar.transform_key_number};
        std::vector<std::string> toTransformKeyIDs {transformPar.to_transform_key_IDs}, 
                                 transformKeyIDs {transformPar.transform_key_IDs};
        std::string surplusKeyId {transformPar.surplus_key_ID};
        HttpKMSCompleteQuery(dstKms); //Clear this request from HTTP query (all parameters read!)
        NS_LOG_FUNCTION( this << "Transforming keys" );
        bool keysExist {true};
        for(size_t i = 0; i < toTransformKeyIDs.size(); i++){
            keysExist = buffer->ProbeKeyStatus(toTransformKeyIDs[i], QKDKey::RESERVED); //Check if key exists and is RESERVED
            if (!keysExist)
                break;
        }
        if(keysExist){
            uint32_t keySizeInBytes = keySize/8;
            std::string mergedKey {};
            for(size_t i = 0; i < toTransformKeyIDs.size(); i++){
                mergedKey += (buffer->FetchKeyByID(toTransformKeyIDs[i], 1))->GetKeyString(); //Fetching will remove key from QKD buffer!
            }
            for(size_t i = 0; i < keyNumber; i++){
                std::string keyString = mergedKey.substr(0, keySizeInBytes);
                mergedKey.erase(0, keySizeInBytes);
                Ptr<QKDKey> key = CreateObject<QKDKey> (transformKeyIDs[i], keyString);
                buffer->AddNewKey(key,1);
            }
            if(!mergedKey.empty()){
                Ptr<QKDKey> key = CreateObject<QKDKey> (surplusKeyId, mergedKey);
                buffer->AddNewKey(key,1);
            }

            NS_LOG_FUNCTION( this << "Transformation successfuly completed!" );
        }else{
            NS_FATAL_ERROR( this << "KMS mistreated reserved keys: keys not found!" );
        }
    }else{ //Release key reservation
        NS_LOG_FUNCTION( this << "Releasing reserved keys for failed transformation!");
        std::vector<std::string> toTransformKeyIDs {transformPar.to_transform_key_IDs};
        HttpKMSCompleteQuery(dstKms); //Clear this request from HTTP query (all parameters read!)
        for(size_t i = 0; i < toTransformKeyIDs.size(); i++){
            buffer->ReleaseReservation(toTransformKeyIDs[i]);
        }
        NS_LOG_FUNCTION( this << "Reserved keys are released" << toTransformKeyIDs );
        //@toDo Repeat TransformKeys? We have keySize, keyNumber, and dstKms! All we need!
    }
  
}

void
QKDKeyManagerSystemApplication::ProcessKMSCloseRequest (HTTPMessage headerIn, Ptr<Socket> socket, std::string ksid)
{
    NS_LOG_FUNCTION( this << "Processing CLOSE from peer KMS" << ksid );
    std::string payload = headerIn.GetMessageBodyString(); //Read the packet payload
    nlohmann::json jcloseRequest;
    try {
        jcloseRequest = nlohmann::json::parse(payload);
    } catch (...) {
        NS_FATAL_ERROR( this << "JSON parse error!" );
    }

    std::string surplusKeyId {};
    uint32_t syncIndex {0};
    if(jcloseRequest.contains("surplus_key_ID"))
        surplusKeyId = jcloseRequest["surplus_key_ID"];
    if(jcloseRequest.contains("sync_index"))
        syncIndex = jcloseRequest["sync_index"];

    std::map<std::string, Association004>::iterator it = m_associations004.find(ksid);
    if(it == m_associations004.end()){ //Key stream association does not exists (peer error, or association already released)
        NS_LOG_FUNCTION( this << "KSID not registered on KMS, or is already closed!" );
        
        //create packet
        HTTPMessage httpMessage; 
        httpMessage.CreateResponse(HTTPMessage::HttpStatus::NotAcceptable, "", { 
          {"Request URI", headerIn.GetUri() }
        });
        std::string hMessage = httpMessage.ToString(); 
        Ptr<Packet> packet = Create<Packet> (
          (uint8_t*) (hMessage).c_str(),
          hMessage.size()
        );
        NS_ASSERT (packet);

        NS_LOG_FUNCTION( this << "Sending response on CLOSE request " << packet->GetUid() << packet->GetSize() );
        SendToSocketPairKMS(socket, packet);

    }else{
        it->second.peerRegistered = false; //QKDApp is no longer registered for particular association!
        bool empty {false};
        uint32_t localSyncIndex {0};
        if(it->second.buffer.begin() != it->second.buffer.end()) //Replica association buffer is not empty!
            localSyncIndex = it->second.buffer.begin()->first; //The oldest index in dedicated association buffer!
        else
            empty = true;

        //record additional key consumption (some keys may not be perserved)
        if(!surplusKeyId.empty() && syncIndex > localSyncIndex){
            //must record key consumed
            NS_LOG_FUNCTION(this << "emiree" << syncIndex << localSyncIndex);
            uint32_t presentKeyMaterial {0};
            for (std::map<uint32_t, ChunkKey>::iterator it2 = it->second.buffer.begin(); it2 != it->second.buffer.find(syncIndex); ++it2){
                //from begining of buffer until SyncIndex all keys are not perserved
                NS_LOG_FUNCTION(this << it2->second.chunkSize);
                presentKeyMaterial += it2->second.chunkSize;
            }
            NS_LOG_FUNCTION(this << "emiree1" << presentKeyMaterial);
            m_keyServedTraceEmir(presentKeyMaterial);
            //m_keyServedTrace((it->second).dstSaeId, presentKeyMaterial);
            //m_keyServedWithKSIDTrace(ksid, (it->second).dstSaeId, presentKeyMaterial);
        }

        if(!surplusKeyId.empty() && syncIndex < localSyncIndex) //Only if peer KMS dedicated association buffer is not empty (known by the surplusKeyId presence)
            syncIndex = localSyncIndex; //KMSs synchronize on largest index that exists at both peers!
        
        bool flag {false};
        if(empty && !surplusKeyId.empty())
            flag = true; //If replica empty, primary not. Replica sends flag insted of index!

        ReleaseAssociation(ksid, surplusKeyId, syncIndex);

        nlohmann::json jresponse;
        if(!flag){
            if(!surplusKeyId.empty())
                jresponse["sync_index"] = syncIndex;
        }else{
            jresponse["flag_empty"] = true;
        }

        std::string msg = jresponse.dump();

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

        NS_LOG_FUNCTION( this << "Sending response on CLOSE" << msg << packet->GetUid() << packet->GetSize());
        SendToSocketPairKMS(socket, packet);
    }

}

void
QKDKeyManagerSystemApplication::ReleaseAssociation (std::string ksid, std::string surplusKeyId, uint32_t syncIndex)
{
    NS_LOG_FUNCTION( this << "Releasing association ... " << ksid );
    std::map<std::string, Association004>::iterator it = m_associations004.find(ksid);
    if(it == m_associations004.end()) { //Key stream association does not exists
      NS_LOG_DEBUG( this << " Key stream association identified with " << ksid << " does not exists!" );
      return;
    }

    if(surplusKeyId.empty()){
        m_associations004.erase(it);
    }else{
        std::string preservedKeyString {}; //First preserve remaining key material!
        std::map<uint32_t, ChunkKey>::iterator a = it->second.buffer.find(syncIndex);
        while(a != it->second.buffer.end()){
            preservedKeyString += a->second.key;
            ++a;
        }

        if(!preservedKeyString.empty()){
            //Ipv4Address dstKms = it->second.dstKmsNode; //Obtain dstKms adress from assocition entry
            UUID ksid = it->second.ksid;

            QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid.string() );
            NS_ASSERT(appConnection.IsValid());
            appConnection.PrintRegistryInfo();

            QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
            NS_ASSERT(conn.IsValid());
            conn.PrintRegistryInfo();

            Ptr<QKDBuffer> buffer = conn.GetSourceBuffer();
            if(buffer){
                NS_LOG_FUNCTION( this << "Releasing dedicated association buffer ... " );
                NS_LOG_FUNCTION( this << "Preserving key material ... " );
                NS_LOG_FUNCTION( this << preservedKeyString.size() << " bit of key material preserved ... " );
                NS_LOG_FUNCTION( this << "Assigning ID to preserved key material ... " );
                Ptr<QKDKey> key = CreateObject<QKDKey> (surplusKeyId, preservedKeyString);
                buffer->AddNewKey(key, 1);
                NS_LOG_FUNCTION( this << "Preserved key material added to the QKD buffer " 
                                      << surplusKeyId << preservedKeyString.size() );
            }else{
                NS_FATAL_ERROR( this << "QKD buffer not found!" );
            }
        }
        m_associations004.erase(it);
    }
    NS_LOG_FUNCTION( this << "Key stream association identified with " << ksid << "is removed!" );

}

void
QKDKeyManagerSystemApplication::ProcessKMSCloseResponse(HTTPMessage headerIn, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << "Processing response on KMS /close request ... " );
    std::string payload = headerIn.GetMessageBodyString();
    nlohmann::json jcloseResponse;
    try {
        jcloseResponse = nlohmann::json::parse(payload);
    } catch (...) {
        NS_FATAL_ERROR( this << "JSON parse error!" );
    }

    Ipv4Address dstKms = GetDestinationKmsAddress(socket);
    std::map<Ipv4Address, std::vector<HttpQuery> >::iterator it = m_httpRequestsQueryKMS.find(dstKms);
    if(it == m_httpRequestsQueryKMS.end())
        NS_FATAL_ERROR( this );

    std::string ksid = it->second[0].ksid;
    std::map<std::string, Association004>::iterator a = m_associations004.find(ksid);
    if(a == m_associations004.end()){
        NS_LOG_DEBUG( this << " Key stream association identified with " << ksid << " does not exists!" );
        return;
    }

    if(headerIn.GetStatusCode() == HTTPMessage::NotAcceptable){
        //must record key consumed
        uint32_t presentKeyMaterial {0};
        for (std::map<uint32_t, ChunkKey>::iterator it2 = a->second.buffer.begin(); it2 != a->second.buffer.end(); ++it2){
            presentKeyMaterial += it2->second.chunkSize;
        }
        m_keyServedTraceEmir(presentKeyMaterial);
        //m_keyServedTrace((a->second).dstSaeId, presentKeyMaterial);
        //m_keyServedWithKSIDTrace(ksid, (a->second).dstSaeId, presentKeyMaterial);

        m_associations004.erase(a); //Just delete association!

    }else if(headerIn.GetStatusCode() == HTTPMessage::Ok){
        uint32_t peerSyncIndex {0};
        uint32_t localSyncIndex {it->second[0].sync_index};
        if(jcloseResponse.contains("sync_index")){
            peerSyncIndex = jcloseResponse["sync_index"];
            if(peerSyncIndex > localSyncIndex)
                localSyncIndex = peerSyncIndex;
            
            //must record key consumed
            uint32_t presentKeyMaterial {0};
            for (std::map<uint32_t, ChunkKey>::iterator it2 = a->second.buffer.begin(); it2 != a->second.buffer.find(localSyncIndex); ++it2){
                //from begining of buffer until localSyncIndex all keys are not perserved
                presentKeyMaterial += it2->second.chunkSize;
            }
            //m_keyServedTrace((a->second).dstSaeId, presentKeyMaterial);
            //m_keyServedWithKSIDTrace(ksid, (a->second).dstSaeId, presentKeyMaterial);
            m_keyServedTraceEmir(presentKeyMaterial);

            ReleaseAssociation(it->second[0].ksid, it->second[0].surplus_key_ID, localSyncIndex);
        }else{

            //must record key consumed
            uint32_t presentKeyMaterial {0};
            for (std::map<uint32_t, ChunkKey>::iterator it2 = a->second.buffer.begin(); it2 != a->second.buffer.end(); ++it2){
                presentKeyMaterial += it2->second.chunkSize;
            }
            //m_keyServedTrace((a->second).dstSaeId, presentKeyMaterial);
            //m_keyServedWithKSIDTrace(ksid, (a->second).dstSaeId, presentKeyMaterial);
            m_keyServedTraceEmir(presentKeyMaterial);
            
            m_associations004.erase(a);
        }

    }else{
        NS_FATAL_ERROR( this << "Unknown http status code received" );
    }

    HttpKMSCompleteQuery(dstKms);

}

/**
 * ********************************************************************************************

 *        HTTP handling
 
 * ********************************************************************************************
 */

void   
QKDKeyManagerSystemApplication::HttpKMSAddQuery(Ipv4Address dstKms, HttpQuery request)
{
    NS_LOG_FUNCTION( this );
    std::map<Ipv4Address, std::vector<HttpQuery> >::iterator it = m_httpRequestsQueryKMS.find(dstKms);
    if(it != m_httpRequestsQueryKMS.end())
        it->second.push_back(request);
    else
        m_httpRequestsQueryKMS.insert(std::make_pair(dstKms, std::vector<HttpQuery> {request}));
}

void 
QKDKeyManagerSystemApplication::HttpKMSCompleteQuery(Ipv4Address dstKms)
{
    NS_LOG_FUNCTION( this );
    std::map<Ipv4Address, std::vector<HttpQuery> >::iterator it = m_httpRequestsQueryKMS.find(dstKms);
    if(it != m_httpRequestsQueryKMS.end())
        if(!it->second.empty())
            it->second.erase(it->second.begin());
        else
            NS_FATAL_ERROR( this << "HTTP query for this KMS is empty!");
    else
        NS_FATAL_ERROR( this << "HTTP query to destination KMS does not exist!" );
}

QKDKeyManagerSystemApplication::RequestType
QKDKeyManagerSystemApplication::HttpQueryMethod(Ipv4Address dstKms)
{
    NS_LOG_FUNCTION( this );
    QKDKeyManagerSystemApplication::RequestType methodType = NONE;
    std::map<Ipv4Address, std::vector<HttpQuery> >::iterator it = m_httpRequestsQueryKMS.find(dstKms);
    if(it!=m_httpRequestsQueryKMS.end())
        methodType = it->second.begin()->method_type;
    else
        NS_FATAL_ERROR( this << "HTTP response cannot be mapped: HTTP query is empty!" );
    return methodType;
}

void
QKDKeyManagerSystemApplication::Http004AppQuery ( UUID saeId, Ptr<Socket> socket )
{
  NS_LOG_FUNCTION( this << saeId << socket );
  m_http004App.insert (std::make_pair (saeId, socket));
}

void
QKDKeyManagerSystemApplication::Http004AppQueryComplete (UUID saeId)
{
  NS_LOG_FUNCTION( this << saeId ); 
  //Must use equal_range
  std::pair<std::multimap<UUID, Ptr<Socket> >::iterator, std::multimap<uint32_t, Ptr<Socket> >::iterator > ret;
  //ret = m_http004App.equal_range(saeId);
  //if (ret.first == ret.second) NS_FATAL_ERROR( this << "Query is empty" );

  std::multimap<UUID, Ptr<Socket> >::iterator it = ret.first;
  m_http004App.erase(it);

}

Ptr<Socket>
QKDKeyManagerSystemApplication::GetSocketFromHttp004AppQuery (UUID saeId)
{
  NS_LOG_FUNCTION( this << saeId );

  std::pair<std::multimap<UUID, Ptr<Socket> >::iterator, std::multimap<UUID, Ptr<Socket> >::iterator > ret;
  //ret = m_http004App.equal_range(saeId);
  //if (ret.first == ret.second) NS_FATAL_ERROR( this << "sae query is not registered" );

  std::multimap<UUID, Ptr<Socket> >::iterator it = ret.first;

  NS_LOG_FUNCTION( this << saeId << it->second);
  return it->second;

}

Ipv4Address
QKDKeyManagerSystemApplication::GetDestinationKmsAddress (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION( this );
  Ipv4Address dstKMSAddress;
  
  std::map<Ipv4Address, std::pair<Ptr<Socket>, Ptr<Socket> > >::iterator it;
  for (it = m_socketPairsKMS.begin(); it != m_socketPairsKMS.end(); ++it)
  {
    if ((it->second).first == socket) {
      dstKMSAddress = it->first;
      break;
    }
  }

  return dstKMSAddress;
}

uint32_t
QKDKeyManagerSystemApplication::GetMaxKeyPerRequest(){
  return m_maxKeyPerRequest;
}

QKDKeyManagerSystemApplication::RequestType
QKDKeyManagerSystemApplication::FetchRequestType(std::string s)
{
  NS_LOG_FUNCTION(this << s);
  RequestType output = NONE;

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

  } else {

      NS_FATAL_ERROR ("Unknown Type: " << s);
  }

  return output;
}

//function called from QKD Control
//by default srcSaeId == srcNodeId where the link is installed
std::string 
QKDKeyManagerSystemApplication::AddNewLink( 
  uint32_t srcNodeId,
  uint32_t dstNodeId,  
  Ipv4Address kmsDstAddress,
  Ptr<QKDBuffer> srcBuffer
){
  return AddNewLink( 
    srcNodeId,
    dstNodeId,  
    kmsDstAddress,
    srcBuffer,
    ""
  );
}


//function called from QKD Control
//by default srcSaeId == srcNodeId where the link is installed
std::string 
QKDKeyManagerSystemApplication::AddNewLink( 
  uint32_t srcNodeId,
  uint32_t dstNodeId,  
  Ipv4Address kmsDstAddress,
  Ptr<QKDBuffer> srcBuffer,
  std::string keyAssociationIdParam
){

  NS_LOG_FUNCTION( this 
    << "srcNodeId: " << srcNodeId 
    << "dstNodeId: " << dstNodeId 
    << "m_local: " << m_local 
    << "kmsDstAddress: " << kmsDstAddress 
    << "keyAssociationIdParam: " << keyAssociationIdParam 
  );
 
  Ptr<QKDConnectionRegister> lr = GetNode()->GetObject<QKDConnectionRegister> ();
  NS_ASSERT (lr);

  std::string keyAssociationId = keyAssociationIdParam;
  if(keyAssociationId.empty()){
    NS_LOG_FUNCTION(this << "empty!");
    QKDKeyAssociationLinkEntry newEntry(
      srcNodeId,
      dstNodeId,
      dstNodeId,//nextHop
      1,//dirrect p2p connection (number of hops)
      0,// 0-direct; 1-virtual
      m_local, //srcKMSAddress
      kmsDstAddress, //dstKMSaddress
      srcBuffer
    );
    lr->AddKeyAssociationEntry(newEntry); 
    keyAssociationId = newEntry.GetId().string();
  }else{
    NS_LOG_FUNCTION(this << "NOT empty!" << keyAssociationId);
    QKDKeyAssociationLinkEntry newEntry(
      UUID{keyAssociationId},
      srcNodeId,
      dstNodeId,
      dstNodeId,//nextHop
      1,//dirrect p2p connection (number of hops)
      0,// 0-direct; 1-virtual
      m_local, //srcKMSAddress
      kmsDstAddress, //dstKMSaddress
      srcBuffer
    );
    lr->AddKeyAssociationEntry(newEntry);
  }
 
  NS_LOG_FUNCTION (this << "Create sink socket to listen requests exchanged between KMSs!" );

  InetSocketAddress sinkAddress = InetSocketAddress (m_local, 8080); 
  Ptr<Socket> sinkSocket = Socket::CreateSocket (GetNode (), m_tid);
  sinkSocket->Bind (sinkAddress);
  sinkSocket->Listen ();
  sinkSocket->ShutdownSend ();
  sinkSocket->SetRecvCallback (MakeCallback (&QKDKeyManagerSystemApplication::HandleReadKMSs, this));
  sinkSocket->SetAcceptCallback (
    MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
    MakeCallback (&QKDKeyManagerSystemApplication::HandleAcceptKMSs, this)
  );
  sinkSocket->SetCloseCallbacks (
    MakeCallback (&QKDKeyManagerSystemApplication::HandlePeerCloseKMSs, this),
    MakeCallback (&QKDKeyManagerSystemApplication::HandlePeerErrorKMSs, this)
  ); 

  //store this socket for further use. Later we will create the send socket as well
  Ptr<Socket> sendSocket = 0;
  m_socketPairsKMS.insert(
    std::make_pair(
      kmsDstAddress,
      std::make_pair(sinkSocket, sendSocket)
    )
  ); 
  NS_LOG_FUNCTION( this << kmsDstAddress << sinkSocket << sendSocket );

  //-----------------------
  //SEND DETAILS TO SDN CONTROLLER
  //----------------------- 

  
  if(m_sdnSupportEnabled){

    std::ostringstream mkmsAddressTemp; 
    m_local.Print(mkmsAddressTemp); //IPv4Address to string
    std::string mkmsAddressString = mkmsAddressTemp.str(); //Uri starts with destination KMS address

    std::ostringstream skmsAddressTemp; 
    kmsDstAddress.Print(skmsAddressTemp); //IPv4Address to string
    std::string skmsAddressString = skmsAddressTemp.str(); //Uri starts with destination KMS address

    //Notify SDN Controller about the new QKD LINK
    nlohmann::json j;
    j["master_SAE_ID"] = srcNodeId;
    j["slave_SAE_ID"] = dstNodeId;
    j["next_hop_id"] = dstNodeId;
    j["key_association_id"] = keyAssociationId;
    j["hops"] = 0; 
    j["master_kms_address"] = mkmsAddressString;
    j["slave_kms_address"] = skmsAddressString;

    NS_LOG_FUNCTION( this << "Prepared JSON_PACKET_TO_SDN:" << j.dump()  );

    std::string msg = j.dump();
    HTTPMessage httpHead;

    Ipv4Address sdnAddress = InetSocketAddress::ConvertFrom(m_sdnControllerAddress).GetIpv4 ();
    std::ostringstream sdnAddressTemp; 
    sdnAddress.Print(sdnAddressTemp); //IPv4Address to string 

    std::string headerUri = "http://" + sdnAddressTemp.str ();
    headerUri += "/api/v1/keys/" + skmsAddressString + "/register_qkd_link";

    //Create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateRequest(headerUri, "POST", msg);
    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packetToSdn = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    ); 

    if(connectedToSDN)
    {
      NS_LOG_FUNCTION (this << "Sending QKD_LINK_REGISTER to SDN CONTROLLER\n PacketID: " 
        << packetToSdn->GetUid() << " of size: " << packetToSdn->GetSize() 
        << hMessage
      );
      m_sendSocketToSDN->Send(packetToSdn);

    //otherwise wait in the queue
    }else{
      m_packetQueuesToSDN.insert( std::make_pair(  m_sendSocketToSDN ,  packetToSdn) );
      NS_LOG_FUNCTION(this << packetToSdn->GetUid() << "enqued for socket " << m_sendSocketToSDN);
    }
  }

  return keyAssociationId;
}

/**
 * This function register the pair of QKDApps (srcSaeId, dstSaeId) to use keys that are produced
 * by the QKD systems on nodes srcNode and dstNode via this KMS
*/
QKDApplicationEntry
QKDKeyManagerSystemApplication::RegisterApplicationEntry(
    UUID  srcSaeId,
    UUID  dstSaeId, 
    std::string type, //1-etsi014 (encryption); 2-etsi014(auth); 3-etsi004(encryption); 4-etsi004(auth)
    Ipv4Address dstKmsAddress,
    uint32_t priority = 0, 
    double expirationTime = 100 
){

  NS_LOG_FUNCTION( this << "keyId: \t" << "srcSaeId:" << srcSaeId << "dstSaeId:" << dstSaeId << "type:" << type);
  
  QKDKeyAssociationLinkEntry conn;
  Ptr<QKDConnectionRegister> lr = GetNode()->GetObject<QKDConnectionRegister> ();
  NS_ASSERT (lr);
  
  lr->AssignKeyAssociation( srcSaeId, dstSaeId, type, priority, conn );
  NS_ASSERT(conn.IsValid());
  conn.PrintRegistryInfo();
  UUID keyAssociationId = conn.GetId();
  UUID applicationEntryId = UUID::Nil();

  return RegisterApplicationEntry(
    keyAssociationId,
    applicationEntryId,
    srcSaeId,
    dstSaeId,
    type,
    dstKmsAddress,
    priority,
    expirationTime
  );
}

/**
 * This function register the pair of QKDApps (srcSaeId, dstSaeId) to use keys that are produced
 * by the QKD systems on nodes srcNode and dstNode via this KMS
 * We assume QKD link (key association) between SAE nodes is established. 
 * Hence, we only need keyAssociationId!
*/
QKDApplicationEntry
QKDKeyManagerSystemApplication::RegisterApplicationEntry(
    UUID  keyAssociationId,
    UUID  applicationEntryId,
    UUID  srcSaeId,
    UUID  dstSaeId, 
    std::string type,     //1-etsi014; 2-etsi004
    Ipv4Address dstKmsAddress,
    uint32_t priority = 0, 
    double expirationTime = 100 
){

  NS_LOG_FUNCTION( this 
    << "keyId:" << keyAssociationId 
    << "applicationEntryId:" << applicationEntryId 
    << "srcSaeId:" << srcSaeId 
    << "dstSaeId:" << dstSaeId 
    << "type:" << type 
  );
  
  QKDApplicationEntry::ConnectionType linkType = QKDApplicationEntry::NONE;
  if(type == "etsi004_enc") {
    linkType = QKDApplicationEntry::ETSI_QKD_004_ENCRYPTION;
  }else if(type == "etsi004_auth") {
    linkType = QKDApplicationEntry::ETSI_QKD_004_AUTHENTICATION;
  }else if(type == "etsi014_enc") {
    linkType = QKDApplicationEntry::ETSI_QKD_014_ENCRYPTION;
  }else if(type == "etsi014_auth") {
    linkType = QKDApplicationEntry::ETSI_QKD_014_AUTHENTICATION;
  }
  NS_ASSERT (
    linkType == QKDApplicationEntry::ETSI_QKD_004_ENCRYPTION || 
    linkType == QKDApplicationEntry::ETSI_QKD_004_AUTHENTICATION ||
    linkType == QKDApplicationEntry::ETSI_QKD_014_ENCRYPTION || 
    linkType == QKDApplicationEntry::ETSI_QKD_014_AUTHENTICATION
  );
  //1-etsi014 (encryption); 2-etsi014(auth); 3-etsi004(encryption); 4-etsi004(auth)
  
  QKDKeyAssociationLinkEntry conn = GetKeyAssociationById( keyAssociationId );
  conn.PrintRegistryInfo();
  NS_ASSERT(conn.IsValid());
  UUID connectionId = conn.GetId();
  NS_LOG_FUNCTION( this << "connectionId FOUND: " << connectionId );
 
  Ptr<QKDConnectionRegister> lr = GetNode()->GetObject<QKDConnectionRegister> ();
  NS_ASSERT (lr);

  QKDApplicationEntry newEntry(
    connectionId,
    srcSaeId,
    dstSaeId,
    linkType,
    priority,
    expirationTime, //expirationTime
    m_local,        //srcKMSAddress
    dstKmsAddress   //dstKMSAddress
  );
  
  if(applicationEntryId != UUID::Nil())
    newEntry.SetId(applicationEntryId);

  lr->AddApplicationEntry(newEntry);
  lr->UpdateQKDApplications(connectionId, newEntry.GetId()); 

  //-----------------------
  //SEND DETAILS TO SDN CONTROLLER
  //----------------------- 
  if(m_sdnSupportEnabled && connectedToSDN){

    std::ostringstream mkmsAddressTemp; 
    conn.GetSourceKmsAddress().Print(mkmsAddressTemp); //IPv4Address to string
    std::string mkmsAddressString = mkmsAddressTemp.str(); //Uri starts with destination KMS address

    std::ostringstream skmsAddressTemp; 
    conn.GetDestinationKmsAddress().Print(skmsAddressTemp); //IPv4Address to string
    std::string skmsAddressString = skmsAddressTemp.str(); //Uri starts with destination KMS address

    UUID appId = newEntry.GetId();
    nlohmann::json j;
    j["key_association_id"] = connectionId.string();
    j["application_entry_id"] = appId.string();
    j["client_SAE_ID"] = srcSaeId.string();
    j["server_SAE_ID"] = dstSaeId.string();
    j["link_type"] = GetQKDApplicationEntryText(linkType);
    j["priority"] = priority;
    j["expirationTime"] = expirationTime;
    j["master_kms_address"] = mkmsAddressString;
    j["slave_kms_address"] = skmsAddressString;

    NS_LOG_FUNCTION( this << "Prepared JSON_PACKET_TO_SDN:" << j.dump()  );

    std::string msg = j.dump();
    HTTPMessage httpHead;
    
    Ipv4Address sdnAddress = InetSocketAddress::ConvertFrom(m_sdnControllerAddress).GetIpv4 ();
    std::ostringstream sdnAddressTemp;
    sdnAddress.Print(sdnAddressTemp); //IPv4Address to string

    std::string headerUri = "http://" + sdnAddressTemp.str ();
    headerUri += "/api/v1/keys/" + skmsAddressString + "/register_sae_link";

    //Create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateRequest(headerUri, "POST", msg);
    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packet = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    ); 
    NS_ASSERT (packet);

    //send the packet only if connected!
    if(connectedToSDN){      
      NS_LOG_FUNCTION (this << "Sending SAE_REGISTER to SDN CONTROLLER\n PacketID: " 
        << packet->GetUid() << " of size: " << packet->GetSize() 
        << hMessage  
      );
      m_sendSocketToSDN->Send(packet); 
    //otherwise wait in the queue
    }else{
      m_packetQueuesToSDN.insert( std::make_pair(  m_sendSocketToSDN ,  packet) );
      NS_LOG_FUNCTION(this << packet->GetUid() << "enqued for socket " << m_sendSocketToSDN);
    }
  }

  return newEntry;

}


/*
*   This function is called when we have exact SAEIDs of the app
*   Then we need to obtain full info about the app from the connection registry
*/
QKDApplicationEntry
QKDKeyManagerSystemApplication::GetApplicationConnectionDetailsBySaeIDsAndType(
  std::string srcSaeId, 
  std::string dstSaeId,
  QKDApplicationEntry::ConnectionType type
){
  NS_LOG_FUNCTION(this << srcSaeId << dstSaeId << type);

  UUID srcId (srcSaeId); 
  UUID dstId (dstSaeId); 

  QKDApplicationEntry output;
  Ptr<QKDConnectionRegister> lr = GetNode()->GetObject<QKDConnectionRegister> ();
  NS_ASSERT (lr);

  lr->LookupApplicationBySaeIDsAndType(srcId, dstId, type, output);
  NS_LOG_FUNCTION(this << output.GetId());

  return output;
}



/*
*   This function is called when we have ksid
*   Then we need to obtain full info about the app from the connection registry
*/
QKDApplicationEntry
QKDKeyManagerSystemApplication::GetApplicationConnectionDetails(std::string ksid)
{
  NS_LOG_FUNCTION(this << ksid);

  UUID tempId (ksid); 
  QKDApplicationEntry output;
  Ptr<QKDConnectionRegister> lr = GetNode()->GetObject<QKDConnectionRegister> ();
  NS_ASSERT (lr);
  lr->LookupApplication(tempId, output);
  return output;
}


/*
*   This function is the base of CAC oriented approach. 
*   Having appId we should find the QKD link (key association) which provides key to the app
*   However, if there are multiple key associations, connecition register should decide which 
*   key association to use to respond to this call.
*/
QKDKeyAssociationLinkEntry
QKDKeyManagerSystemApplication::GetKeyAssociationLinkDetailsByApplicationId(std::string appId)
{
  NS_LOG_FUNCTION(this << appId);

  UUID tempId (appId);
  QKDKeyAssociationLinkEntry output;
  Ptr<QKDConnectionRegister> lr = GetNode()->GetObject<QKDConnectionRegister> ();
  NS_ASSERT (lr);
  lr->LookupKeyAssociationByApplicationId(tempId, output);
  return output;

}

/*
*   This function is called only when adding new key.
*   At the current version of post-processing apps we identify QKD links via dstNodeId
*/
QKDKeyAssociationLinkEntry
QKDKeyManagerSystemApplication::GetKeyAssociationByNodeIds(uint32_t srcNodeId, uint32_t dstNodeId)
{
  NS_LOG_FUNCTION(this << srcNodeId << dstNodeId);

  QKDKeyAssociationLinkEntry output;
  Ptr<QKDConnectionRegister> lr = GetNode()->GetObject<QKDConnectionRegister> ();
  NS_ASSERT (lr);
  lr->LookupKeyAssociationByDestinationNodeId(srcNodeId, dstNodeId, output);
  return output;
} 

/*
*   This function is called only when adding new key.
*   At the current version of post-processing apps we identify QKD links via dstNodeId
*/
QKDKeyAssociationLinkEntry
QKDKeyManagerSystemApplication::GetKeyAssociationById(UUID keyAssociationId)
{
  NS_LOG_FUNCTION(this << keyAssociationId);

  QKDKeyAssociationLinkEntry output;
  Ptr<QKDConnectionRegister> lr = GetNode()->GetObject<QKDConnectionRegister> ();
  NS_ASSERT (lr);
  lr->LookupKeyAssociationById(keyAssociationId, output);
  return output;
} 

void
QKDKeyManagerSystemApplication::SaveKeyAssociation(QKDKeyAssociationLinkEntry& entry){

  NS_LOG_FUNCTION(this << entry.GetId());

  Ptr<QKDConnectionRegister> lr = GetNode()->GetObject<QKDConnectionRegister> ();
  NS_ASSERT (lr);
  lr->SaveKeyAssociation(entry);
}


void 
QKDKeyManagerSystemApplication::SetNode(Ptr<Node> n){
  m_node = n;
}

Ptr<Node> 
QKDKeyManagerSystemApplication::GetNode(){
  return m_node;
}

/*
    This funtion checks only Get key request - ETSI014!
    It performs check on number, size, additional_slave_SAEs, and some exstensions!
    If request is valid then empty JSON structure is returned from this function,
    else Error data structure described in ETSI014 is returned!

    In case "keys are being transformed" message is returned, the function should optionally
    return a number of keys that must be transformed. This is because the number of keys
    to transform can be different from the keyNumber parameter, and is defined as
    keyNumber-availableKeyNumber. Omitted by Emir (no need for this in v1) - number of keys
    to transform should be decided by KMS (via request monitoring).
*/
nlohmann::json
QKDKeyManagerSystemApplication::Check014GetKeyRequest (nlohmann::json jrequest, QKDKeyAssociationLinkEntry conn)
{
  
    NS_LOG_FUNCTION(this << conn.GetId());

    //IMPORTANT NOTE: It is assumed that number and size allowed by KMS is same on both sides! Therefore,
                      //one does not need to check those parametes in GetKeyWithKeyIDs request!
    uint32_t keyNumber = 1; //Default number - ETSI014.
    uint32_t keySize = m_defaultKeySize; //Default size - KMS defined / or buffer defined.
    if(jrequest.contains("number")){ //There is keyNumber specified in request
        keyNumber = jrequest["number"];
    }
    if(jrequest.contains("size")){ //There is keySize specified
        keySize = jrequest["size"]; //Key size in bits!
    }
    nlohmann::json jError;                    //Check the values of specified parameters!
    if(                                       //Message 1: requested parameters do not adhere to KMS rules
      keyNumber > GetMaxKeyPerRequest() || 
      keyNumber <= 0 ||
      keySize > m_maxKeySize || 
      keySize < m_minKeySize ||
      keySize % 8 != 0
    ){ //Message 1!
        jError["message"] = std::string {"requested parameters do not adhere to KMS rules"};
        //Fill the details of error Message!
        if(keyNumber > GetMaxKeyPerRequest()){ 
          std::string msgDetail = "requested number of keys (" + std::to_string(keyNumber) + ") is higher then a maximum number of keys (" + std::to_string(GetMaxKeyPerRequest()) + ") per request allowed by KMS";
          NS_LOG_FUNCTION(this << conn.GetId() << "ERROR: " << msgDetail);
          jError["details"].push_back({{"number_unsupported", msgDetail}});
        }else if(keyNumber <= 0){
          std::string msgDetail = "requested number of keys can not be lower or equal to zero";
          NS_LOG_FUNCTION(this << conn.GetId()<< "ERROR: " << msgDetail);
          jError["details"].push_back({{"number_unsupported", msgDetail}});
        }
        if(keySize > m_maxKeySize){
          std::string msgDetail = "requested size of keys (" + std::to_string(keySize) + ") is higher then a maximum size of key (" + std::to_string(m_maxKeySize) + ") that KMS can deliver";
          NS_LOG_FUNCTION(this << conn.GetId()<< "ERROR: " << msgDetail);
          jError["details"].push_back({{"size_unsupported", msgDetail}});
        }else if(keySize < m_minKeySize){
          std::string msgDetail = "requested size of keys (" + std::to_string(keySize) + ") is lower then a minimum size of key (" + std::to_string(m_minKeySize) + ") that KMS can deliver";
          NS_LOG_FUNCTION(this << conn.GetId()<< "ERROR: " << msgDetail);
          jError["details"].push_back({{"size_unsupported", msgDetail}});
        }else if(keySize % 8 != 0){
          std::string msgDetail = "size shall be a multiple of 8";
          NS_LOG_FUNCTION(this << conn.GetId()<< "ERROR: " << msgDetail);
          jError["details"].push_back({{"size_unsupported", msgDetail}});
        }
        return jError;

    }else{
        
        Ptr<QKDBuffer> buffer = conn.GetSourceBuffer();
        NS_LOG_FUNCTION(this << "krecCheck");
        NS_LOG_FUNCTION(this << conn.GetId() << "\nTarget key size: " << keySize << "\nTarget number: " 
                             << keyNumber << "\nRequired amount of key material: " << keySize*keyNumber);
        NS_LOG_FUNCTION(this << conn.GetId() << "\nAmount of key material in buffer: " << buffer->GetKeyCountBit() 
                             << "\nAmount of key material ready to be served: " << buffer->GetReadyKeyCountBit() 
                             << "\nAmount of key material part of target set: " << buffer->GetTargetKeyCountBit());
        if(buffer && keySize*keyNumber > buffer->GetReadyKeyCountBit()){ //Check if there is enough key material!
            jError["message"] = std::string {"insufficient amount of key material"};
            return jError;      
        }else if(buffer && buffer->GetKeyCount(keySize) < keyNumber){
            //Check the amount of key for transformation purpose:
            if(buffer->GetReadyKeyCountBit() - buffer->GetTargetKeyCountBit() < keySize*keyNumber){
              jError["message"] = "insufficient amount of key material";
              NS_LOG_FUNCTION(this << conn.GetId() << "ERROR: " << jError["message"]);
            }else{
              jError["message"] = "keys are being transformed";
              NS_LOG_FUNCTION(this << conn.GetId() << "ERROR: " << jError["message"]);
            }
        }

    }

    return jError;
}


bool
QKDKeyManagerSystemApplication::AddNewKey(Ptr<QKDKey> key, uint32_t srcNodeId, uint32_t dstNodeId){
  
  NS_LOG_FUNCTION(this << key->GetId() << key->GetSizeInBits() << srcNodeId << dstNodeId );

  bool output = false;
  QKDKeyAssociationLinkEntry keyAssociation = GetKeyAssociationByNodeIds( srcNodeId, dstNodeId );
  Ptr<QKDBuffer> buffer = keyAssociation.GetSourceBuffer();

  if(buffer){

    NS_LOG_FUNCTION(this << "Add key to buffer " << buffer << keyAssociation.GetId());
    output = buffer->AddNewKey(key,0);
 
    //Secret key rate generation (in bits per second) of the key association link.
    double generationRate = buffer->GetAverageKeyGenerationRate();
    keyAssociation.SetSKR(generationRate);

    //Sum of all the application's bandwidth (in bits per second) on this particular key association link.
    double averageConsumptionRate = buffer->GetAverageKeyConsumptionRate();
    keyAssociation.SetExpectedConsumption(averageConsumptionRate);

    //Effective secret key rate (in bits per second) generation of the key association link available after internal consumption
    double expectedConsumptionRate = keyAssociation.GetExpectedConsumption();
    double ratio = generationRate - expectedConsumptionRate; 
    
    //if ratio is negative, it means old keys are taken from the buffer (not from the newly secret key rate)
    keyAssociation.SetEffectiveSKR(ratio);
    
    NS_LOG_FUNCTION(this 
      << "keyAssociationId:" << keyAssociation.GetId()
      << "AverageKeyGenerationRate:" << keyAssociation.GetSKR()
      << "ExpectedConsumption:" << keyAssociation.GetExpectedConsumption()
      << "EffectiveSKR:" << keyAssociation.GetEffectiveSKR()
    );

    SaveKeyAssociation(keyAssociation);

  }else{
    NS_FATAL_ERROR(this << "No buffer found!"); 
  }
  
  return output;
  
}

/*
    Create key container json data structure described in ETSI014.
    Limits the size of obtained key to requested size by QKDApp ->
    This should be changed in @futureBuild. In GetKeysFromBuffer KMS shall
    split or merge the keys and take keySize in consideration while searching for key!
    Now, we do not have description of such KMS beahviour (@futureBuild)!
*/
nlohmann::json
QKDKeyManagerSystemApplication::CreateKeyContainer (std::vector<Ptr<QKDKey>> keys) 
{

  NS_LOG_FUNCTION( this << "Create JSON Key Container data structure!");
  nlohmann::json jkeys;
  for(uint32_t i = 0; i < keys.size(); i++){
      if(keys[i]){
          std::string encodedKey = Base64Encode(keys[i]->ConsumeKeyString()); //Encode fetched key in Base64
          NS_LOG_FUNCTION(this << "KEY" << i+1 << keys[i]->GetId() << encodedKey << "\n");
          jkeys["keys"].push_back({ {"key_ID", keys[i]->GetId()}, {"key", encodedKey} });
      }
  }
  return jkeys;

}

/**
 * ********************************************************************************************

 *        KMS 004 Association operations, monitoring
 
 * ********************************************************************************************
 */
std::string
QKDKeyManagerSystemApplication::GenerateKsid () //@toDo
{
  NS_LOG_FUNCTION( this );
  std::string output;
  UUID ksidRaw = UUID::Random();
  //UUID ksidRaw = UUID::Sequential();
  output = ksidRaw.string();
  NS_LOG_FUNCTION(this << output);
  return output;
}

void
QKDKeyManagerSystemApplication::CheckAssociation (std::string ksid)
{
    /*
      To check the state of a single association! Master!
    */
    NS_LOG_FUNCTION(this << "Checking the state of the association " << ksid << " ...");
    std::map<std::string, Association004>::iterator it = m_associations004.find(ksid);
    if(it == m_associations004.end()){
      NS_LOG_DEBUG( this << " Key stream association identified with " << ksid << " does not exists!" );
      return;
    }
    
    if(it->second.associationDirection == 0 && it->second.peerRegistered){ //Check
        if(
          (it->second).tempBuffer.empty() && 
          ((it->second).buffer.empty() || !(it->second).buffer.begin()->second.ready)
        ){  
            NegotiateKeysForAssociation(
              ksid, 
              it->second.qos.maxRate,
              it->second.qos.priority
            ); //Starts reservation of keys for the association
        }

    }else if(it->second.associationDirection == 1){
        NS_FATAL_ERROR(this << "This function must not be called on replica KMS for a given association " << ksid);
    }
}

void 
QKDKeyManagerSystemApplication::PurgeExpiredAssociations()
{
  NS_LOG_FUNCTION(this);
  std::map<std::string, Association004>::iterator it;
  int64_t currentTime = Simulator::Now ().GetSeconds();
  for (it = m_associations004.begin(); it != m_associations004.end();)
  {
      if( it->second.qos.TTL < currentTime ) {
        NS_LOG_FUNCTION(this << "remove association "
          << "ksid: " << (it->second).ksid 
          << "srcSaeId: " << (it->second).srcSaeId 
          << "dstSaeId: " << (it->second).dstSaeId 
          << " with TTL time: " << it->second.qos.TTL
        );
        m_associations004.erase (it++);    
      }else{
        it++;
      }
  }
}


void
QKDKeyManagerSystemApplication::NegotiateKeysForAssociation (std::string ksid, uint32_t keyAmount, uint32_t priority)
{
    NS_LOG_FUNCTION( this << ksid << keyAmount );
    PurgeExpiredAssociations();

    std::map<std::string, Association004>::iterator it = m_associations004.find(ksid);
    if(it == m_associations004.end()){
      NS_LOG_DEBUG( this << " Key stream association identified with " << ksid << " does not exists!" );  
      return;
    }

    UUID dstSae = (it->second).dstSaeId; //Obtain destination SAE
    QKDApplicationEntry appConnection = GetApplicationConnectionDetails( ksid );
    NS_ASSERT(appConnection.IsValid());
    appConnection.PrintRegistryInfo();

    QKDKeyAssociationLinkEntry conn = GetKeyAssociationLinkDetailsByApplicationId( appConnection.GetId().string() );
    NS_ASSERT(conn.IsValid());
    conn.PrintRegistryInfo();

    Ptr<QKDBuffer> buffer = conn.GetSourceBuffer(); //Buffer for this connection
    if(buffer){
        nlohmann::json jkeyIDs; //KeyIDs of the keys to fill the association buffer. Keys shall be marked reserved!
        if(
          buffer->GetReadyKeyCountBit() - buffer->GetTargetKeyCountBit() < keyAmount && 
          buffer->GetReadyKeyCountBit() - buffer->GetTargetKeyCountBit() >= it->second.qos.chunkSize
        ){
            //Minimum amount of key material that could be assigned to the association buffer
            keyAmount = it->second.qos.chunkSize; 
        }else if(buffer->GetReadyKeyCountBit() - buffer->GetTargetKeyCountBit() < it->second.qos.chunkSize){
            NS_LOG_FUNCTION( this << "Not enough key material to assign to the association dedicated buffer!" );
            //for premium apps mantain the key assoications
            if(priority > 0) ScheduleCheckAssociation(Time ("500ms"), "CheckAssociation", ksid); //Shedule new attempt!
            return;
        }

        bool addKeysReady = false;
        while(!addKeysReady){
            Ptr<QKDKey> key = buffer->SearchOptimalKeyToTransform(keyAmount);
            NS_ASSERT(key->GetId() != ""); //Check
            NS_ASSERT(key->GetSizeInBits() != 0); //Check
            buffer->ReserveKey(key->GetId()); //Reserve key for transformation! @toDo include reservation_type
            jkeyIDs["keys"].push_back({ {"key_ID", key->GetId()} }); //Add keyId object to JSON
            (it->second).tempBuffer.push_back(key->GetId()); //Add keyId to tempBuffer

            if(key->GetSizeInBits() >= keyAmount){
              addKeysReady = true;
              keyAmount = 0;
            }else
              keyAmount -= key->GetSizeInBits();

            NS_LOG_FUNCTION(this << "Found key " << key->GetId() << " of size " << key->GetSizeInBits() << " to transform.\n Remaining key ammount to find: " << keyAmount);
        }
        
        Ipv4Address dstKms = (it->second).dstKmsNode;
        std::ostringstream peerkmsAddressTemp; 
        dstKms.Print(peerkmsAddressTemp); //IPv4Address to string
        std::string headerUri = "http://" + peerkmsAddressTemp.str ();
        headerUri += "/api/v1/associations/fill/" + ksid;
        
        std::string msg = jkeyIDs.dump();

        //Create packet
        HTTPMessage httpMessage; 
        httpMessage.CreateRequest(headerUri, "POST", msg);
        std::string hMessage = httpMessage.ToString(); 
        Ptr<Packet> packet = Create<Packet> (
          (uint8_t*) (hMessage).c_str(),
          hMessage.size()
        ); 
        NS_ASSERT (packet);
        
        CheckSocketsKMS( dstKms ); //Check connection to peer KMS!
        Ptr<Socket> sendSocket = GetSendSocketKMS( dstKms );

        HttpQuery query;
        query.method_type = FILL;
        query.destination_sae = dstSae;
        query.ksid = ksid;
        HttpKMSAddQuery(dstKms, query);
        
        sendSocket->Send(packet);
        NS_LOG_FUNCTION( this << "Proposal of keys to fill association " << ksid 
                              << " dedicated store is sent!" << packet->GetUid() << packet->GetSize() << headerUri << msg );
    }else{
        NS_FATAL_ERROR( this << "QKD Buffer for this connection is not found!" );
    }

}

void
QKDKeyManagerSystemApplication::AddKeyToAssociationDedicatedStore (std::string ksid, Ptr<QKDKey> key)
{
  NS_LOG_FUNCTION( this << ksid << key->GetId() );
  std::map<std::string, Association004>::iterator it = m_associations004.find(ksid);
  if(it == m_associations004.end()){
    NS_LOG_DEBUG( this << " Key stream association identified with " << ksid << " does not exists!" );
    return;
  }
  
  uint32_t keyChunkSize = (it->second).qos.chunkSize /8; //Obtain chunk size (in bytes) from the QoS structure!
  std::string secretKey = key->ConsumeKeyString(); //Obtain key string
  
  NS_LOG_FUNCTION( this << "Secret key size (bytes) " << secretKey.size() );
  NS_LOG_FUNCTION( this << "Last index - " << (it->second).lastIndex );
  uint32_t startingIndex = (it->second).lastIndex; //Find the starting index to fill the buffer with the secret key
  bool startingInReady = true; //Is the starting index an existing index thats not ready, or a next to generate index!

  if((it->second).buffer.rbegin() != (it->second).buffer.rend()){
      startingIndex = (it->second).buffer.rbegin()->first;
      if( ((it->second).buffer.rbegin()->second).ready != true ) 
          startingInReady = false;
      else
          startingIndex++;
  }else if((it->second).lastIndex != 0)
      startingIndex++;

  NS_LOG_FUNCTION (this << "Chunk size (bytes), Start Index, Start Ready" << keyChunkSize << startingIndex << startingInReady);
  //Fill the content of the secret key into the buffer!
  while (!secretKey.empty())
  {
      if(!startingInReady)
      {
          uint32_t currentChunkSize = ( (it->second).buffer.rbegin()->second ).key.size(); //In bytes
          NS_LOG_FUNCTION( this << "currentChunkSize" << currentChunkSize);
          uint32_t diff = keyChunkSize - currentChunkSize; //In bytes
          NS_LOG_FUNCTION( this << "diff" << diff );
          //Check the size of the secretKey, is it enough to fill the diff
          std::string incompleteChunkKey = (it->second).buffer.rbegin()->second.key;
          if(secretKey.size() >= diff){
            std::string diffKey = secretKey.substr(0, diff);
            std::string temp = secretKey.substr(diff);
            secretKey = temp;
            std::string completeKey = incompleteChunkKey+diffKey;
            NS_LOG_FUNCTION( this << incompleteChunkKey << diffKey << completeKey);
              
            (it->second).buffer.rbegin()->second.key = completeKey;
            (it->second).buffer.rbegin()->second.ready = true;

            NS_LOG_FUNCTION( this << startingIndex << (it->second).buffer.rbegin()->second.key );

            startingIndex++;
            startingInReady = true;
          }else{
            std::string completeKey = incompleteChunkKey+secretKey;
            secretKey = "";
            (it->second).buffer.rbegin()->second.key = completeKey;
            startingIndex++; //Increase index
          }

      }else{
          uint32_t len; //len is in bytes
          if (secretKey.size() >= keyChunkSize)
              len = keyChunkSize;
          else
              len = secretKey.size();

          std::string temp; //Remaining secret key
          std::string key; //Key to store as a chunk
          key = secretKey.substr(0, len);
          temp = secretKey.substr(len);
          secretKey = temp;

          NS_LOG_FUNCTION( this << startingIndex << key);

          ChunkKey keyC;
          keyC.key = key;
          keyC.index = startingIndex;
          keyC.chunkSize = len*8; //In bits (variable not really needed)
          if (len == keyChunkSize)
              keyC.ready = true;
          else
              keyC.ready = false;

          (it->second).buffer.insert(std::make_pair(startingIndex, keyC));
          startingIndex++; //Increase index
      }  
  }

  (it->second).lastIndex = startingIndex - 1;
  NS_LOG_FUNCTION( this << "Last index stored is " << (it->second).lastIndex );

  NS_LOG_FUNCTION(this << "ksid:" << ksid);
  NS_LOG_FUNCTION(this << "Is association empty:" << (it->second).buffer.empty() );
  NS_LOG_FUNCTION(this << "Is association first key ready:" << (it->second).buffer.begin()->second.ready );
  NS_LOG_FUNCTION(this << "How many keys do we have in association:" << (it->second).buffer.size() );

}

std::string
QKDKeyManagerSystemApplication::Base64Encode(std::string input)
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
QKDKeyManagerSystemApplication::Base64Decode(std::string input)
{
  std::string output;
  CryptoPP::StringSource(input, true,
    new CryptoPP::Base64Decoder(
      new CryptoPP::StringSink(output)
    ) // Base64Dencoder
  ); // StringSource
  return output;
}

void
QKDKeyManagerSystemApplication::ReadJsonQos (
  QKDKeyManagerSystemApplication::QoS &inQos, 
  nlohmann::json jOpenConnectRequest
){

  inQos.chunkSize     = 0;
  inQos.maxRate       = 0;
  inQos.minRate       = 0;
  inQos.jitter        = 0;
  inQos.priority      = 0;
  inQos.timeout       = 0;
  inQos.TTL           = 0; 

  if (jOpenConnectRequest.contains("QoS")) {
    if (jOpenConnectRequest["QoS"].contains("key_chunk_size")) inQos.chunkSize    = jOpenConnectRequest["QoS"]["key_chunk_size"];  
    if (jOpenConnectRequest["QoS"].contains("max_bps")) inQos.maxRate             = jOpenConnectRequest["QoS"]["max_bps"]; 
    if (jOpenConnectRequest["QoS"].contains("min_bps")) inQos.minRate             = jOpenConnectRequest["QoS"]["min_bps"]; 
    if (jOpenConnectRequest["QoS"].contains("jitter")) inQos.jitter               = jOpenConnectRequest["QoS"]["jitter"]; 
    if (jOpenConnectRequest["QoS"].contains("priority")) inQos.priority           = jOpenConnectRequest["QoS"]["priority"]; 
    if (jOpenConnectRequest["QoS"].contains("timeout")) inQos.timeout             = jOpenConnectRequest["QoS"]["timeout"]; 
    if (jOpenConnectRequest["QoS"].contains("TTL")) inQos.TTL                     = jOpenConnectRequest["QoS"]["TTL"]; 
  }

  NS_LOG_FUNCTION(this << inQos.chunkSize << inQos.maxRate << inQos.minRate << inQos.TTL);

  NS_ASSERT (inQos.chunkSize > 0);
  NS_ASSERT (inQos.maxRate >= 0);
  NS_ASSERT (inQos.minRate >= 0);
  NS_ASSERT (inQos.TTL > 0);

  NS_LOG_FUNCTION(this << "chunkSize:"      << inQos.chunkSize);
  NS_LOG_FUNCTION(this << "max_bps:"        << inQos.maxRate);
  NS_LOG_FUNCTION(this << "min_bps:"        << inQos.minRate);
  NS_LOG_FUNCTION(this << "jitter:"         << inQos.jitter);
  NS_LOG_FUNCTION(this << "priority:"       << inQos.priority);
  NS_LOG_FUNCTION(this << "timeout:"        << inQos.timeout);
  NS_LOG_FUNCTION(this << "TTL:"            << inQos.TTL); 
}

void
QKDKeyManagerSystemApplication::CreateNew004Association (
  std::string srcSaeId, 
  std::string dstSaeId, 
  QKDKeyManagerSystemApplication::QoS &inQos,
  Ipv4Address dstKms, 
  std::string &ksid,
  std::string appConnectionId
){
    NS_LOG_FUNCTION( this << srcSaeId << dstSaeId << m_local << dstKms << ksid << appConnectionId);
    inQos.TTL += Simulator::Now ().GetSeconds();

    QKDKeyManagerSystemApplication::Association004 association004;
    association004.srcSaeId = srcSaeId;
    association004.dstSaeId = dstSaeId;
    association004.qos = inQos;
    association004.dstKmsNode = dstKms;
    association004.lastIndex = 0;
    if(ksid.empty()){
        ksid = appConnectionId; //GenerateKsid();
        association004.associationDirection = 0; //Outbound
        association004.peerRegistered = false; 
    }else{
        association004.associationDirection = 1; //Inbound
        association004.peerRegistered = true;
    }
    association004.ksid = ksid;

    NS_LOG_FUNCTION(this << ksid << appConnectionId);

    m_associations004.insert(std::make_pair (ksid, association004)); 
    m_sessionList.insert(std::make_pair (ksid, 1)); 
}
 
bool
QKDKeyManagerSystemApplication::ProcessQoSRequest(
  QKDApplicationEntry &appConnection,
  QKDKeyAssociationLinkEntry &keyAssociation,
  QKDKeyManagerSystemApplication::QoS &inQos,
  QKDKeyManagerSystemApplication::QoS &outQos,
  std::string ksid
){

  NS_LOG_FUNCTION( this 
    << "ksid:"          << ksid
    << "minRate:"       << inQos.minRate 
    << "maxRate:"       << inQos.maxRate 
    << "priority:"      << inQos.priority 
    << "chunkSize:"     << inQos.chunkSize 
    << "jitter:"        << inQos.jitter 
    << "timeout:"       << inQos.timeout 
    << "TTL:"           << inQos.TTL 
    << "eskr:"          << keyAssociation.GetEffectiveSKR()
    << "consumption:"   << keyAssociation.GetExpectedConsumption()
  );


  double ratioSKR;
  if(keyAssociation.GetExpectedConsumption() == 0)
    ratioSKR = 1;
  else
    ratioSKR = (double) keyAssociation.GetExpectedConsumption()/(double) keyAssociation.GetEffectiveSKR();

  NS_LOG_FUNCTION(this 
    << "keyAssociationId:"    << keyAssociation.GetId()
    << "SKR:"                 << keyAssociation.GetSKR()
    << "EffectiveSKR:"        << keyAssociation.GetEffectiveSKR()
    << "ratioSKR:"            << ratioSKR
    << "ExpectedConsumption:" << keyAssociation.GetExpectedConsumption()
  );
  
  uint32_t processWithQos = 1;

  if(processWithQos)
  {

    outQos = inQos;
    if(
      inQos.maxRate == 0 ||
      keyAssociation.GetEffectiveSKR() < m_minKeyRate.GetBitRate() 
    ){
      NS_LOG_FUNCTION(this << "No resources available!");
      outQos.maxRate = 0;

      m_providedQoS(
        appConnection.GetId().string(), 
        keyAssociation.GetId().string(),
        ceil(inQos.maxRate/inQos.chunkSize),
        round (keyAssociation.GetEffectiveSKR()/inQos.chunkSize),
        0,
        0,
        inQos.priority
      );

      return false;

    }else if (
      ratioSKR < m_qos_maxrate_threshold
    ) {

      if(inQos.priority == 0){
        NS_LOG_FUNCTION(this << "No resources for low-priority requests!");
        outQos.maxRate = 0;

        m_providedQoS(
          appConnection.GetId().string(), 
          keyAssociation.GetId().string(),
          ceil(inQos.maxRate/inQos.chunkSize),
          round (keyAssociation.GetEffectiveSKR()/inQos.chunkSize),
          0,
          0,
          inQos.priority
        );

        return false;      
      }else{ 
        std::map<std::string, uint32_t>::iterator it2 = m_sessionList.find(ksid);
        if(it2 != m_sessionList.end()){ 
          NS_LOG_FUNCTION(this << "SESSION with KSID " << ksid << " was located in the m_session_list!");
        }else{
          NS_LOG_FUNCTION(this << "SESSION with KSID " << ksid << " was *NOT* located in m_session_list!");
          NS_LOG_FUNCTION(this << "WE HAVE NO ENOUGH RESOURCES TO SERVE UNTRUSTED APPS AT THE MOMENT!");
          outQos.maxRate = 0;

          m_providedQoS(
            appConnection.GetId().string(), 
            keyAssociation.GetId().string(),
            ceil(inQos.maxRate/inQos.chunkSize),
            round (keyAssociation.GetEffectiveSKR()/inQos.chunkSize),
            0,
            0,
            inQos.priority
          );
          
          return false;
        }
      }

    } else {

      /////////// CALCULATE MAX RATE
      uint32_t chunkSizeDoubled = (inQos.chunkSize*1);
      uint32_t requestedNumberOfChunkKeys = 0;
      if(inQos.maxRate >0 && inQos.maxRate < chunkSizeDoubled){
        requestedNumberOfChunkKeys = 1;
      }else{
        requestedNumberOfChunkKeys = ceil(inQos.maxRate/chunkSizeDoubled);
      }
      uint32_t supportedNumberOfChunkKeys = round (keyAssociation.GetEffectiveSKR()/chunkSizeDoubled);
      uint32_t priorityThreshold = round(supportedNumberOfChunkKeys/2);
      uint32_t providedNumberOfChunkKeys;

      if(inQos.priority == 1){
        providedNumberOfChunkKeys = m_random->GetValue (priorityThreshold, supportedNumberOfChunkKeys);
      }else{
        providedNumberOfChunkKeys = m_random->GetValue (1,priorityThreshold);
      }
      //even if we have enough resources, only give what is requested
      if(providedNumberOfChunkKeys > requestedNumberOfChunkKeys)
        providedNumberOfChunkKeys = requestedNumberOfChunkKeys;
      
      NS_LOG_FUNCTION(this << "requestedNumberOfChunkKeys:" << requestedNumberOfChunkKeys);
      NS_LOG_FUNCTION(this << "supportedNumberOfChunkKeys:" << supportedNumberOfChunkKeys);
      NS_LOG_FUNCTION(this << "priorityThreshold:" << priorityThreshold); 
      NS_LOG_FUNCTION(this << "providedNumberOfChunkKeys:" << providedNumberOfChunkKeys);
      outQos.maxRate = providedNumberOfChunkKeys * inQos.chunkSize; 
      ///////////////// END OF MAX RATE CALCULATION/////////////////////////////

      ///////// CALCULATE TTL
      uint32_t providedTTL = m_default_ttl;
      NS_LOG_FUNCTION(this << "DefaultTTL:" << m_default_ttl);

      std::map<std::string, uint32_t>::iterator it2 = m_sessionList.find(ksid);
      if(it2 != m_sessionList.end()){
        providedTTL *= it2->second;
        NS_LOG_FUNCTION(this << "SESSION with KSID " << ksid << " was located in the m_session_list!");
      }else{
        NS_LOG_FUNCTION(this << "SESSION with KSID " << ksid << " was *NOT* located in m_session_list!");
      }
      //even if we have enough resources, only give what is requested
      if(providedTTL > inQos.TTL) providedTTL = inQos.TTL;
      outQos.TTL = providedTTL; 
      NS_LOG_FUNCTION(this << "providedTTL:" << providedTTL);
      ///////////////// END OF TTL CALCULATION/////////////////////////////

      NS_LOG_FUNCTION(this << outQos.chunkSize << outQos.maxRate << outQos.minRate << outQos.TTL);

      NS_ASSERT (outQos.chunkSize > 0);
      NS_ASSERT (outQos.maxRate >= 0);
      NS_ASSERT (outQos.minRate >= 0);
      NS_ASSERT (outQos.TTL > 0);

      m_providedQoS(
        appConnection.GetId().string(), 
        keyAssociation.GetId().string(),
        requestedNumberOfChunkKeys,
        supportedNumberOfChunkKeys,
        providedNumberOfChunkKeys,
        priorityThreshold,
        inQos.priority
      );

      return true;
    }
  
  //old strict approach (provide requested keys or not)
  }else{
    
    uint32_t chunkSizeDoubled = (inQos.chunkSize);
    uint32_t supportedNumberOfChunkKeys = round (keyAssociation.GetEffectiveSKR()/chunkSizeDoubled); 
    uint32_t requestedNumberOfChunkKeys = ceil (inQos.maxRate/chunkSizeDoubled);
    uint32_t providedNumberOfChunkKeys = requestedNumberOfChunkKeys;
    uint32_t priorityThreshold = 0;
 
    if(requestedNumberOfChunkKeys > supportedNumberOfChunkKeys)
    {
      outQos.maxRate = 0;
      providedNumberOfChunkKeys = 0;
    }

    NS_LOG_FUNCTION(this << "requestedNumberOfChunkKeys:" << requestedNumberOfChunkKeys);
    NS_LOG_FUNCTION(this << "supportedNumberOfChunkKeys:" << supportedNumberOfChunkKeys);
    NS_LOG_FUNCTION(this << "priorityThreshold:" << priorityThreshold); 
    NS_LOG_FUNCTION(this << "providedNumberOfChunkKeys:" << providedNumberOfChunkKeys);


    m_providedQoS(
      appConnection.GetId().string(), 
      keyAssociation.GetId().string(),
      requestedNumberOfChunkKeys,
      supportedNumberOfChunkKeys,
      providedNumberOfChunkKeys,
      priorityThreshold,
      inQos.priority
    );
  }

  
  return true;
}



std::string
QKDKeyManagerSystemApplication::GenerateKeyId (){
    
    std::string keyId;
    //UUID keyIdRaw = UUID::Sequential();
    UUID keyIdRaw = UUID::Random();
    keyId = keyIdRaw.string();
    NS_LOG_FUNCTION(this << keyId);
    return keyId;
}

} // Namespace ns3
