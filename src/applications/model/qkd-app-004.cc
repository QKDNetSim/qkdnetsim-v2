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

#include "ns3/address.h"
#include "ns3/address-utils.h"
#include "ns3/log.h"
#include "ns3/inet-socket-address.h"
#include "ns3/inet6-socket-address.h"
#include "ns3/node.h"
#include "ns3/socket.h" 
#include "ns3/udp-socket-factory.h"
#include "ns3/tcp-socket-factory.h"
#include "ns3/simulator.h"
#include "ns3/socket-factory.h"
#include "ns3/packet.h"
#include "ns3/trace-source-accessor.h" 
#include "qkd-app-004.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDApp004");

NS_OBJECT_ENSURE_REGISTERED (QKDApp004);

TypeId 
QKDApp004::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDApp004")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<QKDApp004> ()
    .AddAttribute ("Protocol", "The type of protocol to use.",
                   TypeIdValue (TcpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&QKDApp004::m_tid),
                   MakeTypeIdChecker ())
    .AddAttribute ("LengthOfAuthenticationTag", 
                   "The default length of the authentication tag",
                   UintegerValue (256), //32 bytes
                   MakeUintegerAccessor (&QKDApp004::m_authenticationTagLengthInBits),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("EncryptionType", 
                   "The type of encryption to be used (0-unencrypted, 1-OTP, 2-AES)",
                   UintegerValue (2),
                   MakeUintegerAccessor (&QKDApp004::m_encryptionTypeInt),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("AuthenticationType", 
                   "The type of authentication to be used (0-unauthenticated, 1-VMAC, 2-MD5, 3-SHA1)",
                   UintegerValue (3),
                   MakeUintegerAccessor (&QKDApp004::m_authenticationTypeInt),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("AESLifetime", 
                   "Lifetime of AES key expressed in number of packets",
                   UintegerValue (1),
                   MakeUintegerAccessor (&QKDApp004::m_aesLifetime),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("UseCrypto",
                   "Should crypto functions be performed (0-No, 1-Yes)",
                   UintegerValue (0),
                   MakeUintegerAccessor (&QKDApp004::m_useCrypto),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("LengthOfKeyBufferForEncryption",
                   "How many keys to store in local buffer of QKDApp004 for encryption?",
                   UintegerValue (10),
                   MakeUintegerAccessor (&QKDApp004::m_keyBufferLengthEncryption),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("LengthOfKeyBufferForAuthentication",
                   "How many keys to store in local buffer of QKDApp004 for authentication?",
                   UintegerValue (10),
                   MakeUintegerAccessor (&QKDApp004::m_keyBufferLengthAuthentication),
                   MakeUintegerChecker<uint32_t> ())   
    .AddAttribute ("SocketToKMSHoldTime","How long (seconds) should QKDApp004 wait to close socket to KMS after receiving REST response?",
                   TimeValue (Seconds (0.5)),
                   MakeTimeAccessor (&QKDApp004::m_holdTime),
                   MakeTimeChecker ()) 
    .AddAttribute ("MaliciousApplication",
                   "Is this application malicious?",
                   UintegerValue (0), //default value: NO/FALSE
                   MakeUintegerAccessor (&QKDApp004::m_malicious),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("DoSAttackIntensity",
                   "The time elapsed between successive malicious requests; For testing DoS/DDoS attacks;",
                   TimeValue (Seconds (0.1)), //default value: 100ms
                   MakeTimeAccessor (&QKDApp004::m_dosAttackIntensity),
                   MakeTimeChecker())
    .AddAttribute ("MinDataRate", "The minimal data key rate (encryption+authentication) of the app (QoS settings).",
                   DataRateValue (DataRate ("0kb/s")),
                   MakeDataRateAccessor (&QKDApp004::m_minDataRate),
                   MakeDataRateChecker ())

    .AddAttribute ("Priority",
                   "QoS Priority (0 - default, 1 - premium)",
                   UintegerValue (0),
                   MakeUintegerAccessor (&QKDApp004::m_priority),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("TTL",
                   "QoS TTL - defines duration (seconds) of ETSI004 association",
                   UintegerValue (5),
                   MakeUintegerAccessor (&QKDApp004::m_ttl),
                   MakeUintegerChecker<uint32_t> ())


    .AddTraceSource ("Tx", "A new packet is created and is sent",
                     MakeTraceSourceAccessor (&QKDApp004::m_txTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("TxSig", "A new signaling packet is created and is sent",
                     MakeTraceSourceAccessor (&QKDApp004::m_txSigTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("TxKMS", "A new packet is created and is sent to local KMS",
                     MakeTraceSourceAccessor (&QKDApp004::m_txKmsTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("Rx", "A new packet is received",
                     MakeTraceSourceAccessor (&QKDApp004::m_rxTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("RxSig", "A new signaling packet is received",
                     MakeTraceSourceAccessor(&QKDApp004::m_rxSigTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("RxKMS", "A new packet is received from local KMS",
                     MakeTraceSourceAccessor (&QKDApp004::m_rxKmsTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("StateTransition",
                     "Trace fired upon every QKDApp state transition.",
                     MakeTraceSourceAccessor (&QKDApp004::m_stateTransitionTrace),
                     "ns3::Application::StateTransitionCallback")
    .AddTraceSource ("PacketEncrypted",
                    "The change trance for currenly ecrypted packet",
                     MakeTraceSourceAccessor (&QKDApp004::m_encryptionTrace),
                     "ns3::QKDCrypto::PacketEncrypted")
    .AddTraceSource ("PacketDecrypted",
                    "The change trance for currenly decrypted packet",
                     MakeTraceSourceAccessor (&QKDApp004::m_decryptionTrace),
                     "ns3::QKDCrypto::PacketDecrypted")
    .AddTraceSource ("PacketAuthenticated",
                    "The change trance for currenly authenticated packet",
                     MakeTraceSourceAccessor (&QKDApp004::m_authenticationTrace),
                     "ns3::QKDCrypto::PacketAuthenticated")
    .AddTraceSource ("PacketDeAuthenticated",
                    "The change trance for currenly deauthenticated packet",
                     MakeTraceSourceAccessor (&QKDApp004::m_deauthenticationTrace),
                     "ns3::QKDCrypto::PacketDeAuthenticated")
    .AddTraceSource ("Mx", "Missed send packet call",
                     MakeTraceSourceAccessor (&QKDApp004::m_mxTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("KeyObtained", "Trace amount of obtained key material",
                     MakeTraceSourceAccessor (&QKDApp004::m_obtainedKeyMaterialTrace),
                     "ns3::QKDApp004::KeyObtained")
  ;

  return tid;
}


uint32_t QKDApp004::m_applicationCounts = 0;

/**
 * ********************************************************************************************

 *        SETUP
 
 * ********************************************************************************************
 */

QKDApp004::QKDApp004 () 
  : m_sendSignalingSocketApp (0), 
    m_sinkSignalingSocketApp (0),
    m_sendDataSocketApp (0),
    m_sinkDataSocketApp (0),
    m_sendSocketToKMS (0), 
    m_sinkSocketFromKMS (0), 
    m_packetSize (0), 
    m_dataRate (0),
    m_sendEvent (),
    m_packetsSent (0),
    m_dataSent (0),
    m_master (0),
    m_encryptor (0),
    m_appState (NOT_STARTED)
{
  m_applicationCounts++; 
  m_id = UUID::Random();
  m_random = CreateObject<UniformRandomVariable> (); 
}

QKDApp004::~QKDApp004()
{
  //Data sockets
  m_sendDataSocketApp = 0;
  m_sinkDataSocketApp = 0;
  //Signaling sockets
  m_sendSignalingSocketApp = 0;
  m_sinkSignalingSocketApp = 0;
  //KMS sockets
  m_sendSocketToKMS = 0;
  m_sinkSocketFromKMS = 0;
}

void
QKDApp004::Setup (
  std::string socketType,
  Address src,  
  Address dst,   
  Address kms,   
  UUID dstSaeId,
  std::string type
){ 
    Setup(
      socketType,
      src,
      dst, 
      kms, 
      dstSaeId,
      0,
      0,
      DataRate ("0bps"),
      type
  );
}

void
QKDApp004::Setup (
  std::string socketType,
  Address src,  
  Address dst,  
  Address kms,   
  UUID dstSaeId,
  uint32_t packetSize, 
  uint32_t nPacketsSize, 
  DataRate dataRate,
  std::string type
){

  NS_LOG_FUNCTION(this << type << src << dst << packetSize << nPacketsSize << dataRate.GetBitRate());

  if(type == "alice"){
    m_master = 1;
    NS_ASSERT(packetSize>0);
    NS_ASSERT(dataRate.GetBitRate() > 0);
  }else{
    m_master = 0;
  }

  m_local = src;
  m_peer = dst; 
  m_kms = kms;
  m_dstSaeId = dstSaeId;

  m_localSignaling = InetSocketAddress(
    InetSocketAddress::ConvertFrom(m_local).GetIpv4 (),
    7080
  );
  m_peerSignaling = InetSocketAddress(
    InetSocketAddress::ConvertFrom(m_peer).GetIpv4 (),
    7080
  );

  m_packetSize = packetSize; 
  m_dataRate = dataRate; 
  m_socketType = socketType;


  InitializeAssociations();
  SwitchAppState(INITIALIZED);

}

/**
 * ********************************************************************************************

 *        SCHEDULE functions
 
 * ********************************************************************************************
 */
void
QKDApp004::ScheduleTx (void)
{
  NS_LOG_FUNCTION (this << m_appState);

  if (m_appState != STOPPED && m_appState != NOT_STARTED)
  {
    //NS_LOG_FUNCTION (this << "QKDApp is running!");
    m_delay = m_packetSize * 8 / static_cast<double> (m_dataRate.GetBitRate ());
    //NS_LOG_FUNCTION( this << "delay" << Seconds (delay) );
    Time tNext (Seconds (m_delay));
    m_sendEvent = Simulator::Schedule (tNext, &QKDApp004::SendPacket, this);
  } else {
    NS_LOG_FUNCTION (this << "QKDApp is" << GetAppStateString(m_appState));
  }
}

void
QKDApp004::CancelScheduledAction(uint32_t eventId)
{
  NS_LOG_FUNCTION(this << eventId);

  std::map<uint32_t, EventId >::iterator eventEntry = m_scheduledEvents.find ( eventId );
  if(eventEntry != m_scheduledEvents.end ()){
    Simulator::Cancel (eventEntry->second);
  }else{
    NS_FATAL_ERROR ("Invalid entryId " << eventId );
  }

}


/**
 * ********************************************************************************************

 *        SOCKET functions
 
 * ********************************************************************************************
 */
void
QKDApp004::PrepareSinkSocketFromKMS()
{
  NS_LOG_FUNCTION(this);

  if(!m_sinkSocketFromKMS){
    Address localAddress = InetSocketAddress(
      //InetSocketAddress::ConvertFrom(m_kms).GetIpv4 (),
      Ipv4Address::GetAny (), 
      82
      //InetSocketAddress::ConvertFrom(m_kms).GetPort ()+1
    ); 
    m_sinkSocketFromKMS = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId () );

    if (m_sinkSocketFromKMS->Bind (localAddress) == -1)
      NS_FATAL_ERROR ("Failed to bind socket");

    m_sinkSocketFromKMS->Listen ();
    m_sinkSocketFromKMS->ShutdownSend ();
    m_sinkSocketFromKMS->SetRecvCallback (MakeCallback (&QKDApp004::HandleReadFromKMS, this));
    m_sinkSocketFromKMS->SetAcceptCallback (
      MakeCallback (&QKDApp004::ConnectionRequestedFromKMS, this),
      MakeCallback (&QKDApp004::HandleAcceptFromKMS, this)
    );
    m_sinkSocketFromKMS->SetCloseCallbacks (
      MakeCallback (&QKDApp004::HandlePeerCloseFromKMS, this),
      MakeCallback (&QKDApp004::HandlePeerErrorFromKMS, this)
    );  
    NS_LOG_FUNCTION (this << "Create new APP socket " << m_sinkSocketFromKMS 
      << " to listen packets from KMS on " <<  InetSocketAddress::ConvertFrom(localAddress).GetIpv4 () 
      << " and port " <<  InetSocketAddress::ConvertFrom(localAddress).GetPort ()   
    );
  }else{
     NS_LOG_FUNCTION (this << "Socket to listen from local KMS exists!" << m_sinkSocketFromKMS);
  }

}

void
QKDApp004::PrepareSendSocketToKMS()
{
  NS_LOG_FUNCTION(this);

  if(!m_sendSocketToKMS)
    m_sendSocketToKMS = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId () );
  
  Address temp; 
  if(m_sendSocketToKMS->GetPeerName (temp) != 0) {
    Address lkmsAddress = InetSocketAddress(
      InetSocketAddress::ConvertFrom(m_kms).GetIpv4 (),
      InetSocketAddress::ConvertFrom(m_kms).GetPort () 
    );
    m_sendSocketToKMS->SetConnectCallback (
      MakeCallback (&QKDApp004::ConnectionToKMSSucceeded, this),
      MakeCallback (&QKDApp004::ConnectionToKMSFailed, this)); 
    m_sendSocketToKMS->SetDataSentCallback (
      MakeCallback (&QKDApp004::DataToKMSSend, this));  
    m_sendSocketToKMS->SetCloseCallbacks (
      MakeCallback (&QKDApp004::HandlePeerCloseToKMS, this),
      MakeCallback (&QKDApp004::HandlePeerErrorToKMS, this)
    );  
    m_sendSocketToKMS->Connect ( lkmsAddress );
    m_sendSocketToKMS->TraceConnectWithoutContext ("RTT", MakeCallback (&QKDApp004::RegisterAckTime, this)); 
    NS_LOG_FUNCTION (this << "Create new APP socket " << m_sendSocketToKMS << " to reach local KMS at " 
      << InetSocketAddress::ConvertFrom(m_kms).GetIpv4 () << ":" << InetSocketAddress::ConvertFrom(m_kms).GetPort () 
      << "!");
  }else{
     NS_LOG_FUNCTION (this << "Active socket to reach local KMS exists!" << m_sendSocketToKMS);
  }

}

void
QKDApp004::PrepareSendSocketToApp()
{
  NS_LOG_FUNCTION(this);

  if(!m_sendSignalingSocketApp || !m_sendDataSocketApp){

    if(!m_sendSignalingSocketApp){

      if(m_socketType == "tcp"){
        m_sendSignalingSocketApp = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId () );
      }else{
        m_sendSignalingSocketApp = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId () );
      }

      NS_LOG_FUNCTION (this << "m_sendSignalingSocketApp:" << m_sendSignalingSocketApp
        << InetSocketAddress::ConvertFrom(m_localSignaling).GetIpv4 () 
        << InetSocketAddress::ConvertFrom(m_localSignaling).GetPort ()
      ); 

      m_sendSignalingSocketApp->Connect (m_peerSignaling); 
      m_sendSignalingSocketApp->SetConnectCallback (
        MakeCallback (&QKDApp004::ConnectionSignalingToAppSucceeded, this),
        MakeCallback (&QKDApp004::ConnectionSignalingToAppFailed, this)); 
    }

    if(!m_sendDataSocketApp){

      if(m_socketType == "tcp"){
        m_sendDataSocketApp = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId () );
      }else{
        m_sendDataSocketApp = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId () );
      }

      NS_LOG_FUNCTION (this << "m_sendDataSocketApp:" << m_sendDataSocketApp
        << InetSocketAddress::ConvertFrom(m_local).GetIpv4 () 
        << InetSocketAddress::ConvertFrom(m_local).GetPort ()
      ); 

      m_sendDataSocketApp->Connect (m_peer); 
      m_sendDataSocketApp->SetConnectCallback (
        MakeCallback (&QKDApp004::ConnectionToAppSucceeded, this),
        MakeCallback (&QKDApp004::ConnectionToAppFailed, this)); 
    }

  }else{
    NS_LOG_FUNCTION (this << "Socket to reach peer app exists!" << m_sendSignalingSocketApp);
  }
}

void
QKDApp004::PrepareSinkSocketFromApp()
{
  NS_LOG_FUNCTION(this);

  if(!m_sinkSignalingSocketApp)
  {

    if(m_socketType == "tcp")
      m_sinkSignalingSocketApp = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId () );
    else
      m_sinkSignalingSocketApp = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId () );  

    NS_LOG_FUNCTION (this << "m_sinkSignalingSocketApp:" << m_sinkSignalingSocketApp
      << InetSocketAddress::ConvertFrom(m_localSignaling).GetIpv4 () 
      << InetSocketAddress::ConvertFrom(m_localSignaling).GetPort ()
    ); 

    if (m_sinkSignalingSocketApp->Bind (m_localSignaling) == -1)
      NS_FATAL_ERROR ("Failed to bind socket");

    m_sinkSignalingSocketApp->Listen ();
    m_sinkSignalingSocketApp->ShutdownSend (); 
    m_sinkSignalingSocketApp->SetRecvCallback (MakeCallback (&QKDApp004::HandleReadSignalingFromApp, this));
    m_sinkSignalingSocketApp->SetAcceptCallback (
      MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
      MakeCallback (&QKDApp004::HandleAcceptSignalingFromApp, this)
    );
    m_sinkSignalingSocketApp->SetCloseCallbacks (
      MakeCallback (&QKDApp004::HandlePeerCloseSignalingFromApp, this),
      MakeCallback (&QKDApp004::HandlePeerErrorSignalingFromApp, this)
    ); 

  }else{
     NS_LOG_FUNCTION (this << "Socket to listen signaling from peer app exists!" << m_sinkSignalingSocketApp);
  }


  if(!m_sinkDataSocketApp)
  {

    if(m_socketType == "tcp")
      m_sinkDataSocketApp = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId () );
    else
      m_sinkDataSocketApp = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId () );  

    NS_LOG_FUNCTION (this << "m_sinkDataSocketApp:" << m_sinkDataSocketApp
      << InetSocketAddress::ConvertFrom(m_local).GetIpv4 () 
      << InetSocketAddress::ConvertFrom(m_local).GetPort ()
    ); 

    if (m_sinkDataSocketApp->Bind (m_local) == -1)
      NS_FATAL_ERROR ("Failed to bind socket");
    
    m_sinkDataSocketApp->Listen ();
    m_sinkDataSocketApp->ShutdownSend (); 
    m_sinkDataSocketApp->SetRecvCallback (MakeCallback (&QKDApp004::HandleReadFromApp, this));
    m_sinkDataSocketApp->SetAcceptCallback (
      MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
      MakeCallback (&QKDApp004::HandleAcceptFromApp, this)
    );
    m_sinkDataSocketApp->SetCloseCallbacks (
      MakeCallback (&QKDApp004::HandlePeerCloseFromApp, this),
      MakeCallback (&QKDApp004::HandlePeerErrorFromApp, this)
    ); 
  }else{
     NS_LOG_FUNCTION (this << "Socket to listen data from peer app exists!" << m_sinkSignalingSocketApp);
  }

}

bool
QKDApp004::ConnectionRequestedFromKMS (Ptr<Socket> socket, const Address &from)
{
  NS_LOG_FUNCTION (this << socket << from 
    << InetSocketAddress::ConvertFrom(from).GetIpv4 () 
    << InetSocketAddress::ConvertFrom(from).GetPort ()
  ); 
  NS_LOG_FUNCTION (this << "QKDApp Connection from KMS requested on socket " << socket);
  return true; // Unconditionally accept the connection request.

}

void 
QKDApp004::HandleAcceptFromKMS (Ptr<Socket> socket, const Address& from)
{ 
  Address peer;
  NS_LOG_FUNCTION (this << socket << from 
    << InetSocketAddress::ConvertFrom(from).GetIpv4 () 
    << InetSocketAddress::ConvertFrom(from).GetPort ()
  );  
  NS_LOG_FUNCTION (this << "QKDApp Connection from KMS accepted on socket " << socket);
  socket->SetRecvCallback (MakeCallback (&QKDApp004::HandleReadFromKMS, this));
  ProcessPacketsToKMSFromQueue();
}

void 
QKDApp004::HandleAcceptFromApp (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from 
    << InetSocketAddress::ConvertFrom(from).GetIpv4 () 
    << InetSocketAddress::ConvertFrom(from).GetPort ()
  );  

  NS_LOG_FUNCTION (this << "QKDApp Connection from APP accepted on socket " << s);
  s->SetRecvCallback (MakeCallback (&QKDApp004::HandleReadFromApp, this));
} 

void 
QKDApp004::HandleAcceptSignalingFromApp (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from 
    << InetSocketAddress::ConvertFrom(from).GetIpv4 () 
    << InetSocketAddress::ConvertFrom(from).GetPort ()
  );  

  NS_LOG_FUNCTION (this << "QKDApp Signaling Connection from APP accepted on socket " << s);
  s->SetRecvCallback (MakeCallback (&QKDApp004::HandleReadSignalingFromApp, this));
} 

void
QKDApp004::ConnectionToKMSSucceeded (Ptr<Socket> socket) 
{
  NS_LOG_FUNCTION (this << socket << "QKDApp Connection to KMS succeeded via socket " << socket);
}

void
QKDApp004::ConnectionToKMSFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket << "QKDApp, Connection to KMS Failed via socket " << socket);
}

void
QKDApp004::ConnectionToAppSucceeded (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket << "QKDApp Connection to APP succeeded via socket " << socket);
}

void
QKDApp004::ConnectionToAppFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket << "QKDApp, Connection to APP Failed via socket " << socket);
}

void
QKDApp004::ConnectionSignalingToAppSucceeded (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket << "QKDApp Signaling Connection to APP succeeded via socket " << socket);
}

void
QKDApp004::ConnectionSignalingToAppFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket << "QKDApp, Connection to APP Failed via socket " << socket);
}

void 
QKDApp004::HandlePeerCloseFromKMS (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDApp004::HandlePeerErrorFromKMS (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDApp004::HandlePeerCloseToKMS (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  if(socket == m_sendSocketToKMS) {
    m_sendSocketToKMS->SetConnectCallback (
      MakeNullCallback<void, Ptr<Socket> > (),
      MakeNullCallback<void, Ptr<Socket> > ()
    ); 
    m_sendSocketToKMS->SetCloseCallbacks (
      MakeNullCallback<void, Ptr<Socket> > (),
      MakeNullCallback<void, Ptr<Socket> > ()
    );
    m_sendSocketToKMS = 0;
  }
}

void 
QKDApp004::HandlePeerErrorToKMS (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
  if(socket == m_sendSocketToKMS) { 
    m_sendSocketToKMS->SetConnectCallback (
      MakeNullCallback<void, Ptr<Socket> > (),
      MakeNullCallback<void, Ptr<Socket> > ()
    ); 
    m_sendSocketToKMS->SetCloseCallbacks (
      MakeNullCallback<void, Ptr<Socket> > (),
      MakeNullCallback<void, Ptr<Socket> > ()
    );
    m_sendSocketToKMS = 0;
  }
}

void 
QKDApp004::HandlePeerCloseFromApp (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}
void 
QKDApp004::HandlePeerErrorFromApp (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDApp004::HandlePeerCloseSignalingFromApp (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDApp004::HandlePeerErrorSignalingFromApp (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDApp004::HandleReadFromKMS (Ptr<Socket> socket)
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
  
      NS_LOG_FUNCTION (this 
        << packet << "PACKETID: " << packet->GetUid() 
        << " of size: " << packet->GetSize()
      ); 

      if (InetSocketAddress::IsMatchingType (from))
      {
          NS_LOG_FUNCTION("At time " << Simulator::Now ().GetSeconds ()
                   << "s packet from KMS received "
                   <<  packet->GetSize () << " bytes from "
                   << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                   << " port " << InetSocketAddress::ConvertFrom (from).GetPort ()
          );
      }
      PacketReceivedFromKMS (packet, from, socket);
  }

  if(m_queue_kms.size() == 0){
    NS_LOG_FUNCTION(this << "Close socket to KMS!");
    if (m_sendSocketToKMS) {
      Time tNext (m_holdTime);
      m_closeSocketEvent = Simulator::Schedule (tNext, &QKDApp004::CloseSocketToKms, this); 
    }
  }else{
    if (m_closeSocketEvent.IsRunning ()) Simulator::Cancel (m_closeSocketEvent);
    ProcessPacketsToKMSFromQueue();
  } 
}

void
QKDApp004::CloseSocketToKms(){
  
  NS_LOG_FUNCTION(this);
  if (m_sendSocketToKMS && m_queue_kms.size() == 0) {
    m_sendSocketToKMS->Close();
    m_sendSocketToKMS = 0;
  }
}

void
QKDApp004::ProcessPacketsToKMSFromQueue(){
  
  NS_LOG_FUNCTION (this << m_queue_kms.size() );

  //check whether the socket to KMS is active and connected
  Address temp; 
  if(!m_sendSocketToKMS || m_sendSocketToKMS->GetPeerName (temp) != 0) {
    PrepareSendSocketToKMS();
  }else{
    if(m_queue_kms.size() > 0){
      uint32_t c = 0;
      auto it = m_queue_kms.begin();
      while (it != m_queue_kms.end())
      {
        NS_LOG_FUNCTION(this << c << m_queue_kms.size() << it->keyType );
        Http004KMSQuery(it->uri, it->ksid, it->keyType);

        if(it->packet) {
          m_txKmsTrace (it->packet);
          m_sendSocketToKMS->Send(it->packet);
        }
        m_queue_kms.erase(it);
        c++;
      }
    }
  }
}

void
QKDApp004::PacketReceivedFromKMS (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION ( this << p->GetUid() << p->GetSize() << from );
  std::string receivedStatus = p->ToString();
  NS_LOG_FUNCTION ( this << "\n\n\n" << p->GetUid() << p->GetSize() << receivedStatus << from );

  if(m_malicious)
    return; //Malicious application does not process responses, it only overwhelms KMS by requests 

  Ptr<Packet> buffer;
  if (receivedStatus.find("Fragment") != std::string::npos) {
    auto itBuffer = m_buffer_kms.find (from);
    if (itBuffer == m_buffer_kms.end ()){
      itBuffer = m_buffer_kms.insert (
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

  NS_LOG_FUNCTION(this << "CONTENT OF THE BUFFER: \n" << requestString);

  NS_LOG_FUNCTION(this << "Packet payload:" << requestString);
 
  //parse HTTP message
  parser.Parse(&request, requestString);
  if(request.IsFragmented() || request.GetStatusMessage() == "Undefined")
  {
    NS_LOG_FUNCTION(this << "HTTP Content Parsed after merge with buffer: " << request.ToString() << "\n ***IsFragmented:" << request.IsFragmented() << "\n\n\n\n"); 
  }else{
    NS_LOG_FUNCTION(this << "Full packet received:" << request.ToString()  );
  } 
  NS_LOG_FUNCTION(this << "HTTPMessage Size:" << request.GetSize());

  while (buffer->GetSize () >= request.GetSize())
  {
    NS_LOG_DEBUG ("Parsing packet pid(" << p->GetUid() << ") of size " << request.GetSize () 
      << " (Header size:" << request.GetHeadersSize() 
      << " content length:" << request.GetContentLength() 
      << ") from buffer of size " << buffer->GetSize ()
    );
    Ptr<Packet> completePacket = buffer->CreateFragment (0, static_cast<uint32_t> (request.GetSize () ));

    uint8_t *b2 = new uint8_t[completePacket->GetSize ()];
    completePacket->CopyData(b2, completePacket->GetSize ());
    std::string completePacketString = std::string((char*)b2); 

    HTTPMessage completePacketHttp;
    parser.Parse(&completePacketHttp, completePacketString);
    delete[] b2;
    
    NS_LOG_FUNCTION(this << "completePacketHttp" << completePacketHttp.IsFragmented());

    if(completePacketHttp.IsFragmented() == false){
      NS_LOG_FUNCTION( this << "821: " << buffer->GetSize() << completePacketHttp.GetSize() << request.GetSize() << completePacketHttp.IsFragmented() );
      NS_LOG_FUNCTION(this << "Croped HTTP message: " << completePacketHttp.ToString());
  
      buffer->RemoveAtStart (static_cast<uint32_t> (completePacketHttp.GetSize () ));
      m_rxKmsTrace (completePacket);
      ProcessResponseFromKMS(completePacketHttp, completePacket, socket);
    } 
    NS_LOG_FUNCTION(this << "Croped HTTP message: " << completePacketHttp.ToString());
    NS_LOG_FUNCTION(this << "Remains in the buffer " << buffer->GetSize () );
    break;
  }
}

void 
QKDApp004::HandleReadFromApp (Ptr<Socket> socket)
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
  
      NS_LOG_FUNCTION (this << packet 
        << "PACKETID: " << packet->GetUid() 
        << " of size: " << packet->GetSize() 
      ); 

      if (InetSocketAddress::IsMatchingType (from))
      {
          NS_LOG_FUNCTION( this << "At time " << Simulator::Now ().GetSeconds ()
                   << "s packet from APP pair received "
                   <<  packet->GetSize () << " bytes from "
                   << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                   << " port " << InetSocketAddress::ConvertFrom (from).GetPort () << "\n");
      }
  
      DataPacketReceivedFromApp (packet, from, socket); 
  }
}

void
QKDApp004::DataPacketReceivedFromApp (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION ( this << m_master << p->GetUid() << p->GetSize() << from );

  if (m_master == 0) { //Process encrypted data on Replica QKDApp

    if (m_appState == READY) { //Replica QKDApp MUST be in ready state to receive data
      
      QKDAppHeader header;
      Ptr<Packet> buffer;

      auto itBuffer = m_buffer_qkdapp.find (from);
      if (itBuffer == m_buffer_qkdapp.end ())
        {
          itBuffer = m_buffer_qkdapp.insert (std::make_pair (from, Create<Packet> (0))).first;
        }

      buffer = itBuffer->second;
      buffer->AddAtEnd (p);
      buffer->PeekHeader (header);

      NS_ABORT_IF (header.GetLength () == 0);
 
      while (buffer->GetSize () >= header.GetLength ())
        {
          NS_LOG_DEBUG ("Removing packet of size " << header.GetLength () << " from buffer of size " << buffer->GetSize ());
          Ptr<Packet> completePacket = buffer->CreateFragment (0, static_cast<uint32_t> (header.GetLength ()));
          buffer->RemoveAtStart (static_cast<uint32_t> (header.GetLength ()));
 
          m_txTrace (completePacket, m_associations.first.ksid);
          m_txTrace (completePacket, m_associations.second.ksid);

          completePacket->RemoveHeader (header);
          NS_LOG_FUNCTION(this << "RECEIVED QKDAPP HEADER: " << header);

          ProcessDataPacketFromApp(header, completePacket, socket);

          if (buffer->GetSize () > header.GetSerializedSize ())
            { 
              buffer->PeekHeader (header);
            }
          else
            {
              break;
            }
        }
       
    } else {
      NS_LOG_FUNCTION( this << "Primary/Replica:" << m_master << "Invalid state " << GetAppStateString() );
    }
  }

}

void 
QKDApp004::HandleReadSignalingFromApp (Ptr<Socket> socket)
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
  
      NS_LOG_FUNCTION (this << packet 
        << "PACKETID: " << packet->GetUid() 
        << " of size: " << packet->GetSize() 
      ); 

      if (InetSocketAddress::IsMatchingType (from))
      {
          NS_LOG_FUNCTION( this << "At time " << Simulator::Now ().GetSeconds ()
                   << "s signaling packet from APP pair received "
                   <<  packet->GetSize () << " bytes from "
                   << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                   << " port " << InetSocketAddress::ConvertFrom (from).GetPort () << "\n");
      }
  
      SignalingPacketReceivedFromApp (packet, from, socket); 
  }
}

void
QKDApp004::SignalingPacketReceivedFromApp (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION ( this << p->GetUid() << p->GetSize() << from );
  std::string receivedStatus = p->ToString();
  NS_LOG_FUNCTION ( this << "\n\n\n" << p->GetUid() << p->GetSize() << receivedStatus << from );
 
  Ptr<Packet> buffer;
  if (receivedStatus.find("Fragment") != std::string::npos) {
    auto itBuffer = m_buffer_sig.find (from);
    if (itBuffer == m_buffer_sig.end ()){
      itBuffer = m_buffer_sig.insert (
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
      m_rxSigTrace (completePacket);
      ProcessSignalingPacketFromApp(request2, socket); 
    }
    NS_LOG_FUNCTION(this << "Croped HTTP message: " << request2.ToString());
    NS_LOG_FUNCTION(this << "Remains in the buffer " << buffer->GetSize () );
    break;
  }
}

void 
QKDApp004::DataToKMSSend (Ptr<Socket> socket, uint32_t)
{
    NS_LOG_FUNCTION (this << "QKDApp Data to KMS Sent via socket " << socket);
}


/**
 * ********************************************************************************************

 *        KEY BUFFER functions
 
 * ********************************************************************************************
 */

void
QKDApp004::InitializeAssociations ()
{
  NS_LOG_FUNCTION( this );

  m_primaryQueueEstablished = false;
  m_replicaQueueEstablished = false;

  //Association for encryption
  m_associations.first.ksid.clear();
  m_associations.first.verified = false;
  m_associations.first.queueSize = m_keyBufferLengthEncryption;
  m_associations.first.buffer.clear();

  //Association for authentication
  m_associations.second.ksid.clear();
  m_associations.second.verified = false;
  m_associations.second.queueSize = m_keyBufferLengthAuthentication;
  m_associations.second.buffer.clear();

}

void
QKDApp004::CheckAssociationsState ()
{
    NS_LOG_FUNCTION( this << "Checking associations ..." );
    NS_ASSERT(m_master); //Only Primary QKDApp checks associations states
    /*
        Function called after sendksidresponse is recieved.
        Main purpose is to check if associations are established!
        If they are, then switch application state to:
        ASSOCIATIONS_ESTABLISHED and moves on next state in AppTransitionTree
    */
    bool encAssociation = true;
    bool authAssociation = true;
    if(GetEncryptionKeySize() != 0 && !m_associations.first.verified)
        encAssociation = false;
    if(GetAuthenticationKeySize() != 0 && !m_associations.second.verified)
        authAssociation = false;

    if(encAssociation && authAssociation && m_appState == ESTABLISHING_ASSOCIATIONS){
        NS_LOG_FUNCTION( this << "All necessary associations are established" );
        SwitchAppState(ASSOCIATIONS_ESTABLISHED);
        AppTransitionTree();
    }else
        NS_LOG_FUNCTION( this << "Necessary associations are NOT yet established" );

}

void
QKDApp004::CheckQueues ()
{
    NS_LOG_FUNCTION( this << "Checking key queues ... " << m_master );
    bool encQueueReady = false;
    bool authQueueReady = false;
    if(m_associations.first.verified && m_associations.first.buffer.size() < m_associations.first.queueSize)
        GetKeyFromKMS(m_associations.first.ksid);
    else 
        encQueueReady = true;

    if(m_associations.second.verified && m_associations.second.buffer.size() < m_associations.second.queueSize)
        GetKeyFromKMS(m_associations.second.ksid);
    else
        authQueueReady = true;

    if(authQueueReady && encQueueReady){
        if(!m_master){
            NS_LOG_FUNCTION( this << "Replica QKDApp established key queues" );
            SwitchAppState(KEY_QUEUES_ESTABLISHED);
            AppTransitionTree();
        }else if(m_master){
            if(m_replicaQueueEstablished){
                NS_LOG_FUNCTION( this << "Both Primary and Replica QKDApp established queues!" );
                SwitchAppState(KEY_QUEUES_ESTABLISHED);
                AppTransitionTree();
            }else{
                NS_LOG_FUNCTION( this << "Primary QKDApp establihed queues! Waiting on Replica QKDApp ..." );
                m_primaryQueueEstablished = true;
            }
        }
    }

}

QKDApp004::QKDAppKey
QKDApp004::GetEncKey ()
{
    NS_LOG_FUNCTION( this << m_master << "Obtaining encryption key from the local QKDApp buffer ..." << m_associations.first.ksid );
    if(m_master){ //Primary QKDApp obtains encryption key

        NS_LOG_FUNCTION( this << "We have in total " << m_associations.first.buffer.size() << " encryption keys!");
        
        QKDApp004::QKDAppKey output;
        std::map<uint32_t, QKDAppKey>::iterator it = m_associations.first.buffer.begin();
        NS_ASSERT (it != m_associations.first.buffer.end());

        NS_LOG_FUNCTION( this << "The lifetime of the first key is " << (it->second).lifetime );
        
        output = it->second;
        (it->second).lifetime -= m_packetSize; //Decrease key lifetime by packet size!
        NS_LOG_FUNCTION( this << "Remaining lifetime: " << output.lifetime ); 

        uint32_t counter = 0;
        for(std::map<uint32_t, QKDAppKey>::iterator it2 = m_associations.first.buffer.begin(); it2 != m_associations.first.buffer.end();)
        {

          NS_LOG_FUNCTION(this << "Key " << counter++ << " of size " << output.key.size() << " and lifetime " << (it2->second).lifetime );
          if(int32_t ((it2->second).lifetime) <= 0)
          {   
              //Key expires and is deleted!
              NS_LOG_FUNCTION( this << "Local encryption key erased " << it2->first << ". Key lifetime expired!" );
              m_associations.first.buffer.erase(it2++); //Delete expired key
              GetKeyFromKMS(m_associations.first.ksid, 0); //Make new get_key request to obtain the next key!
          }else{
            ++it2;
          }
        }       

        NS_LOG_FUNCTION(this << "Returning key of size " << output.key.size());
        return output; //return encryption key

    }else{ //Replica QKDApp obtains encryption key
        std::map<uint32_t, QKDAppKey>::iterator it = m_associations.first.buffer.find(m_associations.first.keyActive), 
                                                it1 = m_associations.first.buffer.begin();
        
        QKDApp004::QKDAppKey encKey;
        if(it == m_associations.first.buffer.end())
        { 
          //Out of sync!
          //Key is not obtained in time, packet should be stored for delayed processing!
          encKey.key = ""; //return empty key
        }else
          encKey = it->second; //encryption key (keyActive previously read from the QKDApp header)

        std::map<uint32_t, QKDAppKey>::iterator a = m_associations.first.buffer.begin(),
                                                b = m_associations.first.buffer.end();
        while(a != b){
            NS_LOG_FUNCTION( this << "Local encryption key store entry (test - krecS)" << a->first );
            ++a;
        }
        while(it1 != it){ //Remove any key older then keyActive (NOTE: could cause problems with delayed packets!)
            NS_LOG_FUNCTION( this << "Local encryption key erased " << it1->first << ". Synchronization!" );
            m_associations.first.buffer.erase(it1); //Remove first entry - oldest key
            it1 = m_associations.first.buffer.begin();
        }
        return encKey; //return encryption key
    }

}

QKDApp004::QKDAppKey
QKDApp004::GetAuthKey ()
{
    NS_LOG_FUNCTION( this << m_master << "Obtaining authentication key from the local QKDApp buffer ..." << m_associations.second.ksid );
    if(m_master){

        NS_LOG_FUNCTION( this << "We have in total " << m_associations.second.buffer.size() << " authentication keys!");

        std::map<uint32_t, QKDAppKey>::iterator it = m_associations.second.buffer.begin();
        NS_ASSERT (it != m_associations.second.buffer.end());
        
        QKDApp004::QKDAppKey authKey = it->second; //Authentication key is the first key in synchronized local QKDApp buffer
        
        std::map<uint32_t, QKDAppKey>::iterator a = m_associations.second.buffer.begin(),
                                                b = m_associations.second.buffer.end();
        while(a != b){
            NS_LOG_FUNCTION( this << "Local authentication key store entry (test - krecM)" << a->first << a->second.key.size());
            ++a;
        }

        NS_LOG_FUNCTION( this << "Local authentication key erased " << it->first );
        m_associations.second.buffer.erase(it); //Authentication keys do not have lifetime! One use only!
        NS_LOG_FUNCTION( this << "Calling get_key request" );
        GetKeyFromKMS(m_associations.second.ksid, 0); //Make new get_key request to obtain the next key!

        return authKey; //return authentication key

    }else{
        std::map<uint32_t, QKDAppKey>::iterator it = m_associations.second.buffer.find(m_associations.second.keyActive), 
                                                it1 = m_associations.second.buffer.begin();
        QKDApp004::QKDAppKey authKey;
        if(it == m_associations.second.buffer.end()){ //Out of sync!
                                                      //Key is not obtained in time, packet should be stored for delayed processing!
            authKey.key = ""; //return empty key
        }else
            authKey = it->second; //authentication key (keyActive previously read from the QKDApp header)
        while(it1 != it){ //Remove any key older then keyActive (NOTE: could cause problems with delayed packets!)
            NS_LOG_FUNCTION( this << "Local authentication key erased " << it1->first );
            m_associations.second.buffer.erase(it1);
            it1 = m_associations.second.buffer.begin();
        }
        return authKey; //return authentication key
    }

}



/**
 * ********************************************************************************************

 *        HTTP handling to APP
 
 * ********************************************************************************************
 */
void
QKDApp004::Http004AppQuery (uint32_t methodType, std::string ksid)
{
  NS_LOG_FUNCTION(this << methodType << ksid);
  m_httpRequestsApp.push_back (std::make_pair (methodType, ksid));
}

void
QKDApp004::Http004AppQueryComplete ()
{
  if(m_httpRequestsApp.size() > 0)
    m_httpRequestsApp.erase (m_httpRequestsApp.begin());
}

uint32_t
QKDApp004::GetMethodFromHttp004AppQuery ()
{
  NS_LOG_FUNCTION( this );
  return (m_httpRequestsApp[0]).first;
}

std::string
QKDApp004::GetKsidFromHttp004AppQuery ()
{
  NS_LOG_FUNCTION( this );
  return (m_httpRequestsApp[0]).second;
}



/**
 * ********************************************************************************************

 *        HTTP handling to KMS
 
 * ********************************************************************************************
 */
void
QKDApp004::Http004KMSQuery (std::string uri, std::string ksid, uint32_t keyType)
{
  NS_LOG_FUNCTION(this << uri << ksid << keyType );

  m_httpRequestsKMS.insert(
    std::make_pair(
      uri,
      std::make_pair(ksid, keyType)
    )
  );
}

void
QKDApp004::Http004KMSQueryComplete (std::string uri)
{
  NS_LOG_FUNCTION(this << uri << m_httpRequestsKMS.size());

  std::map<std::string, std::pair<std::string, uint32_t> >::iterator it = m_httpRequestsKMS.find(uri);
  if ( it != m_httpRequestsKMS.end () ){
    m_httpRequestsKMS.erase(it);
  }
}

uint32_t
QKDApp004::GetMethodFromHttp004KMSQuery (std::string uri)
{
  NS_LOG_FUNCTION( this << uri );
  //OPEN_CONNECT 0, GET_KEY 1, CLOSE 2

  size_t pos = 0;
  std::string delimiter = "/";
  std::string token;
  std::vector<std::string> uriParams;
  while ((pos = uri.find(delimiter)) != std::string::npos) {
    token = uri.substr(0, pos);
    if(token.length() > 0){
      uriParams.push_back(token);
    }
    uri.erase(0, pos + delimiter.length());
  }
  if(uri.length() > 0){
    uriParams.push_back(uri);
  }
  for(uint32_t i=0; i< uriParams.size(); i++){
    if(uriParams[i] == "open_connect"){
      return 0;
    }else if(uriParams[i] == "get_key"){
      return 1;
    }else if(uriParams[i] == "close"){
      return 2;
    }
  }  
  NS_FATAL_ERROR( "METHOD NOT FOUND " << uri );
  return 0;
}

std::string
QKDApp004::GetKsidFromHttp004KMSQuery (std::string uri)
{ 
  NS_LOG_FUNCTION( this << uri << m_httpRequestsKMS.size() );
 
  //FETCH KSID FROM CACHE
  uri = "http://" + uri;
  std::map<std::string, std::pair<std::string, uint32_t> >::iterator it = m_httpRequestsKMS.find(uri);
  if ( it != m_httpRequestsKMS.end () ){
    return it->second.first;
  }

  //FETCH KSID FROM THE URI
  size_t pos = 0;
  std::string delimiter = "/";
  std::string token;
  std::vector<std::string> uriParams;
  while ((pos = uri.find(delimiter)) != std::string::npos) {
    token = uri.substr(0, pos);
    if(token.length() > 0){
      uriParams.push_back(token);
    }
    uri.erase(0, pos + delimiter.length());
  }
  if(uri.length() > 0){
    uriParams.push_back(uri);
  }
  for(uint32_t i=0; i< uriParams.size(); i++){
    NS_LOG_FUNCTION(this << i << uriParams[i]);
    if(uriParams[i] == "open_connect" || uriParams[i] == "get_key" || uriParams[i] == "close"){
      return uriParams[i-1];
    }
  } 
 
  NS_FATAL_ERROR( "KSID NOT FOUND " << uri );
  return "";
}

uint32_t
QKDApp004::GetKeyTypeFromHttp004KMSQuery (std::string uri)
{
  NS_LOG_FUNCTION( this << uri );
  uri = "http://" + uri;

  std::map<std::string, std::pair<std::string, uint32_t> >::iterator it = m_httpRequestsKMS.find(uri);
  if ( it != m_httpRequestsKMS.end () ){
    return it->second.second;
  }

  NS_FATAL_ERROR( "KEY TYPE NOT FOUND " << uri );
  return 0;
}


 /**
 * ********************************************************************************************
 *        MALICIOUS functions
 * ********************************************************************************************
 */
void 
QKDApp004::SendMaliciousRequestToKMS ()
{
  NS_LOG_FUNCTION (this);

  //Check whether the socket to KMS is active and connected
  Address temp; 
  if(!m_sendSocketToKMS || m_sendSocketToKMS->GetPeerName (temp) != 0){
    PrepareSendSocketToKMS();
  }
  
  if(m_appState != READY)
    return; //Simple malicious application is stopped, abort!

  std::string message;

  if(1 || !m_maliciousPacket){ //Create malicious packet for the first time

    std::string maliciousKsid = UUID::Sequential().string();

    if(GetAppState() == QKDApp004::STOPPED) return;
    if(!m_sinkSocketFromKMS) PrepareSinkSocketFromKMS();
    
    Ipv4Address lkmsAddress = InetSocketAddress::ConvertFrom(m_kms).GetIpv4 ();
    std::ostringstream lkmsAddressTemp; 
    lkmsAddress.Print(lkmsAddressTemp); //IPv4Address to string
    std::string headerUri = "http://" + lkmsAddressTemp.str();
    //headerUri += "/api/v1/keys/" + maliciousKsid + "/get_key";
    headerUri += "/api/v1/keys/" + m_dstSaeId.string() + "/open_connect/1";
    NS_LOG_FUNCTION(this << "maliciousKsid: " << headerUri );

    nlohmann::json msgBody; //No metadata
    //msgBody["Key_stream_ID"] = maliciousKsid;
    msgBody["Source"] = m_id.string();
    msgBody["Destination"] = m_dstSaeId.string();
    msgBody["QoS"] = {
      {"priority", 0},
      {"max_bps", 50000},
      {"min_bps", 100}, 
      {"jitter", 100}, 
      {"timeout", 100}, 
      {"key_chunk_size", 100},
      {"TTL", 10}
    };

    message = msgBody.dump();

    //Create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateRequest(headerUri, "POST", message);
    std::string hMessage = httpMessage.ToString(); 
    m_maliciousPacket = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    );

    NS_ASSERT (m_maliciousPacket);
  } 

  //Send malicious packet to KMS
  NS_LOG_FUNCTION (this << "Sending malicious PACKETID: " << m_maliciousPacket->GetUid() 
    << " of size: " << m_maliciousPacket->GetSize()
    << " with payload: " << message
    << " via socket " << m_sendSocketToKMS 
  );
  m_txKmsTrace (m_maliciousPacket);
  m_sendSocketToKMS->Send(m_maliciousPacket); 

  //Schedule next malicious request to KMS
  Simulator::Schedule (m_dosAttackIntensity, &QKDApp004::SendMaliciousRequestToKMS, this);

}

/**
 * ********************************************************************************************
 *        APPLICATION functions
 * ********************************************************************************************
 */
void
QKDApp004::StartApplication (void)
{
  
    NS_LOG_FUNCTION( this << m_local << m_peer << m_master );
    m_packetsSent = 0;
    
    if(m_malicious && m_master){ //Does not need to validate config. parameters
      m_maliciousPacket = NULL;
      SwitchAppState(READY);
      SendMaliciousRequestToKMS();
      return; //do not proceed with the function
    }

    if(m_encryptionTypeInt < 0 || m_encryptionTypeInt > 2){
        NS_FATAL_ERROR( "Invalid encryption type " << m_encryptionTypeInt 
            << ". Allowed values are (0-unencrypted, 1-OTP, 2-AES)" );
    }
    if(m_authenticationTypeInt < 0 || m_authenticationTypeInt > 3){
        NS_FATAL_ERROR( "Invalid authentication type " << m_authenticationTypeInt 
            << ". Allowed values are (0-unauthenticated, 1-VMAC, 2-MD5, 3-SHA1)" );
    }
    if(m_aesLifetime < 0){
        NS_FATAL_ERROR( "Invalid AES lifetime " << m_aesLifetime 
            << ". The value must be larger than zero." );
    } else if(m_aesLifetime != 0 && m_aesLifetime < m_packetSize)
        NS_FATAL_ERROR( "Invalid AES lifetime " << m_aesLifetime 
            << ". The value must be larger than one packet size " << m_packetSize );

    if(m_encryptionTypeInt == 1)
        m_aesLifetime = m_packetSize; //For when OTP is applied

    if(m_appState == INITIALIZED){ 
        SetEncryptionAndAuthenticationSettings(
          m_encryptionTypeInt, 
          m_authenticationTypeInt,
          m_authenticationTagLengthInBits
        );
        AppTransitionTree(); //Transition states
        PrepareSinkSocketFromApp(); //Create sink sockets for peer QKD applications

    }else
      NS_FATAL_ERROR( "Invalid state " << GetAppStateString () 
          << " for StartApplication()." );

}

void
QKDApp004::StopApplication (void)
{
    //@toDo:  As any other responsible application, on stopping, application will call CLOSE
    //        Application will wait for response (but it is optional) and then close sockets!
    NS_LOG_FUNCTION( this << "Stopping QKDApp ... " );
    if(m_sendEvent.IsRunning())
        Simulator::Cancel(m_sendEvent);
    
    if(m_master){ //Only Primary QKDApp calls CLOSE, as it is one responsible for the associations!
        NS_LOG_FUNCTION( this << "Closing assocaitions ... ");
        if(!m_associations.first.ksid.empty()) //Encrpytion association active
            Close(m_associations.first.ksid);

        if(!m_associations.second.ksid.empty()) //Authentication association active
            Close(m_associations.second.ksid);

    }else{ //Replica QKDApp closes sockets to the KMS also
        if(m_sendSocketToKMS) 
            m_sendSocketToKMS->Close();
        if(m_sendSocketToKMS) 
            m_sinkSocketFromKMS->Close();
    }
    //Closing send and sink sockets for QKDApp communication!
    if(m_sendDataSocketApp)
        m_sendDataSocketApp->Close();
    if(m_sinkDataSocketApp)
        m_sinkDataSocketApp->Close();
    if(m_sendSignalingSocketApp)
        m_sendSignalingSocketApp->Close();
    if(m_sinkSignalingSocketApp)
        m_sinkSignalingSocketApp->Close();
    
    SwitchAppState(STOPPED);
    InitializeAssociations(); //Clear associations records
    NS_LOG_FUNCTION( this << "Data and signaling sockets are closed. Data transmission is stopped ..." );
}

void
QKDApp004::SendPacket ()
{
  NS_LOG_FUNCTION( this );
  NS_ASSERT(m_master);

  if (m_appState == READY) //Direct call from SceduleTx()
    SwitchAppState(SEND_DATA);

  NS_LOG_FUNCTION(this << "testkrec" << m_appState);
  if (m_appState == SEND_DATA) {

    if(!m_sendDataSocketApp) {
      PrepareSendSocketToApp(); 
    }

    //Obtain secret keys!
    QKDApp004::QKDAppKey encKey;
    encKey.index = 0;
    QKDApp004::QKDAppKey authKey;
    authKey.index = 0;

    //Obtain encryption key!
    if (GetEncryptionKeySize() != 0){
      encKey = GetEncKey();
      if(encKey.key == ""){
        SwitchAppState(READY);
        return;
      }
    }
      
    //Obtain authentication key from application key buffer!
    if (GetAuthenticationKeySize() != 0){
      authKey = GetAuthKey();
      if(authKey.key == ""){
        SwitchAppState(READY);
        return;
      }
    }


    //Keys are not Base64 coded!
    NS_LOG_FUNCTION(this << "\nEncryption Key (krec)" << encKey.key << "\nAuthentication Key (krec)" << authKey.key);

    //Define confidential message
    std::string confidentialMsg = GetPacketContent();
    NS_LOG_FUNCTION( this << "Confidential message" << confidentialMsg.size() << confidentialMsg );
    
    std::string encryptedMsg;
    std::string authTag;
    if (m_useCrypto) {
      
      encryptedMsg = m_encryptor->EncryptMsg(confidentialMsg, encKey.key);
      NS_LOG_FUNCTION ( this << "Encryption key" << encKey.index << encKey.key 
        << "Encrypted message" << m_encryptor->Base64Encode(encryptedMsg));
      if(GetAuthenticationKeySize() != 0)
          authTag = m_encryptor->Authenticate (encryptedMsg, authKey.key);
      else
          authTag = GetPacketContent(32);
      NS_LOG_FUNCTION( this << "Authentication key" << authKey.index << authKey.key 
        << "Authentication tag" << authTag );

    } else {

      encryptedMsg = confidentialMsg;
      authTag = GetPacketContent(32); //Use random authTag
      NS_LOG_FUNCTION ( this << "Encryption key" << encKey.index << encKey.key );
      NS_LOG_FUNCTION( this << "Authentication key" << authKey.index << authKey.key );
      NS_LOG_FUNCTION( this << "Authentication Tag" << authTag);

    }
    
    //Create packet with protected/unprotected data
    std::string msg = encryptedMsg;
    Ptr<Packet> packet = Create<Packet> ( (uint8_t*) msg.c_str(), msg.length() );
    NS_ASSERT (packet);
    m_authenticationTrace (packet, authTag);

    //Add qkd header!
    QKDAppHeader qHeader;
    qHeader.SetEncrypted(m_encryptionType); 
    qHeader.SetEncryptionKeyId(std::to_string(encKey.index));
    qHeader.SetAuthenticated(m_authenticationType);
    qHeader.SetAuthenticationKeyId(std::to_string(authKey.index));
    qHeader.SetAuthTag(authTag);
    qHeader.SetLength(packet->GetSize() + qHeader.GetSerializedSize());
    packet->AddHeader(qHeader);

    //Send packet!
    m_txTrace (packet, m_associations.first.ksid);
    m_txTrace (packet, m_associations.second.ksid);
    m_sendDataSocketApp->Send (packet);
    m_packetsSent++;
    m_dataSent += packet->GetSize();

    NS_LOG_FUNCTION (this << "Sending protected packet: " << packet->GetUid() << " of size " << packet->GetSize() );
    
    SwitchAppState(READY); //Application should go in ready or wait! If buffer is empty go to WAIT.
                      //When a number of keys are obtained again, go to READY state.
    ScheduleTx (); //Schedule new time instance to send data!

  } else if (m_appState == WAIT) {

    //m_txTrace (0, m_associations.first.ksid);
    //m_txTrace (0, m_associations.second.ksid);

    ScheduleTx ();
    NS_LOG_FUNCTION( this << "Application is currently unable to send new data! QKDApp state" << GetAppStateString(m_appState) );
  
  } else {

    NS_FATAL_ERROR( this << "Application is in invalid state!" );

  }

}

void 
QKDApp004::ProcessDataPacketFromApp (QKDAppHeader header, Ptr<Packet> packet, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << "Processing data packet from peer QKDApp" );
    if(!m_master){ //Only Replica QKDApp receives encrypted data!
        std::string payload = PacketToString(packet); //Read the packet data
        NS_LOG_FUNCTION( this << "Received data packet" << m_encryptor->Base64Encode(payload) );
        
        SwitchAppState(DECRYPT_DATA);
        SetEncryptionAndAuthenticationSettings(header.GetEncrypted(), header.GetAuthenticated(), m_authenticationTagLengthInBits); 
        std::string decryptedMsg;
        bool authSuccessful = false;
        
        NS_LOG_FUNCTION( this << "Executing authentication check on received packet!" );
        if(GetAuthenticationKeySize() != 0){ //Authentication requires QKD key
            NS_LOG_FUNCTION(this << "VMAC authentciation" );
            if(uint32_t (std::stoi(header.GetAuthenticationKeyId())) > m_associations.second.keyActive){
                m_associations.second.keyActive = std::stoi(header.GetAuthenticationKeyId()); //new keyActive read from QKDApp header
                NS_LOG_FUNCTION( this << "Synchronization - calling get_key request" );
                GetKeyFromKMS(m_associations.second.ksid, 0); //Calling get_key request
            }

            QKDApp004::QKDAppKey authKey = GetAuthKey(); //Obtain authentication key
            if(authKey.key == ""){ //Packet received out of sync (dealyed packet). Packet is dropped!
                NS_LOG_FUNCTION( this << "Authentication key not available" << m_associations.second.keyActive << "Packet is dropped!" );
                SwitchAppState(READY);
                return;
            }

            NS_LOG_FUNCTION( this << "Authentication key obtained from the local key store" << authKey.index << authKey.key );
            if(m_useCrypto){ //Perform actual authentication check
                //Check authTag 
                if(m_encryptor->CheckAuthentication(payload, header.GetAuthTag(), authKey.key)) //Check AuthTag
                    authSuccessful = true;

            }else //We assume packet is successfully authenticated
                authSuccessful = true;     

        }else if(header.GetAuthenticated()){ //Authentication does not require quantum key
            if (m_useCrypto){
                if(m_encryptor->CheckAuthentication(payload, header.GetAuthTag(), ""))
                    authSuccessful = true;

            }else //We assume packet is successfully authenticated
                authSuccessful = true;

        }else //No authentication services
            authSuccessful = true;

        if(authSuccessful)
            NS_LOG_FUNCTION( this << "Packet is successfully authenticated! Processing ... " );
        else
            NS_LOG_FUNCTION( this << "Authentication of received packet FAILED. Packet is dropped!" );

        //Perform decryption
        if (header.GetEncrypted()){
            NS_LOG_FUNCTION(this << "Decrypting received packet ... ");
            if(uint32_t (std::stoi(header.GetEncryptionKeyId())) > m_associations.first.keyActive){
                m_associations.first.keyActive = std::stoi(header.GetEncryptionKeyId()); //new keyActive index
                NS_LOG_FUNCTION( this << "Synchronization - calling get_key request" );
                GetKeyFromKMS(m_associations.first.ksid, 0); //Calling get_key request
            }

            QKDApp004::QKDAppKey encKey = GetEncKey(); //Obtain encryption key
            if(encKey.key == ""){ //Out of sync (delayed packet)! Packet is dropped!
                NS_LOG_FUNCTION( this << "Encyption key not available" << m_associations.first.keyActive << "Packet is dropped!" );
                SwitchAppState(READY);
                return;
            }

            NS_LOG_FUNCTION( this << "Encryption key obained from the local key store " << encKey.index << encKey.key );
            if(m_useCrypto){
                if(authSuccessful){ //Packet is decrypted only when it is succesfully  authenticated
                    decryptedMsg = m_encryptor->DecryptMsg (payload, encKey.key);
                    NS_LOG_FUNCTION( this << "Packet decrypted! Decrypted message: \n" << decryptedMsg );
                }
            }else{ //Fake decryption process
                if(authSuccessful)
                    NS_LOG_FUNCTION( this << "Packet decrypted!" );
            }

        }else //Receiving unprotected packet
            NS_LOG_FUNCTION( this << "Packet received unprotected! Received message: \n" << payload );

        SwitchAppState(READY);

    }else
        NS_FATAL_ERROR( this << "Only Replica QKDApp receives protected packets! Only unidirectional secure data communication!" );

}


void 
QKDApp004::ProcessResponseFromKMS(HTTPMessage& header, Ptr<Packet> packet, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION (this << "Processing response from KMS" << packet->GetUid() << packet->GetSize());

    std::string requestUri = header.GetRequestUri();
    NS_LOG_FUNCTION(this << requestUri);

    uint32_t etsiFunction = GetMethodFromHttp004KMSQuery(requestUri); //Map response to request
    //OPEN_CONNECT 0, GET_KEY 1, CLOSE 2

    if(etsiFunction == 0 && m_appState != STOPPED)
    { //Response on OPEN_CONNECT
      ProcessOpenConnectResponse(header);
    }else if(etsiFunction == 1 && m_appState != STOPPED){ //Response on GET_KEY
      ProcessGetKeyResponse(header);
    }else if(etsiFunction == 2 && m_appState != STOPPED){ //Response on CLOSE
      ProcessCloseResponse(header);
    }else
      NS_FATAL_ERROR (this << "Invalid ETSI QKD GS 004 function used in request");
    
    Http004KMSQueryComplete( requestUri ); //Remove request from http query
}


/**
 * ********************************************************************************************

 *        KEY MANAGEMENT functions
 
 * ********************************************************************************************
 */

void
QKDApp004::OpenConnect (std::string ksid, uint32_t keyType)
{
    if(!m_master && m_associations.second.ksid == ksid){
        keyType = 1;
    }

    NS_LOG_FUNCTION( this << "OPEN_CONNECT(master, ksid, keyType)" << 
                              m_master << ksid << keyType);
    NS_ASSERT(keyType >= 0);
    NS_ASSERT(keyType < 3);

    if(!m_sinkSocketFromKMS) {
      PrepareSinkSocketFromKMS();
    }
 
    uint64_t maxRate = GetMaxEncryptionKeyRate() + GetMaxAuthenticationKeyRate(); 
    uint64_t minRate = m_minDataRate.GetBitRate();

    NS_LOG_FUNCTION(this << maxRate << minRate);

    uint32_t keySize {0};
    if(!keyType) { //0 - encrption key
      keySize = GetEncryptionKeySize();
    }else{ //1 - authentication key
      keySize = GetAuthenticationKeySize();
    }

    if(m_master) NS_ASSERT(keySize != 0);

    NS_ASSERT(m_priority < 2);

    nlohmann::json msgBody;
    msgBody["Source"] = m_id.string();
    msgBody["Destination"] = m_dstSaeId.string();
    msgBody["QoS"] = { 
      {"priority", m_priority},
      {"max_bps", maxRate},
      {"min_bps", minRate}, 
      {"jitter", 100}, 
      {"timeout", 100}, 
      {"key_chunk_size", keySize},
      {"TTL", m_ttl}
    };

    if(!m_master){
      msgBody["Key_stream_ID"] = ksid;
    }else{
      msgBody["QoS"]["key_chunk_size"] = keySize; 
    }

    std::string message = msgBody.dump();

    Ipv4Address lkmsAddress = InetSocketAddress::ConvertFrom(m_kms).GetIpv4();
    std::ostringstream lkmsAddressTemp; 
    lkmsAddress.Print(lkmsAddressTemp); //IPv4Address to string
    std::string headerUri = "http://" + lkmsAddressTemp.str();
    headerUri += "/api/v1/keys/" + m_dstSaeId.string() + "/open_connect/" + std::to_string(keyType);
    
    //Create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateRequest(headerUri, "POST", message);
    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packet = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    ); 
    NS_ASSERT (packet);

    NS_LOG_FUNCTION (this << "Sending PACKETID: " << packet->GetUid() 
        << " of size: " << packet->GetSize() 
        << " via socket " << m_sendSocketToKMS 
    );
    //check whether the socket to KMS is active and connected
    Address temp; 
    if(!m_sendSocketToKMS || m_sendSocketToKMS->GetPeerName(temp) != 0){
        PrepareSendSocketToKMS();
        QKDApp004::KMSPacket kmsPacket;
        kmsPacket.packet = packet;
        kmsPacket.methodType = 0;
        kmsPacket.uri = headerUri;
        if(m_master){
            kmsPacket.keyType = keyType;
            kmsPacket.ksid = "";
        }else{
            kmsPacket.keyType = 0;
            kmsPacket.ksid = ksid;
        }  
        m_queue_kms.push_back(kmsPacket);

    }else{
        Http004KMSQuery(headerUri, ksid, keyType ); //OPEN_CONNECT 0, GET_KEY 1, CLOSE 2; encKey 0, authKey 1)
        
        m_txKmsTrace(packet);
        m_sendSocketToKMS->Send(packet);
    }
}

void
QKDApp004::GetKeyFromKMS (std::string ksid, uint32_t index)
{
    NS_LOG_FUNCTION( this << "GET_KEY (master,ksid,index)" << m_master << ksid << index );
    
    if(GetAppState() == QKDApp004::STOPPED) return;
    if(!m_sinkSocketFromKMS) PrepareSinkSocketFromKMS();
   
    Ipv4Address lkmsAddress = InetSocketAddress::ConvertFrom(m_kms).GetIpv4 ();
    std::ostringstream lkmsAddressTemp; 
    lkmsAddress.Print(lkmsAddressTemp); //IPv4Address to string
    std::string headerUri = "http://" + lkmsAddressTemp.str();
    headerUri += "/api/v1/keys/" + ksid + "/get_key/fresh/" + std::to_string(m_random->GetValue (0,1000000));

    nlohmann::json msgBody; //No metadata
    msgBody["Key_stream_ID"] = ksid;
    std::string message = msgBody.dump();

    //Create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateRequest(headerUri, "POST", message);
    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packet = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    ); 
    NS_ASSERT (packet);

    NS_LOG_FUNCTION (this << "Sending PACKETID: " << packet->GetUid() 
      << " of size: " << packet->GetSize()
      << " via socket " << m_sendSocketToKMS 
    );

    //Check whether the socket to KMS is active and connected
    Address temp; 
    if(!m_sendSocketToKMS || m_sendSocketToKMS->GetPeerName (temp) != 0){
        PrepareSendSocketToKMS();
        QKDApp004::KMSPacket kmsPacket;
        kmsPacket.packet = packet;
        kmsPacket.methodType = 1;
        kmsPacket.keyType = 0;
        kmsPacket.ksid = ksid;
        kmsPacket.uri = headerUri;
        m_queue_kms.push_back(kmsPacket);
    }else{
        Http004KMSQuery(headerUri, ksid, 0); //(etsi 004 function: OPEN_CONNECT 0, GET_KEY 1, CLOSE 2; KSID)
        m_txKmsTrace (packet);
        m_sendSocketToKMS->Send(packet);
    }
}

void
QKDApp004::Close (std::string ksid)
{
    NS_LOG_FUNCTION( this << "Closing key stream association" << m_master << ksid );
    if(!m_sinkSocketFromKMS) PrepareSinkSocketFromKMS();

    //Empty queues assigned to this association and association registry
    if(m_associations.first.ksid == ksid){//close encryption association
        //InitializeAssociation(ksid);
        NS_LOG_FUNCTION( this << "Encryption key stream association closed on QKDApp side!");
    }else if(m_associations.second.ksid == ksid){
        //InitializeAssociation(ksid);
        NS_LOG_FUNCTION( this << "Authentication key stream association closed on QKDApp side!");
    }else
        NS_FATAL_ERROR( this << "Closing association failed. Ksid not registered" << ksid );

    //Send CLOSE message to the local KMS
    Ipv4Address lkmsAddress = InetSocketAddress::ConvertFrom(m_kms).GetIpv4 ();
    std::ostringstream lkmsAddressTemp; 
    lkmsAddress.Print(lkmsAddressTemp); //IPv4Address to string
    std::string headerUri = "http://" + lkmsAddressTemp.str ();
    headerUri += "/api/v1/keys/" + ksid + "/close";
 
    //Create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateRequest(headerUri, "GET");
    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packet = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    ); 
    NS_ASSERT (packet);
    
    NS_LOG_FUNCTION (this << "Sending PACKETID: " << packet->GetUid() 
      << " of size: " << packet->GetSize()
      << " via socket " << m_sendSocketToKMS 
    );

    //check whether the socket to KMS is active and connected
    Address temp; 
    if(!m_sendSocketToKMS || m_sendSocketToKMS->GetPeerName (temp) != 0){
      PrepareSendSocketToKMS();
      QKDApp004::KMSPacket kmsPacket;
      kmsPacket.packet = packet;
      kmsPacket.methodType = 2;
      kmsPacket.keyType = 0;
      kmsPacket.ksid = ksid;
      kmsPacket.uri = headerUri;
      m_queue_kms.push_back(kmsPacket);
    }else{
      //Store request to HTTP requests store (to be able to map responses)
      Http004KMSQuery(headerUri, ksid, 2); //(etsi gs 004 function: OPEN_CONNECT 0, GET_KEY 1, CLOSE 2; KSID)
      m_txKmsTrace (packet);
      m_sendSocketToKMS->Send (packet);
    }

}

void
QKDApp004::ProcessOpenConnectResponse (HTTPMessage& header)
{
    NS_LOG_FUNCTION( this << "Processing OPEN_CONNECT response!" << m_master  );    

    if(!m_sinkSocketFromKMS) PrepareSinkSocketFromKMS();

    std::string payload = header.GetMessageBodyString(); //Read HTTP body message
    nlohmann::json jOpenConnect; //Read JSON data structure from message
    if(!payload.empty()){
        try{
           jOpenConnect = nlohmann::json::parse(payload);
        }catch(...){
          NS_FATAL_ERROR( this << "JSON parse error!");
        }
    }

    NS_LOG_FUNCTION(this << payload);

    std::string requestUri = header.GetRequestUri();
    HTTPMessage::HttpStatus responseStatus = header.GetStatus();
    if(
        responseStatus == HTTPMessage::HttpStatus::BadRequest || 
        responseStatus == HTTPMessage::HttpStatus::Unauthorized || 
        responseStatus == HTTPMessage::HttpStatus::ServiceUnavailable
    ){ //Process status field of response (ETSI004 defined: 1, 4, 5, 7)
        
        if(m_master){
          
          std::string ksid = GetKsidFromHttp004KMSQuery(requestUri);
          uint32_t keyType = GetKeyTypeFromHttp004KMSQuery(requestUri);

          Time t {"5s"};
          EventId event = Simulator::Schedule (t, &QKDApp004::OpenConnect, this, ksid, keyType);
          //@toDoFuture If (QoS is rejected){repeat request in few sec (stage-1)}else{report fatal_error}
          //uint32_t status004 = jOpenConnect["status"]; //Read status code for OPEN_CONNECT
          NS_LOG_FUNCTION( this << "QKDApp received ERROR on OPEN_CONNECT." );

        }else{ 
            std::string ksid = GetKsidFromHttp004KMSQuery(requestUri);
            ClearAssociation(ksid); //Clear key stream association
            SendKsidResponse(HTTPMessage::HttpStatus::ServiceUnavailable); //Send response on /connect indicating error!
        }

    }else if(responseStatus == HTTPMessage::HttpStatus::Ok){ //For ETSI004 status 0 
        NS_LOG_FUNCTION( this << "Successful OPEN_CONNECT" );
        if(m_master){ //Primary QKDApp on OPEN_CONNECT response

            std::string ksid;
            if(jOpenConnect.contains("Key_stream_ID")) ksid = jOpenConnect["Key_stream_ID"];
            NS_ASSERT(!ksid.empty());

            uint32_t keyType = GetKeyTypeFromHttp004KMSQuery(requestUri);
            if(keyType == 0){
                NS_LOG_FUNCTION( this << "KSID " << ksid << " registered for encryption" );
                m_associations.first.ksid = ksid; //Register encryption ksid
            }else{
                NS_LOG_FUNCTION( this << "KSID " << ksid << " registered for authentication" );
                m_associations.second.ksid = ksid; //Register authentication ksid
            }
            SendKsidRequest(ksid, keyType); //Connect to peer QKDApp by sending ksid

        }else{ //Replica QKDApp on OPEN_CONNECT response

            std::string ksid = GetKsidFromHttp004KMSQuery(requestUri);
            if (m_associations.first.ksid == ksid)
                m_associations.first.verified = true; //Association is verified if it's established by both QKDApp!
            else if (m_associations.second.ksid == ksid)
                m_associations.second.verified = true; //Association is verified if it's established by both QKDApp!
            else{
              NS_FATAL_ERROR( this 
                << "Unknown ksid: " << ksid << "\t" 
                << m_associations.first.ksid << "\t"  
                << m_associations.second.ksid  
              );
            }
            SendKsidResponse(HTTPMessage::HttpStatus::Ok); //Send response on /connect indicating success!
        }

    }else
        NS_FATAL_ERROR( this << "Unsupported error status code" << responseStatus << "of response.");

}

void
QKDApp004::ProcessGetKeyResponse (HTTPMessage& header)
{
    NS_LOG_FUNCTION( this );
    std::string payload = header.GetMessageBodyString();
    std::string requestUri = header.GetRequestUri();
    std::string ksid = GetKsidFromHttp004KMSQuery(requestUri);

    nlohmann::json jGetKeyResponse;
    if(!payload.empty()){
        try{
            jGetKeyResponse = nlohmann::json::parse(payload);
        }catch (...){
            NS_FATAL_ERROR( this << "JSON parse error!");
        }
    }

    HTTPMessage::HttpStatus responseStatus = header.GetStatus();
    if(
      responseStatus == HTTPMessage::HttpStatus::BadRequest || 
      responseStatus == HTTPMessage::HttpStatus::Unauthorized || 
      responseStatus == HTTPMessage::HttpStatus::ServiceUnavailable
    ){
        //Process status field of response (ETSI004 defined: 2, 3, 8) @toDo
        //uint32_t status004 = jGetKeyResponse["status"];
        NS_LOG_FUNCTION( this << "QKDApp received ERROR on GET_KEY" );
        if(m_appState == ESTABLISHING_KEY_QUEUES){
            Time t {"300ms"};
            EventId event = Simulator::Schedule (t, &QKDApp004::GetKeyFromKMS, this, ksid, 0);
        }else if(m_master){
            Time t {"500ms"};
            EventId event = Simulator::Schedule (t, &QKDApp004::GetKeyFromKMS, this, ksid, 0);
        }else if(!m_master){
            NS_LOG_FUNCTION(this << "Association has been closed ...");
        }
    
    }else if(responseStatus == HTTPMessage::HttpStatus::Ok){ //For ETSI004 status 0    
        uint32_t index = -1;
        std::string key;
        if (jGetKeyResponse.contains("index"))
            index = jGetKeyResponse["index"];
        if (jGetKeyResponse.contains("Key_buffer"))
            key = jGetKeyResponse["Key_buffer"];
        NS_ASSERT(index >= 0);
        NS_ASSERT(!key.empty());
        
        m_obtainedKeyMaterialTrace (key.size()*8);

        NS_LOG_FUNCTION( this << "Key obtained (master,ksid,index,key)" << m_master << ksid << index << key);
        QKDAppKey appKey;
        appKey.key = key;
        appKey.index = index;
        appKey.lifetime = m_aesLifetime;
        
        if(m_associations.first.ksid == ksid)
            m_associations.first.buffer.insert( std::make_pair(index, appKey) );
        else if(m_associations.second.ksid == ksid)
            m_associations.second.buffer.insert( std::make_pair(index, appKey) );
        else
            NS_FATAL_ERROR( this << "Association with ksid" << ksid << "does not exist on QKDApp" );

        if(m_appState == ESTABLISHING_KEY_QUEUES)
            CheckQueues();
        else if(m_appState == WAIT){ //If Auth key and Enc key are ready then go to READY state!
            bool ready = true;
            if(GetEncryptionKeySize() != 0 && m_associations.first.buffer.empty())
                ready = false;
            if(GetAuthenticationKeySize() != 0 && m_associations.second.buffer.empty())
                ready = false;
            if(ready)
                SwitchAppState(READY);
        }
    
    }else{
        NS_FATAL_ERROR( this << "Unsupported status code" << responseStatus << " of the response.");
    }
}

void
QKDApp004::ProcessCloseResponse (HTTPMessage& header)
{
    NS_LOG_FUNCTION( this << "Processing response on CLOSE method ..." );

    std::string requestUri = header.GetRequestUri();
    std::string ksid = GetKsidFromHttp004KMSQuery(requestUri);

    if(m_httpRequestsKMS.empty()){ //Sockets are closed when both CLOSE responses are received!
        if(m_sendSocketToKMS) m_sendSocketToKMS->Close();
        if(m_sinkSocketFromKMS) m_sinkSocketFromKMS->Close();
    }

    //Application does not really need to process CLOSE response!
    HTTPMessage::HttpStatus responseStatus = header.GetStatus();
    if(
      responseStatus == HTTPMessage::HttpStatus::BadRequest || 
      responseStatus == HTTPMessage::HttpStatus::Unauthorized || 
      responseStatus == HTTPMessage::HttpStatus::ServiceUnavailable
    ){
        NS_LOG_FUNCTION( this << "QKDApp received error message on CLOSE method" );
        InitializeAssociations();

    }else if(responseStatus == HTTPMessage::HttpStatus::Ok){
        NS_LOG_FUNCTION( this << "Application successfully closed association " << ksid );
        InitializeAssociations(); //Associations are initialized once again!

    }else{
        NS_FATAL_ERROR( this << "Unsupported error status code" << responseStatus << "of response.");
    }

}

void
QKDApp004::ProcessSignalingPacketFromApp (HTTPMessage& header, Ptr<Socket> socket)
{
    NS_LOG_FUNCTION( this << "Processing singnaling packet received from peer QKDApp" );
    
    std::string payload = header.GetMessageBodyString();

    if(m_master){ //Primary QKDApp processes received signaling packet from Replica QKDApp
        uint32_t methodType = GetMethodFromHttp004AppQuery(); //Send_ksid or Create_queues
        if(methodType == 0){
            NS_LOG_FUNCTION( this << "SEND_KSID: Primary QKDApp received response from Replica QKDApp." );
            std::string ksid = GetKsidFromHttp004AppQuery();
            ProcessSendKsidResponse(header, ksid);
        }else if (methodType == 1){
            NS_LOG_FUNCTION( this << "ESTABLISH_QUEUES: Primary QKDApp received response from Replica QKDApp. Packet ID" );
            ProcessCreateQueuesResponse();
        }
        Http004AppQueryComplete();   

    }else{ //Replica QKDApp processes received signaling packet from Primary QKDApp.

        std::string s = header.GetUri();
        std::string delimiter = "/"; 
        size_t pos = 0;
        std::string token;
        
        std::vector<std::string> uriParams;
        while((pos = s.find(delimiter)) != std::string::npos){
            token = s.substr(0, pos);
            if(token.length() > 0){
                uriParams.push_back(token);
            }
            s.erase(0, pos + delimiter.length());
        }
        if(s.length() > 0){
            uriParams.push_back(s);
        }

        std::string requestType;
        if( 
            uriParams.size() > 3 && 
            uriParams[1] == "api" &&
            uriParams[2] == "v1"
        ){
            requestType = uriParams[4];
        }

        NS_LOG_FUNCTION(this << requestType << s);

        if(requestType == "connect"){ //This is SEND_KSID message

            NS_LOG_FUNCTION( this << "Processing send_ksid request!" );
            std::string ksid = uriParams[5];
            NS_ASSERT(!ksid.empty());
            std::string cryptoT = uriParams[6];
            NS_ASSERT(!cryptoT.empty());

            if(cryptoT == "0")
                m_associations.first.ksid = ksid; //Register KSID for encryption
            else if(cryptoT == "1")
                m_associations.second.ksid = ksid; //Register KSID for autentication
            else
                NS_FATAL_ERROR( this << "Invalid purpose of the association!" );

            NS_LOG_FUNCTION(this << cryptoT << ksid);

            SwitchAppState(ESTABLISHING_ASSOCIATIONS);
            OpenConnect(ksid); //Send OpenConnect to local KMS!

        }else if(requestType == "establish_queues") { //process establish_queues notification
            NS_LOG_FUNCTION( this << "Processing establish_queues request!" );
            SwitchAppState(ESTABLISHING_KEY_QUEUES);
            CheckQueues();

        } else {
          NS_FATAL_ERROR( this << "Invalid method received on app.  RequestType:" << requestType << s );
        }  

      }

}

/**
 * ********************************************************************************************

 *        Application SIGNALING
 
 * ********************************************************************************************
 */

void
QKDApp004::SendKsidRequest (std::string ksid, uint32_t keyType)
{
    NS_LOG_FUNCTION( this << ksid << keyType << this->GetId().string() ); //keyType is enc/auth identifier
    if(!m_sendSignalingSocketApp)
        PrepareSendSocketToApp();
    if(!m_sinkSignalingSocketApp)
        PrepareSinkSocketFromApp();

    NS_ASSERT(m_master); //Only primary QKDApp calls SendKsid

    Ipv4Address m_peerAddress = InetSocketAddress::ConvertFrom(m_peer).GetIpv4 ();
    std::stringstream ss;
    m_peerAddress.Print(ss);
    std::string headerUri = "http://" + ss.str();

    NS_LOG_FUNCTION(this << m_peer << headerUri << m_peerAddress << headerUri.size());
    
    headerUri += "/api/v1/" + this->GetId().string() + "/connect/" + ksid + "/" + std::to_string(keyType);
    NS_LOG_FUNCTION(this << headerUri);

    //Create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateRequest(headerUri, "GET");
    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packet = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    ); 
    NS_ASSERT (packet); 
      
    Http004AppQuery(0, ksid); //0-SendKSID method
    
    m_txSigTrace (packet);
    m_sendSignalingSocketApp->Send(packet);
    m_packetsSent++;
    m_dataSent += packet->GetSize();
    NS_LOG_FUNCTION( this << "SEND_KSID: Primary QKDApp sends KSID to Replica QKDApp" << 
                             headerUri << ". Packet ID" << packet->GetUid() );
}

void
QKDApp004::SendKsidResponse (HTTPMessage::HttpStatus httpStatus, std::string msg)
{
    NS_LOG_FUNCTION( this << "Sending response on SEND_KSID to Primary QKDApp" << httpStatus << msg );
    if(!m_sendSignalingSocketApp)
        PrepareSendSocketToApp();
    if(!m_sinkSignalingSocketApp)
        PrepareSinkSocketFromApp();
    NS_ASSERT(!m_master);

    //create packet
    HTTPMessage httpMessage;
    if(!msg.empty()){    
      httpMessage.CreateResponse(httpStatus, msg, {
        {"Content-Type", "application/json; charset=utf-8"}
      });
    }else{
      httpMessage.CreateResponse(httpStatus);
    }

    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packet = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT (packet);  

    m_txSigTrace (packet);
    m_sendSignalingSocketApp->Send(packet);
    m_packetsSent++;
    m_dataSent += packet->GetSize();
    
    NS_LOG_FUNCTION( this << "SEND_KSID: Replica QKDApp sends respose to Primary QKDApp. Packet ID" 
                          << packet->GetUid() << packet->GetSize() );
}

void
QKDApp004::ProcessSendKsidResponse (HTTPMessage& header, std::string ksid)
{
    NS_LOG_FUNCTION( this << "Processing /connect response (send_ksid)" );
    NS_ASSERT(m_master); //Only on Primary QKDApp can receive response on /connect
    if(header.GetStatus() == HTTPMessage::HttpStatus::Ok){
        if(m_associations.first.ksid == ksid)
            m_associations.first.verified = true; //Acknowledge peer application registered for ksid
        else if(m_associations.second.ksid == ksid)
            m_associations.second.verified = true; //Acknowledge peer application registered for ksid
        else
            NS_FATAL_ERROR( this );
        NS_LOG_FUNCTION( this << "Association successfully established between QKDApps " << ksid );
        CheckAssociationsState(); //Check if the QKDApp is ready to leave ESTABLISHING_ASSOCIATIONS state!

    }else{
        NS_LOG_FUNCTION( this << "/connect failed! " << ksid );
        Close(ksid); //Close established association
    }
}

void
QKDApp004::CreateKeyQueues ()
{
    NS_LOG_FUNCTION( this << "Primary QKDApp sending establish_queues notification to Replica QKDApp" );
    NS_ASSERT(m_master); //Only Primary QKDApp function
    
    Ipv4Address m_peerAddress = InetSocketAddress::ConvertFrom(m_peer).GetIpv4 ();
    std::stringstream ss;
    m_peerAddress.Print(ss);
    std::string headerUri = "http://" + ss.str();
    headerUri += "/api/v1/" + this->GetId().string() + "/establish_queues";

    //Create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateRequest(headerUri, "GET"); //GET for a notification message?
    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packet = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    ); 
    NS_ASSERT (packet); 
    
    Http004AppQuery(1, ""); //1 - establish_queues method!
    
    m_txSigTrace (packet);
    m_sendSignalingSocketApp->Send(packet);
    m_packetsSent++;
    m_dataSent += packet->GetSize();
    
    NS_LOG_FUNCTION(this << "Packet ID:" << packet->GetUid() << "Packet size:" << packet->GetSize() );

}

void
QKDApp004::CreateKeyQueuesResponse ()
{
    NS_LOG_FUNCTION( this << "Replica QKDApp sending response on /fill indicating success" );
    NS_ASSERT(!m_master); //Only Replica QKDApp function

    //create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateResponse(HTTPMessage::HttpStatus::Ok);
    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packet = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    );
    NS_ASSERT (packet); 

    m_txSigTrace (packet);
    m_sendSignalingSocketApp->Send(packet);
    m_packetsSent++;
    m_dataSent += packet->GetSize();

    NS_LOG_FUNCTION(this << "Packet ID" << packet->GetUid() << "Packet size" << packet->GetSize() );

}

void
QKDApp004::ProcessCreateQueuesResponse ()
{
  NS_LOG_FUNCTION( this );

  m_replicaQueueEstablished = true;

  if (m_primaryQueueEstablished) {
    SwitchAppState(KEY_QUEUES_ESTABLISHED);
    AppTransitionTree();
  }

}

void
QKDApp004::CreateKeyStreamAssociations ()
{
  
    NS_LOG_FUNCTION( this << "Establishing associations" );
    if(GetEncryptionKeySize() != 0 && m_associations.first.ksid == "")
        OpenConnect("", 0); //Establish association for a set of future encryption (0) keys
    if (GetAuthenticationKeySize() != 0 && m_associations.second.ksid == "")
        OpenConnect("", 1); //Establish association for a set of future authentication (1) keys
}

void
QKDApp004::ClearAssociation (std::string ksid)
{
    NS_LOG_FUNCTION( this << "Clearing key stream association on QKDApp" << ksid );
    if(m_associations.first.ksid == ksid){ //Clear association created for encryption
        m_associations.first.ksid.clear(); //Clear ksid
        m_associations.first.verified = false;
        m_associations.first.keyActive = 0;
        m_associations.first.buffer.clear(); //Clear any keys in buffer!
    }else if(m_associations.second.ksid == ksid){ //Clear association created for authentication
        m_associations.second.ksid.clear(); //Clear ksid
        m_associations.second.verified = false;
        m_associations.second.keyActive = 0;
        m_associations.second.buffer.clear(); //Clear any keys in buffer!
    }
    NS_LOG_FUNCTION( this << "Key stream association " << ksid << " cleared!" );
}

void 
QKDApp004::RegisterAckTime (Time oldRtt, Time newRtt)
{
  NS_LOG_FUNCTION (this << oldRtt << newRtt); 
}


/**
 * ********************************************************************************************

 *        STATE functions
 
 * ********************************************************************************************
 */

void
QKDApp004::AppTransitionTree (void)
{
  
    NS_LOG_FUNCTION( this << m_master );
    if(m_master){ //Transitions for Primary QKDApp
        if(m_appState == INITIALIZED){
            if (GetEncryptionKeySize() == 0 && GetAuthenticationKeySize() == 0){ //QKD key material not needed!
                SwitchAppState(READY);
                PrepareSendSocketToApp();
                SendPacket(); //Immediately sends unprotected packets
            }else{ //Establish associations for a set of future QKD keys
                SwitchAppState(ESTABLISHING_ASSOCIATIONS);
                PrepareSendSocketToKMS();
                CreateKeyStreamAssociations(); //Call OPEN_CONNECT
            }
        }else if(m_appState == ASSOCIATIONS_ESTABLISHED){
            SwitchAppState(ESTABLISHING_KEY_QUEUES);
            CreateKeyQueues();
            CheckQueues();
        }else if(m_appState == KEY_QUEUES_ESTABLISHED){
            SwitchAppState(READY);
            SendPacket(); //Start sending packets!
        }else{
            NS_FATAL_ERROR( this << "Invalid entry state" << m_appState <<
                                    "for AppTransitionTree()!" );
        }

    }else if(!m_master){ //Data transmision state transition for Replica QKDApp
        if(m_appState == INITIALIZED){
            SwitchAppState(READY);
        }else if(m_appState == KEY_QUEUES_ESTABLISHED){
            if (m_associations.first.verified)
              m_associations.first.keyActive = m_associations.first.buffer.begin()->first;
            if (m_associations.second.verified)
              m_associations.second.keyActive = m_associations.second.buffer.begin()->first;
            SwitchAppState(READY);
            CreateKeyQueuesResponse();
        }else{
            NS_FATAL_ERROR( this << "Invalid entry state" << m_appState <<
                                    "for AppTransitionTree()!" );
        }

    }

}


QKDApp004::QKDAppState
QKDApp004::GetAppState () const
{
  return m_appState;
}

std::string
QKDApp004::GetAppStateString (QKDApp004::QKDAppState state)
{
  switch (state)
    {
    case NOT_STARTED:
      return "NOT_STARTED";
      break;
    case INITIALIZED:
      return "INITIALIZED";
      break; 
    case ESTABLISHING_ASSOCIATIONS:
      return "ESTABLISHING_ASSOCIATIONS";
      break;
    case ASSOCIATIONS_ESTABLISHED:
      return "ASSOCIATIONS_ESTABLISHED";
      break;
    case ESTABLISHING_KEY_QUEUES:
      return "ESTABLISHING_KEY_QUEUES";
      break;
    case KEY_QUEUES_ESTABLISHED:
      return "KEY_QUEUES_ESTABLISHED";
      break;
    case READY:
      return "READY";
      break;
    case WAIT:
      return "WAIT";
      break;
    case SEND_DATA:
      return "SEND_DATA";
      break;
    case DECRYPT_DATA:
      return "DECRYPT_DATA";
      break;
    case STOPPED:
      return "STOPPED";
      break;
    default:
      NS_FATAL_ERROR ("Unknown state");
      return "FATAL_ERROR";
      break;
    }
}


std::string
QKDApp004::GetAppStateString () const
{
  return GetAppStateString (m_appState);
}

void
QKDApp004::SwitchAppState (QKDApp004::QKDAppState state)
{

  const std::string oldState = GetAppStateString ();
  const std::string newState = GetAppStateString (state);

  //Check transition matrix! @toDo
  if (oldState == "SEND_DATA" && newState == "READY") {
    if  ( (m_associations.first.ksid != "" && m_associations.first.buffer.empty()) ||
          (m_associations.second.ksid != "" && m_associations.second.buffer.empty())  
        )
      state = QKDApp004::QKDAppState::WAIT; //Queues are empty. Go to state WAIT!
  }
  
  m_appState = state;
  NS_LOG_FUNCTION( this << "QKDApp" << oldState << "-->" << GetAppStateString (state) );
  //m_appStateTransitionTrace(oldState, newState);

}

/**
 * ********************************************************************************************

 *        ADDTIONAL functions
 
 * ********************************************************************************************
 */

void 
QKDApp004::SetEncryptionAndAuthenticationSettings(
  uint32_t encryptionType, 
  uint32_t authenticationType,
  uint32_t authenticationTagLengthInBits
){

  NS_LOG_FUNCTION (this << encryptionType << authenticationType << authenticationTagLengthInBits);

  switch (encryptionType){
    case 0:
      m_encryptionType = QKDEncryptor::UNENCRYPTED;
      break;
    case 1:
      m_encryptionType = QKDEncryptor::QKDCRYPTO_OTP;
      break;
    case 2:
      m_encryptionType = QKDEncryptor::QKDCRYPTO_AES;
      break;
  }
 
  switch (authenticationType){
    case 0:
      m_authenticationType = QKDEncryptor::UNAUTHENTICATED;
      break;
    case 1:
      m_authenticationType = QKDEncryptor::QKDCRYPTO_AUTH_VMAC;
      break;
    case 2:
      m_authenticationType = QKDEncryptor::QKDCRYPTO_AUTH_MD5;
      break;
    case 3:
      m_authenticationType = QKDEncryptor::QKDCRYPTO_AUTH_SHA1;
      break;
  }

  if(!m_encryptor){
    m_encryptor = CreateObject<QKDEncryptor> (
      m_encryptionType,
      m_authenticationType,
      authenticationTagLengthInBits
    );
  }else{
    m_encryptor->ChangeSettings(
      m_encryptionType,
      m_authenticationType,
      authenticationTagLengthInBits
    );
  }

}

std::string
QKDApp004::GetPacketContent(uint32_t msgLength)
{
  NS_LOG_FUNCTION(this);
  
  if (msgLength == 0)
    msgLength = m_packetSize;

  //Generate random string with same size as merged key string
  std::string confidentialMessage;
  static const char alphanum[] =
    "0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz";
  
  uint32_t randVal = 0;
  for (uint32_t i = 0; i < msgLength; ++i){ 
    randVal = round(m_random->GetValue (0, sizeof(alphanum) - 1));
    confidentialMessage += alphanum[ randVal ];
  } 

  return confidentialMessage;

}

uint32_t 
QKDApp004::GetEncryptionKeySize()
{
    switch(m_encryptionType){
      case QKDEncryptor::UNENCRYPTED:
        return 0;
        break;
      case QKDEncryptor::QKDCRYPTO_OTP:
        return m_packetSize * 8;
        break;
      case QKDEncryptor::QKDCRYPTO_AES: 
        return CryptoPP::AES::MAX_KEYLENGTH * 8; //In bits 256! Quantum resistant!
        break;
    }
    return 0;
}

uint64_t
QKDApp004::GetMaxEncryptionKeyRate()
{ 
    uint32_t rate = 0;
    switch(m_encryptionType){
      case QKDEncryptor::UNENCRYPTED:

        NS_LOG_FUNCTION(this << "UNENCRYPTED");
        return 0;
        break;

      case QKDEncryptor::QKDCRYPTO_OTP:

        NS_LOG_FUNCTION(this << "OTP:" << m_dataRate.GetBitRate());
        return m_dataRate.GetBitRate();
        break;

      case QKDEncryptor::QKDCRYPTO_AES: 

        //In bits 256! Quantum resistant!
        if(m_dataRate.GetBitRate() < m_aesLifetime){
          rate = CryptoPP::AES::MAX_KEYLENGTH * 8;
        }else{
          rate = round (
            (m_dataRate.GetBitRate()/m_aesLifetime) * CryptoPP::AES::MAX_KEYLENGTH * 8
          );
        }
        NS_LOG_FUNCTION(this << "AES:" << rate << m_dataRate.GetBitRate() << m_aesLifetime << CryptoPP::AES::MAX_KEYLENGTH * 8);
        return rate;
        break;

    }
    return rate;
}

uint32_t
QKDApp004::GetAuthenticationKeySize()
{ 
    uint32_t rate = 0;
    switch (m_authenticationType){
      case QKDEncryptor::UNAUTHENTICATED:

        NS_LOG_FUNCTION(this << "UNENCRYPTED");
        return 0;
        break;

      case QKDEncryptor::QKDCRYPTO_AUTH_VMAC:

        rate = CryptoPP::AES::DEFAULT_KEYLENGTH * 8; //Use with AES. In bits 128 bits!
        NS_LOG_FUNCTION(this << "QKDCRYPTO_AUTH_VMAC: " << rate);
        return rate;
        break;

      case QKDEncryptor::QKDCRYPTO_AUTH_MD5:

        NS_LOG_FUNCTION(this << "QKDCRYPTO_AUTH_MD5");
        return 0; //NoKey
        break;

      case QKDEncryptor::QKDCRYPTO_AUTH_SHA1:

        NS_LOG_FUNCTION(this << "QKDCRYPTO_AUTH_SHA1");
        return 0; //NoKey
        break;

    }
    return rate;
}

uint64_t
QKDApp004::GetMaxAuthenticationKeyRate()
{
    NS_ASSERT(m_packetSize>0);
    NS_ASSERT(m_dataRate.GetBitRate() > 0);

    uint32_t rate = 0;
    switch (m_authenticationType){
      case QKDEncryptor::UNAUTHENTICATED:
        return 0;
        break;
      case QKDEncryptor::QKDCRYPTO_AUTH_VMAC:
          
          //Use with AES. In bits 128 bits!
          if(m_aesLifetime){

            if(m_dataRate.GetBitRate() < m_aesLifetime){
              rate = CryptoPP::AES::DEFAULT_KEYLENGTH * 8;
            }else{
              rate = round (
                (m_dataRate.GetBitRate()/m_aesLifetime) * CryptoPP::AES::DEFAULT_KEYLENGTH * 8
              );
            }
            return rate;

          }else{ 

            if(m_dataRate.GetBitRate() < m_packetSize){
              rate = CryptoPP::AES::DEFAULT_KEYLENGTH * 8;
            }else{
              rate = round (
                (m_dataRate.GetBitRate()/m_packetSize) * CryptoPP::AES::DEFAULT_KEYLENGTH * 8
              );
            }
            return rate; 

          }
          break;
      case QKDEncryptor::QKDCRYPTO_AUTH_MD5:
        return 0; //NoKey
        break;
      case QKDEncryptor::QKDCRYPTO_AUTH_SHA1:
        return 0; //NoKey
        break;
    }
    return 0;
}


std::string
QKDApp004::PacketToString (Ptr<Packet> packet)
{
  NS_LOG_FUNCTION( this );

  uint8_t *buffer = new uint8_t[packet->GetSize ()];
  packet->CopyData(buffer, packet->GetSize ());
  std::string payload = std::string((char*)buffer, packet->GetSize());
  delete[] buffer;

  return payload;
}


 
} // Namespace ns3
