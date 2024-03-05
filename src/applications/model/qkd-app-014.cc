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
#include "qkd-app-014.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDApp014");

NS_OBJECT_ENSURE_REGISTERED (QKDApp014);

TypeId 
QKDApp014::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDApp014")
    .SetParent<Application> ()
    .SetGroupName("Applications")
    .AddConstructor<QKDApp014> ()
    .AddAttribute ("Protocol", "The type of protocol to use.",
                   TypeIdValue (TcpSocketFactory::GetTypeId ()),
                   MakeTypeIdAccessor (&QKDApp014::m_tid),
                   MakeTypeIdChecker ())
    .AddAttribute ("NumberOfKeyToFetchFromKMS", 
                   "The total number of keys per request to LKMS (ESTI QKD 014)",
                   UintegerValue (3),
                   MakeUintegerAccessor (&QKDApp014::m_numberOfKeysKMS),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("LengthOfAuthenticationTag", 
                   "The default length of the authentication tag",
                   UintegerValue (256), //32 bytes
                   MakeUintegerAccessor (&QKDApp014::m_authenticationTagLengthInBits),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("EncryptionType", 
                   "The type of encryption to be used (0-unencrypted, 1-OTP, 2-AES)",
                   UintegerValue (1),
                   MakeUintegerAccessor (&QKDApp014::m_encryptionTypeInt),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("AuthenticationType", 
                   "The type of authentication to be used (0-unauthenticated, 1-VMAC, 2-MD5, 3-SHA1)",
                   UintegerValue (2),
                   MakeUintegerAccessor (&QKDApp014::m_authenticationTypeInt),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("AESLifetime", 
                   "Lifetime of AES key expressed in bytes",
                   UintegerValue (1),
                   MakeUintegerAccessor (&QKDApp014::m_aesLifetime),
                   MakeUintegerChecker<uint64_t> ())
    .AddAttribute ("UseCrypto",
                   "Should crypto functions be performed (0-No, 1-Yes)",
                   UintegerValue (0),
                   MakeUintegerAccessor (&QKDApp014::m_useCrypto),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("WaitInsufficient","Penalty time (in seconds) when there is insufficient amount of key",
                   TimeValue (Seconds (0.3)),
                   MakeTimeAccessor (&QKDApp014::m_waitInsufficient),
                   MakeTimeChecker ())
    .AddAttribute ("WaitTransform","Penalty time (in seconds) when keys are being transformed",
                   TimeValue (Seconds (0.05)),
                   MakeTimeAccessor (&QKDApp014::m_waitTransform),
                   MakeTimeChecker ()) 

    .AddTraceSource ("Tx", "A new packet is created and is sent",
                     MakeTraceSourceAccessor (&QKDApp014::m_txTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("TxSig", "A new signaling packet is created and is sent",
                     MakeTraceSourceAccessor (&QKDApp014::m_txSigTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("TxKMS", "A new packet is created and is sent to local KMS",
                     MakeTraceSourceAccessor (&QKDApp014::m_txKmsTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("Rx", "A new packet is received",
                     MakeTraceSourceAccessor (&QKDApp014::m_rxTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("RxSig", "A new signaling packet is received",
                     MakeTraceSourceAccessor(&QKDApp014::m_rxSigTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("RxKMS", "A new packet is received from local KMS",
                     MakeTraceSourceAccessor (&QKDApp014::m_rxKmsTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("StateTransition",
                     "Trace fired upon every QKDApp014 state transition.",
                     MakeTraceSourceAccessor (&QKDApp014::m_stateTransitionTrace),
                     "ns3::Application::StateTransitionCallback")
    .AddTraceSource ("PacketEncrypted",
                    "The change trance for currenly ecrypted packet",
                     MakeTraceSourceAccessor (&QKDApp014::m_encryptionTrace),
                     "ns3::QKDCrypto::PacketEncrypted")
    .AddTraceSource ("PacketDecrypted",
                    "The change trance for currenly decrypted packet",
                     MakeTraceSourceAccessor (&QKDApp014::m_decryptionTrace),
                     "ns3::QKDCrypto::PacketDecrypted")
    .AddTraceSource ("PacketAuthenticated",
                    "The change trance for currenly authenticated packet",
                     MakeTraceSourceAccessor (&QKDApp014::m_authenticationTrace),
                     "ns3::QKDCrypto::PacketAuthenticated")
    .AddTraceSource ("PacketDeAuthenticated",
                    "The change trance for currenly deauthenticated packet",
                     MakeTraceSourceAccessor (&QKDApp014::m_deauthenticationTrace),
                     "ns3::QKDCrypto::PacketDeAuthenticated")
    .AddTraceSource ("Mx", "Missed send packet call",
                     MakeTraceSourceAccessor (&QKDApp014::m_mxTrace),
                     "ns3::Packet::TracedCallback")
    .AddTraceSource ("KeyObtained", "Trace amount of obtained key material",
                     MakeTraceSourceAccessor (&QKDApp014::m_obtainedKeyMaterialTrace),
                     "ns3::QKDApp014::KeyObtained")
  ;

  return tid;
}
//@toDo: add use fallback to AES when OTP is used (Y/N)

uint32_t QKDApp014::m_applicationCounts = 0;

/**
 * ********************************************************************************************

 *        SETUP
 
 * ********************************************************************************************
 */

QKDApp014::QKDApp014 () 
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

  m_transitionMatrix = {
    {"NOT_STARTED", "INITIALIZED"},
    {"INITIALIZED", "WAIT"},
    {"INITIALIZED", "READY"},
    {"WAIT", "READY"},
    {"READY", "WAIT"},
    {"READY", "SEND_DATA"},
    {"SEND_DATA", "READY"},
    {"READY", "DECRYPT_DATA"},
    {"DECRYPT_DATA", "READY"},
    {"DECRYPT_DATA", "STOPPED"}, 
    {"SEND_DATA", "STOPPED"},
    {"READY", "STOPPED"},
    {"WAIT", "STOPPED"},
  };
}

QKDApp014::~QKDApp014()
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
QKDApp014::Setup (
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
QKDApp014::Setup (
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

    NS_LOG_FUNCTION (this << m_appState);

    if(type == "alice"){
      m_master = 1;
    }else{
      m_master = 0;
    }

    m_local = src;
    m_peer = dst; 
    m_kms = kms;

    m_localSignaling = InetSocketAddress(
      InetSocketAddress::ConvertFrom(m_local).GetIpv4 (),
      6089+m_applicationCounts
    );
    m_peerSignaling = InetSocketAddress(
      InetSocketAddress::ConvertFrom(m_peer).GetIpv4 (),
      6089+m_applicationCounts
    );

    m_dstSaeId = dstSaeId;
    m_packetSize = packetSize; 
    m_dataRate = dataRate; 
    m_socketType = socketType;

    m_internalAppWait = false; //No longer wait schedule required!
    InitializeAppKeyBuffer (); //Setup application key buffer!
    SwitchAppState (INITIALIZED);
}



/**
 * ********************************************************************************************

 *        SCHEDULE functions
 
 * ********************************************************************************************
 */
void
QKDApp014::ScheduleTx (void)
{
  NS_LOG_FUNCTION (this << m_appState);

  if (m_appState != STOPPED && m_appState != NOT_STARTED)
  {
    NS_LOG_FUNCTION (this << "QKDApp014 is running!");
    double delay = m_packetSize * 8 / static_cast<double> (m_dataRate.GetBitRate ());
    NS_LOG_FUNCTION( this << "delay" << Seconds (delay) );
    Time tNext (Seconds (delay));
    m_sendEvent = Simulator::Schedule (tNext, &QKDApp014::SendPacket, this);

  } else
    NS_LOG_FUNCTION (this << "QKDApp014 is" << GetAppStateString(m_appState));
}

uint32_t
QKDApp014::ScheduleAction(Time t, std::string action)
{
    NS_LOG_FUNCTION( this << action << t );
    uint32_t scheduleID {0};
    EventId event;
    if(action == "CheckAppBufferState"){
        if(m_internalAppWait == false){
            m_internalAppWait = true;
            event = Simulator::Schedule (t, &QKDApp014::CheckAppBufferState, this);
            scheduleID = event.GetUid();
            m_scheduledEvents.insert( std::make_pair( scheduleID ,  event) );
            NS_LOG_FUNCTION(this << "Event successfully scheduled!");
        }else{
            NS_LOG_FUNCTION(this << "Scheduled event already exists!");
        }
    }else 
        NS_FATAL_ERROR( this << "Invalid action" << action );

    return scheduleID;
}

void
QKDApp014::CancelScheduledAction(uint32_t eventId)
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
QKDApp014::PrepareSinkSocketFromKMS()
{
  
  NS_LOG_FUNCTION(this);

  if(!m_sinkSocketFromKMS){
    Address localAddress = InetSocketAddress(
      //InetSocketAddress::ConvertFrom(m_kms).GetIpv4 (),
      Ipv4Address::GetAny (), 
      82//InetSocketAddress::ConvertFrom(m_kms).GetPort ()
    ); 
    m_sinkSocketFromKMS = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId () );

    if (m_sinkSocketFromKMS->Bind (localAddress) == -1)
      NS_FATAL_ERROR ("Failed to bind socket");

    m_sinkSocketFromKMS->Listen ();
    m_sinkSocketFromKMS->ShutdownSend ();
    m_sinkSocketFromKMS->SetRecvCallback (MakeCallback (&QKDApp014::HandleReadFromKMS, this));
    m_sinkSocketFromKMS->SetAcceptCallback (
      MakeCallback (&QKDApp014::ConnectionRequestedFromKMS, this),
      MakeCallback (&QKDApp014::HandleAcceptFromKMS, this)
    );
    m_sinkSocketFromKMS->SetCloseCallbacks (
      MakeCallback (&QKDApp014::HandlePeerCloseFromKMS, this),
      MakeCallback (&QKDApp014::HandlePeerErrorFromKMS, this)
    );  
    NS_LOG_FUNCTION (this << "Create new APP socket " << m_sinkSocketFromKMS 
      << " to listen packets from KMS on " <<  InetSocketAddress::ConvertFrom(localAddress).GetIpv4 () 
      << " and port " <<  82//InetSocketAddress::ConvertFrom(localAddress).GetPort ()   
    );
  }else{
     NS_LOG_FUNCTION (this << "Socket to listen from local KMS exists!" << m_sinkSocketFromKMS);
  }

}

void
QKDApp014::PrepareSendSocketToKMS()
{
  NS_LOG_FUNCTION(this);

  if(!m_sendSocketToKMS){
    Address lkmsAddress = InetSocketAddress(
      InetSocketAddress::ConvertFrom(m_kms).GetIpv4 (),
      InetSocketAddress::ConvertFrom(m_kms).GetPort ()
    );
    m_sendSocketToKMS = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId () );
    m_sendSocketToKMS->Bind ();
    m_sendSocketToKMS->ShutdownRecv ();
    m_sendSocketToKMS->SetConnectCallback (
      MakeCallback (&QKDApp014::ConnectionToKMSSucceeded, this),
      MakeCallback (&QKDApp014::ConnectionToKMSFailed, this)); 
    m_sendSocketToKMS->SetDataSentCallback (
      MakeCallback (&QKDApp014::DataToKMSSend, this));  
    m_sendSocketToKMS->Connect ( lkmsAddress );
    NS_LOG_FUNCTION (this << "Create new APP socket " << m_sendSocketToKMS << " to reach local KMS!");
  }else{
     NS_LOG_FUNCTION (this << "Socket to reach local KMS exists!" << m_sendSocketToKMS);
  }

}

void
QKDApp014::PrepareSendSocketToApp()
{
  NS_LOG_FUNCTION(this << m_sendSignalingSocketApp);

  if(!m_sendSignalingSocketApp || !m_sendDataSocketApp)
  {

    if(!m_sendSignalingSocketApp){

      if(m_socketType == "tcp"){
        m_sendSignalingSocketApp = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId () );
      }else{
        m_sendSignalingSocketApp = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId () );
      }

      m_sendSignalingSocketApp->Bind ();
      m_sendSignalingSocketApp->Connect (m_peerSignaling); 
      m_sendSignalingSocketApp->SetConnectCallback (
        MakeCallback (&QKDApp014::ConnectionSignalingToAppSucceeded, this),
        MakeCallback (&QKDApp014::ConnectionSignalingToAppFailed, this)); 
    }

    if(!m_sendDataSocketApp)
    {

      if(m_socketType == "tcp"){
        m_sendDataSocketApp = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId () );
      }else{
        m_sendDataSocketApp = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId () );
      }

      m_sendDataSocketApp->Bind ();
      m_sendDataSocketApp->Connect (m_peer); 
      m_sendDataSocketApp->SetConnectCallback (
        MakeCallback (&QKDApp014::ConnectionToAppSucceeded, this),
        MakeCallback (&QKDApp014::ConnectionToAppFailed, this)); 
    }

  }else{
    NS_LOG_FUNCTION (this << "Socket to reach peer app exists!" << m_sendSignalingSocketApp);
  }
}

void
QKDApp014::PrepareSinkSocketFromApp()
{
  NS_LOG_FUNCTION(this << GetNode()->GetId() << m_socketType );

  if(!m_sinkSignalingSocketApp)
  {

    if(m_socketType == "tcp") {
      m_sinkSignalingSocketApp = Socket::CreateSocket (GetNode (), TcpSocketFactory::GetTypeId () );
    } else {
      m_sinkSignalingSocketApp = Socket::CreateSocket (GetNode (), UdpSocketFactory::GetTypeId () );  
    }

    if (m_sinkSignalingSocketApp->Bind (m_localSignaling) == -1)
      NS_FATAL_ERROR ("Failed to bind socket");

    m_sinkSignalingSocketApp->Listen ();
    m_sinkSignalingSocketApp->ShutdownSend (); 
    m_sinkSignalingSocketApp->SetRecvCallback (MakeCallback (&QKDApp014::HandleReadSignalingFromApp, this));
    m_sinkSignalingSocketApp->SetAcceptCallback (
      MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
      MakeCallback (&QKDApp014::HandleAcceptSignalingFromApp, this)
    );
    m_sinkSignalingSocketApp->SetCloseCallbacks (
      MakeCallback (&QKDApp014::HandlePeerCloseSignalingFromApp, this),
      MakeCallback (&QKDApp014::HandlePeerErrorSignalingFromApp, this)
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
 
    if (m_sinkDataSocketApp->Bind (m_local) == -1)
      NS_FATAL_ERROR ("Failed to bind socket");

    m_sinkDataSocketApp->Listen ();
    m_sinkDataSocketApp->ShutdownSend (); 
    m_sinkDataSocketApp->SetRecvCallback (MakeCallback (&QKDApp014::HandleReadFromApp, this));
    m_sinkDataSocketApp->SetAcceptCallback (
      MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
      MakeCallback (&QKDApp014::HandleAcceptFromApp, this)
    );
    m_sinkDataSocketApp->SetCloseCallbacks (
      MakeCallback (&QKDApp014::HandlePeerCloseFromApp, this),
      MakeCallback (&QKDApp014::HandlePeerErrorFromApp, this)
    ); 
  }else{
     NS_LOG_FUNCTION (this << "Socket to listen data from peer app exists!" << m_sinkSignalingSocketApp);
  }

}

bool
QKDApp014::ConnectionRequestedFromKMS (Ptr<Socket> socket, const Address &from)
{
  NS_LOG_FUNCTION (this << socket << from 
    << InetSocketAddress::ConvertFrom(from).GetIpv4 () 
    << InetSocketAddress::ConvertFrom(from).GetPort ()
  ); 
  NS_LOG_FUNCTION (this << "QKDApp014 Connection from KMS requested on socket " << socket);
  return true; // Unconditionally accept the connection request.

}

void 
QKDApp014::HandleAcceptFromKMS (Ptr<Socket> socket, const Address& from)
{ 
  Address peer;
  NS_LOG_FUNCTION (this << socket << from 
    << InetSocketAddress::ConvertFrom(from).GetIpv4 () 
    << InetSocketAddress::ConvertFrom(from).GetPort ()
  );  
  NS_LOG_FUNCTION (this << "QKDApp014 Connection from KMS accepted on socket " << socket);
  socket->SetRecvCallback (MakeCallback (&QKDApp014::HandleReadFromKMS, this));
}

void 
QKDApp014::HandleAcceptFromApp (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from 
    << InetSocketAddress::ConvertFrom(from).GetIpv4 () 
    << InetSocketAddress::ConvertFrom(from).GetPort ()
  );  

  NS_LOG_FUNCTION (this << "QKDApp014 Connection from APP accepted on socket " << s);
  s->SetRecvCallback (MakeCallback (&QKDApp014::HandleReadFromApp, this));
} 

void 
QKDApp014::HandleAcceptSignalingFromApp (Ptr<Socket> s, const Address& from)
{
  NS_LOG_FUNCTION (this << s << from 
    << InetSocketAddress::ConvertFrom(from).GetIpv4 () 
    << InetSocketAddress::ConvertFrom(from).GetPort ()
  );  

  NS_LOG_FUNCTION (this << "QKDApp014 Signaling Connection from APP accepted on socket " << s);
  s->SetRecvCallback (MakeCallback (&QKDApp014::HandleReadSignalingFromApp, this));
} 

void
QKDApp014::ConnectionToKMSSucceeded (Ptr<Socket> socket) 
{
  NS_LOG_FUNCTION (this << socket << "QKDApp014 Connection to KMS succeeded via socket " << socket);
}

void
QKDApp014::ConnectionToKMSFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket << "QKDApp014, Connection to KMS Failed via socket " << socket);
}

void
QKDApp014::ConnectionToAppSucceeded (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket << "QKDApp014 Connection to APP succeeded via socket " << socket);
}

void
QKDApp014::ConnectionToAppFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket << "QKDApp014, Connection to APP Failed via socket " << socket);
}

void
QKDApp014::ConnectionSignalingToAppSucceeded (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket << "QKDApp014 Signaling Connection to APP succeeded via socket " << socket);
}

void
QKDApp014::ConnectionSignalingToAppFailed (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket << "QKDApp014, Connection to APP Failed via socket " << socket);
}

void 
QKDApp014::HandlePeerCloseFromKMS (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDApp014::HandlePeerErrorFromKMS (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDApp014::HandlePeerCloseFromApp (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}
void 
QKDApp014::HandlePeerErrorFromApp (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDApp014::HandlePeerCloseSignalingFromApp (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDApp014::HandlePeerErrorSignalingFromApp (Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << socket);
}

void 
QKDApp014::HandleReadFromKMS (Ptr<Socket> socket)
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
}

void 
QKDApp014::HandleReadFromApp (Ptr<Socket> socket)
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
QKDApp014::HandleReadSignalingFromApp (Ptr<Socket> socket)
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
QKDApp014::DataToKMSSend (Ptr<Socket> socket, uint32_t)
{
    NS_LOG_FUNCTION (this << "QKDApp014 Data to KMS Sent via socket " << socket);
}


/**
 * ********************************************************************************************

 *        KEY BUFFER functions
 
 * ********************************************************************************************
 */
void 
QKDApp014::InitializeAppKeyBuffer() 
{

  NS_LOG_FUNCTION( this << "Application key buffer is initialized!");
  //Initialize storages of keys!
  m_appKeyBuffer.outboundEncKeyStore = {};
  m_appKeyBuffer.outboundAuthKeyStore = {};
  m_appKeyBuffer.inboundKeyStore = {};
  m_appKeyBuffer.temporaryKeyStoreMaster = {};
}

void
QKDApp014::RemoveKeysFromTemporaryKeyStore (std::vector<std::string> keyIds) 
{ 
  NS_LOG_FUNCTION( this << "Keys removed from temporary key store" << keyIds );
  std::map<std::string, QKDApp014::QKDApp014Key>::iterator it;
  for (uint i = 0; i < keyIds.size(); i++) {
    it = (m_appKeyBuffer.temporaryKeyStoreMaster).find(keyIds[i]);
    if (it == m_appKeyBuffer.temporaryKeyStoreMaster.end())
      //NS_FATAL_ERROR( this << "Key with ID" << keyIds[i] << "does not exist in temporary key store!" );
      NS_LOG_DEBUG( this << "Key with ID" << keyIds[i] << "does not exist in temporary key store!" );
    else
      (m_appKeyBuffer.temporaryKeyStoreMaster).erase(it);
  }
}

void
QKDApp014::AddKeyInInboundKeyStore (QKDApp014::QKDApp014Key& key)
{ 
  NS_LOG_FUNCTION( this << "Key with ID" << key.keyId << "is added to inbound key store!" );
  (m_appKeyBuffer.inboundKeyStore).insert(std::make_pair(key.keyId, key));
}

void
QKDApp014::AddEncKeyInKeyStore (QKDApp014::QKDApp014Key& key)
{
  NS_LOG_FUNCTION( this << "Key with ID" << key.keyId << "is added to encription key store!" );
  (m_appKeyBuffer.outboundEncKeyStore).insert(std::make_pair(key.keyId, key));
}

void
QKDApp014::AddAuthKeyInKeyStore (QKDApp014::QKDApp014Key& key)
{
  NS_LOG_FUNCTION( this << "Key with ID" << key.keyId << "is added to authentication key store!" );
  (m_appKeyBuffer.outboundAuthKeyStore).insert(std::make_pair(key.keyId, key));
}

void
QKDApp014::PrintTemporaryKeyStoreContent ()
{
  std::map<std::string, QKDApp014::QKDApp014Key>::iterator it = (m_appKeyBuffer.temporaryKeyStoreMaster).begin();
  while (it != (m_appKeyBuffer.temporaryKeyStoreMaster).end()) {
    NS_LOG_FUNCTION( this << "KeyId" << it->first << it->second.keyId << "\n" );
    it++;
  }
}

void
QKDApp014::PrintAppBufferStatusInformation ()
{
  NS_LOG_FUNCTION( this << "Outbound encrption key count" << m_appKeyBuffer.outboundEncKeyStore.size()
                        << "Outbound authentication key count" <<  m_appKeyBuffer.outboundAuthKeyStore.size() 
                        << "Inbound key count" << m_appKeyBuffer.inboundKeyStore.size() );
}

void
QKDApp014::CheckAppBufferState ()
{
    NS_LOG_FUNCTION(this << "Primary QKDApp checks internal enc/auth buffer states ...");
    if(m_internalAppWait) m_internalAppWait = false;
    //Note: CheckAppBufferState must not be triggered from anywhere while m_internalAppWait is true! It is called on scheduled event!
    if(m_master){ //Only at Primary application!
        if(GetEncryptionKeySize() != 0 && m_appKeyBuffer.outboundEncKeyStore.empty()) //Check the state of encryption key store
            GetKeysFromKMS(0); // 0 - Encryption key
        if(GetAuthenticationKeySize() != 0 && m_appKeyBuffer.outboundAuthKeyStore.empty()) //Check the state of authentication key store
            GetKeysFromKMS(1); // 1 - Authentication key
        CheckAppState();
    }
}

void
QKDApp014::CheckAppState ()
{
    NS_LOG_FUNCTION(this << "Checking the conditions to change the application state ...");
    bool encryptionReady {true}, authenticationReady {true};
    if(GetEncryptionKeySize() != 0 && m_appKeyBuffer.outboundEncKeyStore.empty())
        encryptionReady = false;
    if(GetAuthenticationKeySize() != 0 && m_appKeyBuffer.outboundAuthKeyStore.empty())
        authenticationReady = false;

    if(m_appState == WAIT && encryptionReady && authenticationReady)
        SwitchAppState(READY);
    else if(m_appState == READY && !(encryptionReady && authenticationReady))
        SwitchAppState(WAIT);
}

QKDApp014::QKDApp014Key
QKDApp014::GetKeyFromAppKeyBuffer (uint32_t keyType)
{
    QKDApp014::QKDApp014Key key;
    if(keyType == 0){ //Get encryption key
        NS_LOG_FUNCTION( this << "Obtaining encryption key from application key buffer!" );
        if(!m_appKeyBuffer.outboundEncKeyStore.empty()){
            std::map<std::string, QKDApp014::QKDApp014Key>::iterator it = m_appKeyBuffer.outboundEncKeyStore.begin();
            key = it->second;
            NS_LOG_FUNCTION( this << "Key" << key.keyId << key.lifetime << m_packetSize );
            if(int64_t (key.lifetime - m_packetSize) < int64_t (m_packetSize)){
                NS_LOG_FUNCTION( this << "Key " << key.keyId << " removed from application key buffer!" );
                m_appKeyBuffer.outboundEncKeyStore.erase(it);
            } else {
                it->second.lifetime = key.lifetime - m_packetSize;
            }
        } else
            NS_FATAL_ERROR ( this << "Encryption key buffer is empty!" );

    }else if(keyType == 1){ //Get authentication key
        NS_LOG_FUNCTION( this << "Obtaining authentication key from application key buffer!" );
        if(!m_appKeyBuffer.outboundAuthKeyStore.empty()){
            std::map<std::string, QKDApp014::QKDApp014Key>::iterator it = m_appKeyBuffer.outboundAuthKeyStore.begin();
            key = it->second;
            NS_LOG_FUNCTION( this << "Key " << key.keyId << " removed from applicaiton key buffer!" );
            m_appKeyBuffer.outboundAuthKeyStore.erase(it);
        } else
            NS_FATAL_ERROR ( this << "Authentication key buffer is empty!" );

    }else
        NS_FATAL_ERROR( this << "Invalid key type" << keyType 
            << "Allowed values are 0-Encryption key type, and 1-Authentication key type" );

    return key;

}

QKDApp014::QKDApp014Key
QKDApp014::GetKeyFromAppKeyBuffer (std::string keyId, std::string keyType) 
{
    NS_LOG_FUNCTION( this << keyId );
    QKDApp014::QKDApp014Key key;
    std::map<std::string, QKDApp014::QKDApp014Key>::iterator it;
    it = m_appKeyBuffer.inboundKeyStore.find(keyId);
    if(it != m_appKeyBuffer.inboundKeyStore.end()){
        key = it->second;
        if (keyType == "enc"){
            if(
                (m_encryptionTypeInt == 2 && 
                int64_t (key.lifetime - m_packetSize) < int64_t (m_packetSize)) ||
                m_encryptionTypeInt != 2
            ){ //AES expired key or OTP
                NS_LOG_FUNCTION( this << "Key " << key.keyId << " removed from inbound key buffer!" );
                m_appKeyBuffer.inboundKeyStore.erase(it);
            }else if(m_encryptionTypeInt == 2){ //AES update lifetime
                it->second.lifetime = key.lifetime - m_packetSize;
            }
        }else if(keyType == "auth"){
            NS_LOG_FUNCTION( this << "Key " << key.keyId << " removed from inbound key buffer!" );
            m_appKeyBuffer.inboundKeyStore.erase(it);
        }else
            NS_FATAL_ERROR( this << "Inalid key type as input " << keyType );
    }else
        NS_FATAL_ERROR( this << "Key" << keyId << " is missing from inbound key store" );
    
    return key;
}


/**
 * ********************************************************************************************

 *        HTTP mapping
 
 * ********************************************************************************************
 */
void
QKDApp014::MemoriesRequestKMS (uint32_t methodType, uint32_t keyType)
{
  m_httpRequestsKMS.push_back (std::make_pair (methodType, keyType));
}

void
QKDApp014::MemoriesRequestApp (std::vector<std::string> keyIds)
{
  m_httpRequestsApp.push_back (keyIds);
}

void
QKDApp014::RequestProcessedKMS ()
{
  m_httpRequestsKMS.erase (m_httpRequestsKMS.begin());
}

void
QKDApp014::RequestProcessedApp ()
{
  m_httpRequestsApp.erase (m_httpRequestsApp.begin());
}

uint32_t
QKDApp014::GetETSIMethod ()
{
  return (m_httpRequestsKMS[0]).first;
}

uint32_t
QKDApp014::GetKeyType ()
{
  return (m_httpRequestsKMS[0]).second;
}


/**
 * ********************************************************************************************

 *        APPLICATION functions
 
 * ********************************************************************************************
 */
void
QKDApp014::StartApplication (void)
{
  NS_LOG_FUNCTION ( this << m_local << m_peer << m_master );

  m_packetsSent = 0;

  if(m_encryptionTypeInt < 0 || m_encryptionTypeInt > 2){
    NS_FATAL_ERROR ("Invalid encryption type " << m_encryptionTypeInt << ". Allowed values are (0-unencrypted, 1-OTP, 2-AES)" );
  }

  if(m_authenticationTypeInt < 0 || m_authenticationTypeInt > 3){
    NS_FATAL_ERROR ("Invalid authentication type " << m_authenticationTypeInt << ". Allowed values are (0-unauthenticated, 1-VMAC, 2-MD5, 3-SHA1)" );
  }

  if(m_aesLifetime < 0)
    NS_FATAL_ERROR ("Invalid AES lifetime " << m_aesLifetime << ". The value must be larger than zero." );
  
  else if (m_aesLifetime < m_packetSize && m_aesLifetime != 0)
    NS_FATAL_ERROR ("Invalid AES lifetime " << m_aesLifetime << ". The value must be larger than one packet size " << m_packetSize );

  if (m_appState == INITIALIZED)
  { 

    SetEncryptionAndAuthenticationSettings(
      m_encryptionTypeInt, 
      m_authenticationTypeInt,
      m_authenticationTagLengthInBits
    );
    AppTransitionTree(); //Transition states
    PrepareSinkSocketFromApp(); //Create sink sockets for peer QKD applications

  } else {
    NS_FATAL_ERROR ("Invalid state " << GetAppStateString ()
                                     << " for StartApplication().");
  }

}

void
QKDApp014::StopApplication (void)
{
  NS_LOG_FUNCTION( this );
 
  if (m_sendEvent.IsRunning ())
  {
    Simulator::Cancel (m_sendEvent);
  }

  if (m_sendDataSocketApp)
    m_sendDataSocketApp->Close ();
  if (m_sinkDataSocketApp)
    m_sinkDataSocketApp->Close ();
  if (m_sendSignalingSocketApp)
    m_sendSignalingSocketApp->Close ();
  if (m_sinkSignalingSocketApp)
    m_sinkSignalingSocketApp->Close ();

  InitializeAppKeyBuffer(); //Clear app key buffer!
  if (m_sendSocketToKMS)
    m_sendSocketToKMS->Close ();
  if (m_sinkSocketFromKMS)
    m_sinkSocketFromKMS->Close ();

  NS_LOG_FUNCTION( this << "Open sockets are closed and application is stopped" );
  SwitchAppState(STOPPED);
}

void
QKDApp014::SendPacket()
{
  NS_LOG_FUNCTION( this );

  if (m_appState == READY) //Direct call from SceduleTx()
    SwitchAppState(SEND_DATA);

  if (m_appState == SEND_DATA) { //QKDApp014 can send packets only when in SEND_DATA state!

    if(!m_sendDataSocketApp) {
      PrepareSendSocketToApp(); 
    }

    bool encrypted = m_encryptionType;
    bool authenticated = m_authenticationType;
    NS_LOG_FUNCTION( this << "Enc/Auth" << encrypted << authenticated );

    //Obtain secret keys!
    QKDApp014::QKDApp014Key encKey;
    encKey.keyId = std::string(32, '0');
    QKDApp014::QKDApp014Key authKey;
    authKey.keyId = std::string(32, '0');
    
    if (encrypted) //Obtain encryption key from application key buffer!
      encKey = GetKeyFromAppKeyBuffer(0); //0 - encryption key
    if (GetAuthenticationKeySize() != 0) //Obtain authentication key from application key buffer!
      authKey = GetKeyFromAppKeyBuffer(1); //1 - authentication key

    //Decode keys from Base64!
    std::string encKeyDecoded = m_encryptor->Base64Decode(encKey.key);
    std::string authKeyDecoded = m_encryptor->Base64Decode(authKey.key);

    //Define confidential message
    std::string confidentialMsg = GetPacketContent();
    NS_LOG_FUNCTION( this << "Confidential message" << confidentialMsg.size() << confidentialMsg );
    
    std::string encryptedMsg;
    std::string authTag;
    
    if (m_useCrypto) {
      
      encryptedMsg = m_encryptor->EncryptMsg(confidentialMsg, encKeyDecoded);
      NS_LOG_FUNCTION ( this << "Encryption key" << encKey.keyId << encKeyDecoded 
        << "Encrypted message (Base64 print)" << m_encryptor->Base64Encode(encryptedMsg));
      authTag = m_encryptor->Authenticate (encryptedMsg, authKeyDecoded);
      NS_LOG_FUNCTION( this << "Authentication key" << authKey.keyId << authKeyDecoded 
        << "Authentication tag" << authTag );

    } else {

      encryptedMsg = confidentialMsg;
      authTag = GetPacketContent(32); //Use random authTag
      NS_LOG_FUNCTION ( this << "Encryption key" << encKey.keyId << encKeyDecoded );
      NS_LOG_FUNCTION( this << "Authentication key" << authKey.keyId << authKeyDecoded );

    }
    
    //Create packet with protected/unprotected data
    std::string msg = encryptedMsg;
    Ptr<Packet> packet = Create<Packet> ( (uint8_t*) msg.c_str(), msg.length() );
    NS_ASSERT (packet);
    m_authenticationTrace (packet, authTag);

    //Add qkd header!
    QKDAppHeader qHeader;
    qHeader.SetEncrypted(m_encryptionType); 
    qHeader.SetEncryptionKeyId(CreateKeyIdField(encKey.keyId));
    qHeader.SetAuthenticated(m_authenticationType);
    qHeader.SetAuthenticationKeyId(CreateKeyIdField(authKey.keyId));
    qHeader.SetAuthTag(authTag);
    qHeader.SetLength(packet->GetSize() + qHeader.GetSerializedSize());
    packet->AddHeader(qHeader);

    //Send packet!
    m_txTrace (packet, m_dstSaeId.string());
    m_sendDataSocketApp->Send (packet);
    m_packetsSent++;
    m_dataSent += packet->GetSize();

    NS_LOG_FUNCTION (this << "Sending protected packet: " << packet->GetUid() << " of size " << packet->GetSize() );
    
    SwitchAppState(READY); //Application is now ready
    CheckAppBufferState();
    //Schedule new time instance to send data!
    ScheduleTx ();
    
  } else if (m_appState == WAIT) {

    m_mxTrace (0, m_dstSaeId.string());
    ScheduleTx ();
    NS_LOG_FUNCTION( this << "Application is currently unable to send new data! QKDApp014 state" << GetAppStateString(m_appState) );
  
  }

}

void
QKDApp014::DataPacketReceivedFromApp (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION ( this << m_master << p->GetUid() << p->GetSize() << from );

  if (m_master == 0) { //Process encrypted data on Replica QKDApp014

    if (m_appState == READY) { //Replica QKDApp014 MUST be in ready state to receive data
      
      QKDAppHeader header;
      Ptr<Packet> buffer;

      auto itBuffer = m_buffer_QKDApp014.find (from);
      if (itBuffer == m_buffer_QKDApp014.end ())
        {
          itBuffer = m_buffer_QKDApp014.insert (std::make_pair (from, Create<Packet> (0))).first;
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

          m_rxTrace ( completePacket, m_dstSaeId.string() ); 
          completePacket->RemoveHeader (header);
          NS_LOG_FUNCTION(this << "RECEIVED QKDApp014 HEADER: " << header);

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
QKDApp014::ProcessDataPacketFromApp(QKDAppHeader header, Ptr<Packet> packet, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION( this );

  if (m_master == 0) { //Only Replica QKDApp014 receives encrypted data!

    uint8_t *buffer = new uint8_t[packet->GetSize ()];
    packet->CopyData(buffer, packet->GetSize ());
    std::string payload = std::string((char*)buffer, packet->GetSize ());
    delete[] buffer;

    NS_LOG_FUNCTION( this << "Replica QKDApp014 received data packet from peer QKDApp014" << m_encryptor->Base64Encode(payload) );

    SwitchAppState(DECRYPT_DATA);
    SetEncryptionAndAuthenticationSettings(header.GetEncrypted(), header.GetAuthenticated(), m_authenticationTagLengthInBits); 
    std::string decryptedMsg;
    bool authSuccessful = false;
    m_packetSize = payload.length();
    //Perform authentication first
    if (GetAuthenticationKeySize() != 0) 
    {
      //Fetch key
      QKDApp014::QKDApp014Key key;
      key = GetKeyFromAppKeyBuffer(ReadKeyIdField(header.GetAuthenticationKeyId()), "auth");
      
      if (m_useCrypto)
      {
        //Decode key
        std::string decodedKey = m_encryptor->Base64Decode(key.key);
        //Check authTag
        if (m_encryptor->CheckAuthentication(payload, header.GetAuthTag(), decodedKey)) {
          authSuccessful = true;
          NS_LOG_FUNCTION( this << "Packet successfully authenticated" );
        }
        else
          NS_LOG_FUNCTION( this << "FAILED authentication of received packet" );

      } else { //We assume packet is authenticated

        authSuccessful = true;
        NS_LOG_FUNCTION( this << "Packet authenticated" );
      }

    } else if (header.GetAuthenticated()) {

      if (m_useCrypto)
      {
        if (m_encryptor->CheckAuthentication(payload, header.GetAuthTag(), "")) {
          authSuccessful = true;
          NS_LOG_FUNCTION( this << "Packet successfully authenticated" );
        }
        else
          NS_LOG_FUNCTION( this << "FAILED authentication of received packet" );
      } else { //We assume packet is authenticated

        authSuccessful = true;
        NS_LOG_FUNCTION( this << "Packet authenticated" );
      }
    } else 
      authSuccessful = true;

    //Perform decryption
    if (header.GetEncrypted()) //Perform decryption
    {
      //Fetch key
      QKDApp014::QKDApp014Key key;
      key = GetKeyFromAppKeyBuffer(ReadKeyIdField(header.GetEncryptionKeyId()), "enc");
      if (m_useCrypto) 
      {
        //Decode key
        std::string decodedKey = m_encryptor->Base64Decode(key.key);
        NS_LOG_FUNCTION( this << decodedKey );
        //Decrypt packet
        if (authSuccessful) 
        {
          decryptedMsg = m_encryptor->DecryptMsg (payload, decodedKey);
          NS_LOG_FUNCTION( this << "Decrypted message" << decryptedMsg );
        }
      } else {

        if (authSuccessful)
          NS_LOG_FUNCTION( this << "Packet decrypted" );
      }

    } else {

      if (m_useCrypto)
        NS_LOG_FUNCTION( this << "Packet decrypted" );
      else
        NS_LOG_FUNCTION( this << "Received message" << payload );
    }

    SwitchAppState(READY);

  } else
    NS_FATAL_ERROR( this << "Only Replica QKDApp014 should receive protected packet" );
}



/**
 * ********************************************************************************************

 *        KEY MANAGEMENT functions
 
 * ********************************************************************************************
 */

void
QKDApp014::GetStatusFromKMS (uint32_t keyType)
{
  NS_LOG_FUNCTION (this << "QKDApp014 Get Status " << keyType);

  if(!m_sendSocketToKMS)
    PrepareSendSocketToKMS();
    
  if(!m_sinkSocketFromKMS)
    PrepareSinkSocketFromKMS();
 
  //SEND PACKET TO KMS - GET STATUS
   
  Ipv4Address lkmsAddress = InetSocketAddress::ConvertFrom(m_kms).GetIpv4 ();
  std::ostringstream lkmsAddressTemp; 
  lkmsAddress.Print(lkmsAddressTemp); //IPv4Address to string
  std::string headerUri = "http://" + lkmsAddressTemp.str ();

  if(keyType)
    headerUri += "/api/v1/keys/" + m_ksid_enc.string() + "/status";
  else
    headerUri += "/api/v1/keys/" + m_ksid_auth.string() + "/status";


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

  MemoriesRequestKMS(0);
  m_txKmsTrace (packet);
  m_sendSocketToKMS->Send (packet);

}

void
QKDApp014::GetKeysFromKMS (uint32_t keyType)
{
  NS_LOG_FUNCTION( this << "QKDApp014 Get Key" << m_master );

  if(!m_sendSocketToKMS)
    PrepareSendSocketToKMS();
  if(!m_sinkSocketFromKMS)
    PrepareSinkSocketFromKMS();

  uint32_t numberOfKeys = m_numberOfKeysKMS; //@toDo dinamic behaviour of numberOfKeys!
  if (numberOfKeys <= 0) //Application basic check of user input!
    NS_FATAL_ERROR( this << "Invalid application parameter - m_numberOfKeysKMS" << numberOfKeys );

  if (keyType == 0) //Get Key request for encryption keys!
  {

    uint32_t sizeOfKeys = GetEncryptionKeySize(); //Size of a key based on defined encryption algorithm
    NS_LOG_FUNCTION( this << "Size of encryption keys" << sizeOfKeys );

    std::vector<std::string> additional_slave_SAE_IDs {}; //No additional Replica SAEs
    bool useGet = false; //Is application allowed to use GET method for such request?
    bool usedMethod; //Used method: false -> POST, true -> GET (if possible)

    if (additional_slave_SAE_IDs.empty() && useGet)
      usedMethod = true;
    else
      usedMethod = false;
    
    //Create HTTP header - ETSI014 Get Key request!
    Ipv4Address lkmsAddress = InetSocketAddress::ConvertFrom(m_kms).GetIpv4 ();
    std::ostringstream lkmsAddressTemp; 
    lkmsAddress.Print(lkmsAddressTemp); //IPv4Address to string
    std::string headerUri = "http://" + lkmsAddressTemp.str ();
    headerUri += "/api/v1/keys/" + m_ksid_enc.string() + "/enc_keys";

    
    std::string requestBody;
    HTTPMessage httpMessage; 
    if (usedMethod) 
    {
      requestBody = {};

      //Update header URI
      headerUri += "/number/" + std::to_string(numberOfKeys);
      headerUri += "/size/" + std::to_string(sizeOfKeys);
      httpMessage.CreateRequest(headerUri, "GET");
    } else {
 
      nlohmann::json jkeyrequest;
      jkeyrequest["number"] = numberOfKeys;
      jkeyrequest["size"] = sizeOfKeys;
      if (!additional_slave_SAE_IDs.empty()){
        jkeyrequest["additional_slave_SAE_IDs"] = additional_slave_SAE_IDs;
      } 
      requestBody = jkeyrequest.dump();
 
      httpMessage.CreateRequest(headerUri, "POST", requestBody);
    }

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

    //Store request to HTTP requests store (to be able to map responses)
    MemoriesRequestKMS(1, 0); //(method type, key type)
    m_txKmsTrace (packet);
    m_sendSocketToKMS->Send (packet);

  } else if (keyType == 1)
  {

    uint32_t sizeOfKeys = GetAuthenticationKeySize(); //Size of a key based on defined authentication algorithm
    NS_LOG_FUNCTION( this << "Size of authentication keys" << sizeOfKeys );

    std::vector<std::string> additional_slave_SAE_IDs {}; //No additional Replica SAEs
    bool useGet = false; //Is application allowed to use GET method for such request?
    bool usedMethod; //Used method: false -> POST, true -> GET

    if (additional_slave_SAE_IDs.empty() && useGet)
      usedMethod = true;
    else
      usedMethod = false;
    
    //Create HTTP header - ETSI014 Get Key request!
    Ipv4Address lkmsAddress = InetSocketAddress::ConvertFrom(m_kms).GetIpv4 ();
    std::ostringstream lkmsAddressTemp; 
    lkmsAddress.Print(lkmsAddressTemp); //IPv4Address to string
    std::string headerUri = "http://" + lkmsAddressTemp.str (); 
    headerUri += "/api/v1/keys/" + m_ksid_auth.string() + "/enc_keys";

    HTTPMessage httpMessage; 
    std::string requestBody;
    if (usedMethod) 
    {
      //Update header URI
      headerUri += "/number/" + std::to_string(numberOfKeys);
      headerUri += "/size/" + std::to_string(sizeOfKeys);
      requestBody = {};
      httpMessage.CreateRequest(headerUri, "GET");    

    } else {
 
      nlohmann::json jkeyrequest;
      jkeyrequest["number"] = numberOfKeys;
      jkeyrequest["size"] = sizeOfKeys;
      if (!additional_slave_SAE_IDs.empty()){
        jkeyrequest["additional_slave_SAE_IDs"] = additional_slave_SAE_IDs;
      }

      requestBody = jkeyrequest.dump();
      httpMessage.CreateRequest(headerUri, "POST", requestBody);   

    }

    //SEND PACKET
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

    MemoriesRequestKMS(1, 1);
    m_txKmsTrace (packet);
    m_sendSocketToKMS->Send (packet);

  } else {
    NS_FATAL_ERROR( this << "Invalid key type" << keyType << "Available values are 0-Encryption key type, and 1-Authentication key type" );
  }

}

void
QKDApp014::GetKeyWithKeyIDs() 
{
  NS_LOG_FUNCTION( this << "QKDApp014 Get key with key IDs" << m_master );

  if(!m_sendSocketToKMS)
   PrepareSendSocketToKMS();
  
  if(!m_sinkSocketFromKMS)
    PrepareSinkSocketFromKMS();

  std::string ksid;
  if (m_keyIDs.contains("ksid"))
    ksid = m_keyIDs["ksid"];

  //Create HTTP header
  Ipv4Address lkmsAddress = InetSocketAddress::ConvertFrom(m_kms).GetIpv4 ();
  std::ostringstream lkmsAddressTemp; 
  lkmsAddress.Print(lkmsAddressTemp); //IPv4Address to string
  std::string headerUri = "http://" + lkmsAddressTemp.str (); 

  std::string msg = m_keyIDs.dump(); //Json - KeyIDs is already in m_keyIDs variable!
  headerUri += "/api/v1/keys/"+ksid+"/dec_keys";
  
  NS_LOG_FUNCTION(this << "ccc:" << m_keyIDs);
  
  //Create packet
  HTTPMessage httpMessage; 
  httpMessage.CreateRequest(headerUri, "POST", msg);
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

  MemoriesRequestKMS(2);
  m_txKmsTrace (packet);
  m_sendSocketToKMS->Send (packet);

}

void
QKDApp014::PacketReceivedFromKMS (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  std::string receivedStatus = p->ToString();
  NS_LOG_FUNCTION ( this << "\n\n\n" << p->GetUid() << p->GetSize() << receivedStatus << from );

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
      m_rxKmsTrace (completePacket); 
      ProcessResponseFromKMS(request2, completePacket, socket); 
    }
    
    NS_LOG_FUNCTION(this << "Croped HTTP message: " << request2.ToString());
    NS_LOG_FUNCTION(this << "Remains in the buffer " << buffer->GetSize () );
    break;
  } 
}

void 
QKDApp014::ProcessResponseFromKMS(HTTPMessage& header, Ptr<Packet> packet, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION (this << packet->GetUid() << packet->GetSize());
 
  std::string payload = header.GetMessageBodyString();
  //Map response to request
  uint32_t methodType = GetETSIMethod();
  //Process json data structure of KMS response!
  nlohmann::json jresponse;
  try {

    jresponse = nlohmann::json::parse(payload);
    
    if (methodType == 0) {
      
      ProcessStatusResponse(header, jresponse);
    
    } else if (methodType == 1){ 
 
      ProcessGetKeyResponse(header, jresponse);

    } else if (methodType == 2) {
  
      ProcessGetKeyWithKeyIDsResponse(header, jresponse);

    } else {
      NS_FATAL_ERROR (this << "Invalid ETSI method used in request");
    }

  }  catch (...) { 
    NS_FATAL_ERROR (this << "JSON parse error!");
  }
}

void
QKDApp014::ProcessStatusResponse (HTTPMessage& header, nlohmann::json jstatusResponse)
{

  HTTPMessage::HttpStatus responseStatus = header.GetStatus();
  if (
    responseStatus == HTTPMessage::HttpStatus::BadRequest || 
    responseStatus == HTTPMessage::HttpStatus::Unauthorized || 
    responseStatus == HTTPMessage::HttpStatus::ServiceUnavailable
  ) {

    NS_FATAL_ERROR( this << "QKDApp014 received ERROR status information from local KMS" << jstatusResponse.dump() );

  } else if (responseStatus == HTTPMessage::HttpStatus::Ok){
        
    NS_LOG_FUNCTION( this << "QKDApp014 received status information from local KMS" );
    //Check the AppBufferState
    CheckAppBufferState();
  
  } else {
    NS_FATAL_ERROR( this << "Unsupported error status code" << responseStatus << "of response.");
  }

  RequestProcessedKMS(); //Remove request from store.

}

void
QKDApp014::ProcessGetKeyResponse (HTTPMessage& header, nlohmann::json jGetKeyResponse)
{
  NS_LOG_FUNCTION( this );

  if(jGetKeyResponse.empty())
      NS_FATAL_ERROR(this << "KMS response on GET_KEY is empty!");

  std::string ksid;
  if (jGetKeyResponse.contains("ksid"))
    ksid = jGetKeyResponse["ksid"];

  HTTPMessage::HttpStatus responseStatus = header.GetStatus();
  if (
    responseStatus == HTTPMessage::HttpStatus::BadRequest || 
    responseStatus == HTTPMessage::HttpStatus::Unauthorized || 
    responseStatus == HTTPMessage::HttpStatus::ServiceUnavailable
  ) {

    if (jGetKeyResponse.contains("message"))
    {
      if (jGetKeyResponse["message"] ==  std::string {"requested parameters do not adhere to KMS rules"}) 
        NS_FATAL_ERROR( this << jGetKeyResponse.dump());
      else if (jGetKeyResponse["message"] == std::string {"insufficient amount of key material"})
        ScheduleAction(Time (m_waitInsufficient), "CheckAppBufferState");
      else if (jGetKeyResponse["message"] == std::string {"keys are being transformed"})
        ScheduleAction(Time (m_waitTransform), "CheckAppBufferState"); //Results in two times schedule when enc and auth! Fixed in ScheduleAction
      else
        NS_FATAL_ERROR( this << "uknown error message");
    } else {
      NS_FATAL_ERROR( this << "uknown error message");
    }
  
  } else if (responseStatus == HTTPMessage::HttpStatus::Ok){
        
    NS_LOG_FUNCTION( this << "Primary QKDApp014 received requested number of keys" << jGetKeyResponse.dump() );
    
    uint32_t keyType = GetKeyType();
    //Push obtained keys to temporary key buffer, until they are negotiated with peer QKDApp014.
    QKDApp014::QKDApp014Key key;
    std::vector<std::string> keysToNegotiate;
    for (nlohmann::json::iterator it = jGetKeyResponse["keys"].begin(); it != jGetKeyResponse["keys"].end(); ++it) {
      key.key = (it.value())["key"];
      key.keyId = (it.value())["key_ID"];
      key.keyType = keyType;
      if(keyType == 0 && m_encryptionType == 2)
          key.lifetime = m_aesLifetime;
      else
          key.lifetime = m_packetSize;
      (m_appKeyBuffer.temporaryKeyStoreMaster).insert(std::make_pair(key.keyId, key));
      keysToNegotiate.push_back(key.keyId);

      m_obtainedKeyMaterialTrace ((m_encryptor->Base64Decode(key.key)).size() * 8);
    }
    
    PrintTemporaryKeyStoreContent();
    ExchangeInfoMessages(ksid, keysToNegotiate);
  
  } else {
    NS_FATAL_ERROR( this << "Unsupported error status code" << responseStatus << "of response.");
  }

  RequestProcessedKMS(); //Remove request from store.

}

void
QKDApp014::ProcessGetKeyWithKeyIDsResponse(HTTPMessage& header, nlohmann::json jGetKeyWithKeyIDsResponse)
{

  NS_LOG_FUNCTION( this );

  std::string ksid;
  if (jGetKeyWithKeyIDsResponse.contains("ksid"))
    ksid = jGetKeyWithKeyIDsResponse["ksid"];

  HTTPMessage::HttpStatus responseStatus = header.GetStatus();
  if (
    responseStatus == HTTPMessage::HttpStatus::BadRequest || 
    responseStatus == HTTPMessage::HttpStatus::Unauthorized || 
    responseStatus == HTTPMessage::HttpStatus::ServiceUnavailable
  ) {
    
      NS_FATAL_ERROR( this << "Replica QKDApp014 received ERROR response on key request" << jGetKeyWithKeyIDsResponse.dump() );

      ExchangeInfoMessages(ksid, {}, responseStatus);
    
    } else if (responseStatus == HTTPMessage::HttpStatus::Ok) {
      
      NS_LOG_FUNCTION( this << "Replica QKDApp014 received requested keys" << jGetKeyWithKeyIDsResponse.dump() );
      
      //Replica application directly stores the keys in application key buffer!
      QKDApp014::QKDApp014Key key;
      for (nlohmann::json::iterator it = jGetKeyWithKeyIDsResponse["keys"].begin(); it != jGetKeyWithKeyIDsResponse["keys"].end(); ++it) {
        
        key.key = (it.value())["key"];
        key.keyId = (it.value())["key_ID"];
        key.lifetime = m_aesLifetime; //In case AES is used!
        AddKeyInInboundKeyStore(key);

        m_obtainedKeyMaterialTrace ((m_encryptor->Base64Decode(key.key)).size() * 8);
      }
      
      ExchangeInfoMessages(ksid, {}, responseStatus);

    } else {
      NS_FATAL_ERROR( this << "Unsupported HTTP status code" << responseStatus << "of response");
    }

    RequestProcessedKMS(); //Remove request from store.

}

void
QKDApp014::SignalingPacketReceivedFromApp (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket)
{
  std::string receivedStatus = p->ToString();
  NS_LOG_FUNCTION ( this << "\n\n\n" << p->GetUid() << p->GetSize() << receivedStatus << from );

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
      m_rxSigTrace (completePacket);
      ProcessSignalingPacketFromApp(request2, completePacket, socket); 
    }
    NS_LOG_FUNCTION(this << "Croped HTTP message: " << request2.ToString());
    NS_LOG_FUNCTION(this << "Remains in the buffer " << buffer->GetSize () );
    break;
  } 
}

void
QKDApp014::ProcessSignalingPacketFromApp (HTTPMessage& header, Ptr<Packet> packet, Ptr<Socket> socket)
{
  NS_LOG_FUNCTION( this << packet->GetSize() << packet->GetUid() );

  if (m_master == 1) { //Primary QKDApp014 processes received signaling packet from Replica QKDApp014.
    
    NS_LOG_FUNCTION( this << "APP-SIGNALING: Primary QKDApp014 received response from Replica QKDApp014. Packet ID" << packet->GetUid());

    std::vector<std::string> keyIds = m_httpRequestsApp[0]; //Take first request in store (mapping of response to request)
    if (header.GetStatus() == HTTPMessage::HttpStatus::Ok) { //Keys successfully negotiated! Primary QKDApp014 adds keys to enc/auth key store for use.

      PrintTemporaryKeyStoreContent();

      for (uint i = 0; i < keyIds.size(); i++) {
        NS_LOG_FUNCTION( this << keyIds[i] << i << keyIds.size()  );
        
        std::map<std::string, QKDApp014::QKDApp014Key>::iterator it;
        it = m_appKeyBuffer.temporaryKeyStoreMaster.find(keyIds[i]);

        if (it == m_appKeyBuffer.temporaryKeyStoreMaster.end()){

          NS_LOG_DEBUG( this << "Key " << keyIds[i] << " was not found in the temporary key store!" );
        
        }else{
          if ((it->second).keyType == 0)
            AddEncKeyInKeyStore(it->second);
          else
            AddAuthKeyInKeyStore(it->second);
        }
      }

      RemoveKeysFromTemporaryKeyStore(keyIds);
      PrintTemporaryKeyStoreContent();
      PrintAppBufferStatusInformation();
      CheckAppState();


    } else { //Possible collision on requested key!

      NS_LOG_DEBUG ( this << "The attempt to negotiate keys failed.");
      //Only the request for this particular key type must be repeated
      if(!m_internalAppWait){ //Only repeat the request if the CheckAppBufferState is not scheduled!
        NS_LOG_FUNCTION(this << "Application is submitting a new GET_KEY request ...");
        //First find a key type! Take a single keyID (first one) ->
        std::string keyID = m_httpRequestsApp[0][0];
        //Find this key in the temporary key store to determine the type ->
        std::map<std::string, QKDApp014::QKDApp014Key>::iterator it = m_appKeyBuffer.temporaryKeyStoreMaster.find(keyID);
        if(it!=m_appKeyBuffer.temporaryKeyStoreMaster.end()){
          GetKeysFromKMS(it->second.keyType); //Try to aquire and negotiate a new key material.
        }else
          NS_LOG_DEBUG(this << "Key" << keyID << "was not found in the temporary key store!");
      }
      RemoveKeysFromTemporaryKeyStore(keyIds); //Remove keys from the temporary key store!
      PrintTemporaryKeyStoreContent(); //Check
    }

    RequestProcessedApp();   

  } else { //Replica QKDApp014 processes received signaling packet from Primary QKDApp014.

    
    std::string payload = header.GetMessageBodyString();
    nlohmann::json jKeyIDs;
    
    try {

      jKeyIDs = nlohmann::json::parse(payload);

      NS_LOG_FUNCTION( this << "APP-SIGNALING: Replica QKDApp014 received proposal from Primary QKDApp014. Packet ID" << packet->GetUid() << jKeyIDs);

      m_keyIDs = jKeyIDs; //Use m_keyIDs to make GetKeyWithKeyIDs!
      GetKeyWithKeyIDs();

    } catch(...) {
      NS_LOG_FUNCTION( this << "JSON parse error" );
    }

  }
}

void
QKDApp014::ExchangeInfoMessages (std::string ksid, std::vector<std::string> keyIds, HTTPMessage::HttpStatus statusCode) 
{
  
  if (!m_sendSignalingSocketApp)
    PrepareSendSocketToApp();
  if (!m_sinkSignalingSocketApp)
    PrepareSinkSocketFromApp();

  if(m_master) { //Primary QKDApp014 sends proposal of keys to Replica QKDApp014.

    nlohmann::json key_IDs;
    key_IDs["ksid"] = ksid;
    for (uint i = 0; i < keyIds.size(); i++) {
      key_IDs["key_IDs"].push_back({ {"key_ID", keyIds[i] } });
    }
    
    std::string msg = key_IDs.dump();

    //Create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateRequest("/keys/key_ids", "POST", msg);
    std::string hMessage = httpMessage.ToString(); 
    Ptr<Packet> packet = Create<Packet> (
      (uint8_t*) (hMessage).c_str(),
      hMessage.size()
    ); 
    NS_ASSERT (packet);

    MemoriesRequestApp(keyIds);
    m_txSigTrace (packet);
    m_sendSignalingSocketApp->Send(packet);
    m_packetsSent++;
    m_dataSent += packet->GetSize();
    NS_LOG_FUNCTION(this << "APP-SIGNALING: Primary QKDApp014 sends proposal to Replica QKDApp014. Packet ID" << packet->GetUid() << packet->GetSize());

  } else { //Replica QKDApp014 sends response to Primary QKDApp014.

    //create packet
    HTTPMessage httpMessage; 
    httpMessage.CreateResponse(statusCode);
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
    NS_LOG_FUNCTION( this << "APP-SIGNALING: Replica QKDApp014 sends respond to Primary QKDApp014. Packet ID" << packet->GetUid() );

  }
}



/**
 * ********************************************************************************************

 *        STATE functions
 
 * ********************************************************************************************
 */

/*
 * \brief QKD App state transitions (Data transmision)
 */
void
QKDApp014::AppTransitionTree (void)
{
  NS_LOG_FUNCTION( this  );

  if (m_master) //Data transmision state transition for Primary QKDApp014
  {

    if (m_appState == INITIALIZED) {
      NS_LOG_FUNCTION( this << GetEncryptionKeySize() << GetAuthenticationKeySize() );
      if (GetEncryptionKeySize() == 0 && GetAuthenticationKeySize() == 0) //No initial key material needed!
      {
        SwitchAppState(READY);
        PrepareSendSocketToApp();
        SendPacket(); //Imidiatly send packet
      } else { //Obtain status information from KMS, obtain initial key material!
        SwitchAppState(WAIT);
        PrepareSendSocketToKMS();

        if(GetEncryptionKeySize() > 0) GetStatusFromKMS(0); //First call Get Status
        if(GetAuthenticationKeySize() > 0) GetStatusFromKMS(1); //First call Get Status

        SendPacket(); //It will result in schedule
      }
    } else {
      NS_FATAL_ERROR( this << "Invalid entry state" << m_appState <<
                              "for AppTransitionTree()!");
    }

  } else if (!m_master) { //Data transmision state transition for Replica QKDApp014
    
    if (m_appState == INITIALIZED) {
      SwitchAppState(READY);
    } else {
      NS_FATAL_ERROR( this << "Invalid entry state" << m_appState <<
                              "for AppTransitionTree()!");
    }

  }
}


QKDApp014::QKDApp014State
QKDApp014::GetAppState () const
{
  return m_appState;
}

std::string
QKDApp014::GetAppStateString (QKDApp014::QKDApp014State state)
{
  switch (state)
    {
    case NOT_STARTED:
      return "NOT_STARTED";
      break;
    case INITIALIZED:
      return "INITIALIZED";
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
QKDApp014::GetAppStateString () const
{
  return GetAppStateString (m_appState);
}

void
QKDApp014::SwitchAppState(QKDApp014::QKDApp014State state)
{

  const std::string oldState = GetAppStateString ();
  const std::string newState = GetAppStateString (state);
 
  
  bool found = false;
  for (std::multimap<std::string, std::string>::iterator iter =
    m_transitionMatrix.begin (); 
    iter != m_transitionMatrix.end (); iter++
  ){
    if(iter->first == oldState && iter->second == newState){    
      m_appState = state;
      NS_LOG_DEBUG (this << " QKDApp014 " << oldState << " --> " << newState << ".");
      m_stateTransitionTrace (oldState, newState);
      found = true;
    } 
  }

  if(found == false) {
    NS_FATAL_ERROR ("Unsupported transition from " << oldState << " to " << newState);
  }
  

}

/**
 * ********************************************************************************************

 *        ADDTIONAL functions
 
 * ********************************************************************************************
 */

void 
QKDApp014::SetEncryptionAndAuthenticationSettings(
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
QKDApp014::GetPacketContent(uint32_t msgLength)
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

std::string
QKDApp014::CreateKeyIdField (std::string keyId)
{
    keyId.erase(std::remove(keyId.begin(), keyId.end(), '-'), keyId.end());
    return keyId;
}

std::string
QKDApp014::ReadKeyIdField (std::string keyId)
{
    NS_LOG_FUNCTION(this << keyId);
    keyId.insert(8, "-");
    keyId.insert(13, "-");
    keyId.insert(18, "-");
    keyId.insert(23, "-");
    NS_LOG_FUNCTION(this << keyId);
    return keyId;
}

uint32_t 
QKDApp014::GetEncryptionKeySize()
{

  NS_LOG_FUNCTION(this << CryptoPP::AES::DEFAULT_KEYLENGTH);
  
  switch (m_encryptionType)
  {
    case QKDEncryptor::UNENCRYPTED:
      return 0;
      break;
    case QKDEncryptor::QKDCRYPTO_OTP:
      return m_packetSize * 8; //This will work great for Primary QKDApp014, Replica QKDApp014 needs to calculate for itself this!
      break;
    case QKDEncryptor::QKDCRYPTO_AES: 
      return CryptoPP::AES::MAX_KEYLENGTH * 8; //In bits 256!
      break;
  }

  return 0;

}

uint32_t
QKDApp014::GetAuthenticationKeySize()
{
  switch (m_authenticationType)
  {
    case QKDEncryptor::UNAUTHENTICATED:
      return 0;
      break;
    case QKDEncryptor::QKDCRYPTO_AUTH_VMAC:
      return CryptoPP::AES::BLOCKSIZE * 8; //In bits //Before: m_authenticationTagLengthInBits - 32B?
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


 
} // Namespace ns3
