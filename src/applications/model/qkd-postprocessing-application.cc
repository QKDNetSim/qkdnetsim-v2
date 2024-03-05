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
 * Author: Miralem Mehic <miralem.mehic@ieee.org>
 */ 

#include "ns3/address.h"
#include "ns3/node.h"
#include "ns3/nstime.h"
#include "ns3/socket.h"
#include "ns3/simulator.h"
#include "ns3/packet.h"
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"   
#include "qkd-postprocessing-application.h"
#include <iostream>
#include <fstream> 
#include <string>

namespace ns3 {

  NS_LOG_COMPONENT_DEFINE ("QKDPostprocessingApplication");

  NS_OBJECT_ENSURE_REGISTERED (QKDPostprocessingApplication);

  TypeId
  QKDPostprocessingApplication::GetTypeId (void)
  {
    static TypeId tid = TypeId ("ns3::QKDPostprocessingApplication")
      .SetParent<Application> ()
      .SetGroupName("Applications")
      .AddConstructor<QKDPostprocessingApplication> () 
      .AddAttribute ("KeySizeInBits", "The amount of data to be added to QKD Buffer (in bits).",
                     UintegerValue (8192),
                     MakeUintegerAccessor (&QKDPostprocessingApplication::m_keySizeInBits),
                     MakeUintegerChecker<uint32_t> ())
      .AddAttribute ("KeyRate", "The average QKD key rate in bps.",
                     DataRateValue (DataRate ("1000bps")),
                     MakeDataRateAccessor (&QKDPostprocessingApplication::m_keyRate),
                     MakeDataRateChecker ())
      .AddAttribute ("DataRate", "The average data rate of communication.",
                     DataRateValue (DataRate ("650kbps")), //3.3Mbps //10kbps
                     MakeDataRateAccessor (&QKDPostprocessingApplication::m_dataRate),
                     MakeDataRateChecker ())
      .AddAttribute ("PacketSize", "The size of packets sent in post-processing state",
                     UintegerValue (320), //280
                     MakeUintegerAccessor (&QKDPostprocessingApplication::m_pktSize),
                     MakeUintegerChecker<uint32_t> ())  
      .AddAttribute ("MaxSiftingPackets", "The size of packets sent in sifting state",
                     UintegerValue (5), ///190
                     MakeUintegerAccessor (&QKDPostprocessingApplication::m_maxPackets_sifting),
                     MakeUintegerChecker<uint32_t> ())   

      .AddAttribute ("Protocol", "The type of protocol to use (TCP by default).",
                     TypeIdValue (TcpSocketFactory::GetTypeId ()),
                     MakeTypeIdAccessor (&QKDPostprocessingApplication::m_tid),
                     MakeTypeIdChecker ()) 
      .AddAttribute ("ProtocolSifting", "The type of protocol to use for sifting (UDP by default).",
                     TypeIdValue (UdpSocketFactory::GetTypeId ()),
                     MakeTypeIdAccessor (&QKDPostprocessingApplication::m_tidSifting),
                     MakeTypeIdChecker ()) 

      .AddAttribute ("Remote", "The address of the destination",
                     AddressValue (),
                     MakeAddressAccessor (&QKDPostprocessingApplication::m_peer),
                     MakeAddressChecker ())
      .AddAttribute ("Local", "The local address on which to bind the listening socket.",
                     AddressValue (),
                     MakeAddressAccessor (&QKDPostprocessingApplication::m_local),
                     MakeAddressChecker ()) 
      .AddAttribute ("Remote_Sifting", "The address of the destination for sifting traffic.",
                     AddressValue (),
                     MakeAddressAccessor (&QKDPostprocessingApplication::m_peer_sifting),
                     MakeAddressChecker ())
      .AddAttribute ("Local_Sifting", "The local address on which to bind the listening sifting socket.",
                     AddressValue (),
                     MakeAddressAccessor (&QKDPostprocessingApplication::m_local_sifting),
                     MakeAddressChecker ()) 
      .AddAttribute ("Local_KMS", "The local KSM address.",
                     AddressValue (),
                     MakeAddressAccessor (&QKDPostprocessingApplication::m_kms),
                     MakeAddressChecker ()) 
      .AddTraceSource ("Tx", "A new packet is created and is sent",
                     MakeTraceSourceAccessor (&QKDPostprocessingApplication::m_txTrace),
                     "ns3::QKDPostprocessingApplication::Tx")
      .AddTraceSource ("Rx", "A packet has been received",
                     MakeTraceSourceAccessor (&QKDPostprocessingApplication::m_rxTrace),
                     "ns3::QKDPostprocessingApplication::Rx")
      .AddTraceSource ("TxKMS", "A new packet is created and is sent to LKMS",
                     MakeTraceSourceAccessor (&QKDPostprocessingApplication::m_txTraceKMS),
                     "ns3::QKDPostprocessingApplication::TxKMS")
      .AddTraceSource ("RxKMS", "A packet has been received from LKMS",
                     MakeTraceSourceAccessor (&QKDPostprocessingApplication::m_rxTraceKMS),
                     "ns3::QKDPostprocessingApplication::RxLKMS")
    ;
    return tid;
  }

  QKDPostprocessingApplication::QKDPostprocessingApplication ()
  {     
    m_connected = false;
    m_random = CreateObject<UniformRandomVariable> ();
    m_packetNumber = 1; 
    m_totalRx = 0;   
    m_packetNumber_sifting = 0;  
    GenerateRandomKeyId();
    m_appId = GenerateRandomString(8);
  }

  QKDPostprocessingApplication::~QKDPostprocessingApplication ()
  {
    NS_LOG_FUNCTION (this);
  }

  void 
  QKDPostprocessingApplication::GenerateRandomKeyId(){
    m_keyId = m_random->GetValue (0, 99999999);
  }


  uint32_t QKDPostprocessingApplication::GetTotalRx () const
  {
    NS_LOG_FUNCTION (this);
    return m_totalRx;
  }

  Ptr<Node> 
  QKDPostprocessingApplication::GetSrc(){
    return m_src;
  }
  void 
  QKDPostprocessingApplication::SetSrc(Ptr<Node> node){
    NS_LOG_FUNCTION (this << node->GetId());
    m_src = node;
  }

  Ptr<Node> 
  QKDPostprocessingApplication::GetDst(){
    return m_dst;
  }
  void 
  QKDPostprocessingApplication::SetDst(Ptr<Node> node){
    NS_LOG_FUNCTION (this << node->GetId());
    m_dst = node;
  }

  std::list<Ptr<Socket> >
  QKDPostprocessingApplication::GetAcceptedSockets (void) const
  {
    NS_LOG_FUNCTION (this);
    return m_sinkSocketList;
  }

  Ptr<Socket>
  QKDPostprocessingApplication::GetSinkSocket (void) const
  {
    NS_LOG_FUNCTION (this);
    return m_sinkSocket;
  }
   
  Ptr<Socket>
  QKDPostprocessingApplication::GetSendSocket (void) const
  {
    NS_LOG_FUNCTION (this);
    return m_sendSocket;
  }

  void
  QKDPostprocessingApplication::SetSocket (std::string type, Ptr<Socket> socket, bool isMaster)
  {
      NS_LOG_FUNCTION (this << type << socket << isMaster);
      if(type == "send"){//send app
        m_sendSocket = socket; 
      }else{ // sink app
        m_sinkSocket = socket; 
      } 
      m_master = isMaster;
  }
   
  void
  QKDPostprocessingApplication::SetSiftingSocket (std::string type, Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION (this << type << socket);
    if(type == "send"){//send app
      m_sendSocket_sifting = socket; 
    }else{ // sink app
      m_sinkSocket_sifting = socket; 
    } 
  }

  void
  QKDPostprocessingApplication::DoDispose (void)
  {
    NS_LOG_FUNCTION (this);

    m_sendSocket = 0;
    m_sinkSocket = 0;
    m_sendSocket_sifting = 0;
    m_sinkSocket_sifting = 0; 

    m_sinkSocketList.clear ();
    Simulator::Cancel (m_sendEvent);
    // chain up
    Application::DoDispose ();
  }

  // Application Methods
  void QKDPostprocessingApplication::StartApplication (void) // Called at time specified by Start
  {
    NS_LOG_FUNCTION (this);
    NS_ASSERT (m_keySizeInBits > 0);
    
    // SINK socket settings
    if (!m_sinkSocket) m_sinkSocket = Socket::CreateSocket (GetNode (), m_tid);  
    InetSocketAddress sinkAddress = InetSocketAddress (
      Ipv4Address::GetAny (), 
      InetSocketAddress::ConvertFrom (m_local).GetPort ()
    );  
    if (m_sinkSocket->Bind (sinkAddress) == -1) NS_FATAL_ERROR ("Failed to bind socket");
    m_sinkSocket->Listen ();
    m_sinkSocket->ShutdownSend ();
    m_sinkSocket->SetRecvCallback (MakeCallback (&QKDPostprocessingApplication::HandleRead, this));
    m_sinkSocket->SetAcceptCallback (
      MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
      MakeCallback (&QKDPostprocessingApplication::HandleAccept, this)
    );
    m_sinkSocket->SetCloseCallbacks (
      MakeCallback (&QKDPostprocessingApplication::HandlePeerClose, this),
      MakeCallback (&QKDPostprocessingApplication::HandlePeerError, this)
    ); 

    // SEND socket settings
    if (!m_sendSocket) m_sendSocket = Socket::CreateSocket (GetNode (), m_tid);
    Ptr<Ipv4L3Protocol> ipv4 = GetNode()->GetObject<Ipv4L3Protocol> ();
    uint32_t interface = ipv4->GetInterfaceForAddress( InetSocketAddress::ConvertFrom (m_local).GetIpv4 () );
    Ptr<NetDevice> netDevice = ipv4->GetNetDevice(interface);
    //m_sendSocket->BindToNetDevice (netDevice);
    m_sendSocket->ShutdownRecv (); 
    m_sendSocket->SetConnectCallback (
      MakeCallback (&QKDPostprocessingApplication::ConnectionSucceeded, this),
      MakeCallback (&QKDPostprocessingApplication::ConnectionFailed, this)
    ); 
    m_sendSocket->SetDataSentCallback (
      MakeCallback (&QKDPostprocessingApplication::DataSend, this)
    );
    m_sendSocket->TraceConnectWithoutContext ("RTT", MakeCallback (&QKDPostprocessingApplication::RegisterAckTime, this)); 
    m_sendSocket->Connect (m_peer); 
    
    NS_LOG_FUNCTION(
      this << 
      "Connecting QKDApp (" << 
      InetSocketAddress::ConvertFrom (m_peer).GetIpv4 () << " port " << InetSocketAddress::ConvertFrom (m_peer).GetPort () <<
      " from " <<
      InetSocketAddress::ConvertFrom (m_local).GetIpv4 () << " port " << InetSocketAddress::ConvertFrom (m_local).GetPort ()
    );
 


    /****   SIFTING SOCKETS    ****/
    // SINK socket settings
    if (!m_sinkSocket_sifting) m_sinkSocket_sifting = Socket::CreateSocket (GetNode (), m_tidSifting);
    m_sinkSocket_sifting->Bind (m_local_sifting); 
    m_sinkSocket_sifting->Listen ();
    m_sinkSocket_sifting->ShutdownSend ();
    m_sinkSocket_sifting->SetRecvCallback (MakeCallback (&QKDPostprocessingApplication::HandleReadSifting, this));

    // SEND socket settings
    if (!m_sendSocket_sifting) m_sendSocket_sifting = Socket::CreateSocket (GetNode (), m_tidSifting);
    m_sendSocket_sifting->Connect (m_peer_sifting);  
    m_sendSocket_sifting->ShutdownRecv (); 



    /****   KMS SOCKETS    ****/
    // SINK socket settings
    if (!m_sinkSocketKMS) m_sinkSocketKMS = Socket::CreateSocket (GetNode (), m_tid);
    uint32_t portKMS = InetSocketAddress::ConvertFrom (m_kms).GetPort (); 
    if (m_sinkSocketKMS->Bind (m_kms) == -1) NS_FATAL_ERROR ("Failed to bind socket");
    m_sinkSocketKMS->Listen ();
    m_sinkSocketKMS->ShutdownSend ();
    m_sinkSocketKMS->SetRecvCallback (MakeCallback (&QKDPostprocessingApplication::HandleReadKMS, this));
    m_sinkSocketKMS->SetAcceptCallback (
        MakeNullCallback<bool, Ptr<Socket>, const Address &> (),
        MakeCallback (&QKDPostprocessingApplication::HandleAcceptKMS, this));
    m_sinkSocketKMS->SetCloseCallbacks (
        MakeCallback (&QKDPostprocessingApplication::HandlePeerCloseKMS, this),
        MakeCallback (&QKDPostprocessingApplication::HandlePeerErrorKMS, this)); 

    // SEND socket settings
    if (!m_sendSocketKMS) m_sendSocketKMS = Socket::CreateSocket (GetNode (), m_tid);
    Ipv4Address localIpv4 = InetSocketAddress::ConvertFrom (m_local).GetIpv4 ();
    InetSocketAddress senderKMS = InetSocketAddress (
      localIpv4, 
      portKMS
    ); 
    NS_LOG_FUNCTION(
      this << 
      "Connecting KMS (" << 
      InetSocketAddress::ConvertFrom (m_kms).GetIpv4 () << " port " << portKMS <<
      " from " <<
      localIpv4 << " port" << portKMS
    );
    m_sendSocketKMS->Bind (senderKMS);  
    m_sendSocketKMS->ShutdownRecv ();
    m_sendSocketKMS->SetConnectCallback (
        MakeCallback (&QKDPostprocessingApplication::ConnectionSucceededKMS, this),
        MakeCallback (&QKDPostprocessingApplication::ConnectionFailedKMS, this)); 
    m_sendSocketKMS->SetDataSentCallback (
        MakeCallback (&QKDPostprocessingApplication::DataSendKMS, this));
    m_sendSocketKMS->TraceConnectWithoutContext ("RTT", MakeCallback (&QKDPostprocessingApplication::RegisterAckTime, this)); 
    m_sendSocketKMS->Connect (m_kms);    

  }


  void QKDPostprocessingApplication::StopApplication (void) // Called at time specified by Stop
  {
    NS_LOG_FUNCTION (this);

    if (m_sendSocket)
      {
        m_sendSocket->Close ();
      }
    else
      {
        NS_LOG_WARN ("QKDPostprocessingApplication found null socket to close in StopApplication");
      }
   
      NS_LOG_FUNCTION (this);
      while(!m_sinkSocketList.empty ()) //these are accepted sockets, close them
      {
        Ptr<Socket> acceptedSocket = m_sinkSocketList.front ();
        m_sinkSocketList.pop_front ();
        acceptedSocket->Close ();
      }
      if (m_sinkSocket) 
      {
        m_sinkSocket->Close ();
        m_sinkSocket->SetRecvCallback (MakeNullCallback<void, Ptr<Socket> > ());
      }

    m_connected = false; 
    Simulator::Cancel (m_sendEvent);//
  }

  void QKDPostprocessingApplication::ScheduleNextReset(){
 
    double ratio = m_keySizeInBits / static_cast<double>(m_keyRate.GetBitRate ());

    Time nextTime (Seconds (ratio)); // Time till next QKD packet
    Simulator::Schedule (nextTime, &QKDPostprocessingApplication::ResetCounter, this);

    NS_LOG_FUNCTION (this << m_keySizeInBits << "\t" <<  static_cast<double>(m_keyRate.GetBitRate ()) << "\t" << "ratio:" << ratio << "nextTime:" << nextTime);
  }

  void QKDPostprocessingApplication::ResetCounter (){

    NS_LOG_FUNCTION (this << m_packetNumber);

    if(m_master) m_packetNumber = 0;
    if(m_connected) SendSiftingPacket();
    SendData();

  }
   
  void QKDPostprocessingApplication::SendData (void)
  {
    NS_LOG_FUNCTION (this);
   
    if(m_master == true){
      NS_LOG_FUNCTION(this << "********************** MASTER **********************");      
    }else{
      NS_LOG_FUNCTION(this << "********************** SLAVE **********************");      
    }

    NS_LOG_DEBUG (this << "\t Sending packet " << m_packetNumber );
    if(m_packetNumber > 0){ 
      nlohmann::json msgBody;
      msgBody["ACTION"] = "QKDPPS";
      msgBody["NUMBER"] = m_packetNumber;
      std::string message = msgBody.dump();
      PrepareOutput(message, "qkdpps");
    }else{ 
    
      NS_LOG_FUNCTION (this << "m_lastUUID:\t" << m_lastUUID);

      std::string keyId;      
      if(m_master){
        UUID keyIdRaw = UUID::Sequential();
        keyId = keyIdRaw.string();
      }else
        keyId = m_lastUUID;

      if(keyId.size() > 0){

        GenerateRandomKeyId();

        nlohmann::json msgBody;
        msgBody["ACTION"] = "ADDKEY";
        msgBody["size"] = m_keySizeInBits;
        msgBody["uuid"] = keyId;
        msgBody["srid"] = m_keyId; //seed random key id
        std::string message = msgBody.dump();

        PrepareOutput(message, "addkey");
        ScheduleNextReset();

        if(m_master && m_connected){
          NS_LOG_FUNCTION( this << "ADDKEY" << keyId );
          Ptr<QKDKey> newKey = Create<QKDKey> (keyId, m_keyId, m_keySizeInBits);
          SendPacketToKMS(newKey);
        }
      }
    }
    m_packetNumber++;

  }

  void QKDPostprocessingApplication::PrepareOutput (std::string value, std::string action)
  {    
      NS_LOG_FUNCTION (this <<  Simulator::Now () << action << value);     
   
      std::ostringstream msg; 
      msg << value << ";";

      //playing with packet size to introduce some randomness 
      msg << std::string( m_random->GetValue (m_pktSize, m_pktSize*1.1), '0');
      msg << '\0';

      Ptr<Packet> packet = Create<Packet> ((uint8_t*) msg.str().c_str(), msg.str().length());
      NS_LOG_DEBUG(this << "\t !!!SENDING PACKET WITH CONTENT:" << value << " of size " << packet->GetSize() );
      
      uint32_t bits = packet->GetSize() * 8;
      NS_LOG_LOGIC (this << "bits = " << bits);

      if(action == "qkdpps"){
          Time nextTime (Seconds (bits / static_cast<double>(m_dataRate.GetBitRate ()))); // Time till next packet
          NS_LOG_FUNCTION(this << "CALCULATED NEXTTIME:" << bits / m_dataRate.GetBitRate ());
          NS_LOG_LOGIC ("nextTime = " << nextTime);
          m_sendEvent = Simulator::Schedule (nextTime, &QKDPostprocessingApplication::SendPacket, this, packet);
      }else if(action == "addkey"){
          SendPacket(packet);
      }

  }


  void QKDPostprocessingApplication::SendPacket (Ptr<Packet> packet){

      NS_LOG_FUNCTION (this << "\t" << packet << "PACKETID: " << packet->GetUid() << packet->GetSize() );
      if(m_connected){ 
        m_txTrace (packet);
        m_sendSocket->Send (packet); 
      }
  }

  void QKDPostprocessingApplication::SendPacketToKMS (Ptr<QKDKey> key){

      NS_LOG_FUNCTION (this);

      //Create a message body
      nlohmann::json msgBody;
      Ipv4Address source = InetSocketAddress::ConvertFrom(m_local).GetIpv4 ();
      std::ostringstream srcAddressTemp;
      source.Print(srcAddressTemp); //IPv4Address to string
      std::string sourceString = srcAddressTemp.str ();

      Ipv4Address destination = InetSocketAddress::ConvertFrom(m_peer).GetIpv4 ();
      std::ostringstream dstAddressTemp;
      destination.Print(dstAddressTemp); //IPv4Address to string
      std::string destinationString = dstAddressTemp.str ();

      msgBody["source"] = sourceString;
      msgBody["destination"] = destinationString;
      
      msgBody["key_id"] = key->GetId(); 
      msgBody["key"] = key->GetKeyString();
      msgBody["src_id"] = GetSrc()->GetId();
      msgBody["dst_id"] = GetDst()->GetId();

      std::string message = msgBody.dump();

      Ipv4Address lkmsAddress = InetSocketAddress::ConvertFrom(m_kms).GetIpv4 ();
      std::ostringstream lkmsAddressTemp;
      lkmsAddress.Print(lkmsAddressTemp); //IPv4Address to string
      std::string headerUri = "http://" + lkmsAddressTemp.str ();
      headerUri += "/api/v1/keys/" + destinationString + "/store_pp_key";

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
        << " key_id: " << key->GetId() 
        << " via socket " << m_sendSocketKMS 
      );

      m_txTraceKMS (packet);
      m_sendSocketKMS->Send (packet); 
  }

  void QKDPostprocessingApplication::SendSiftingPacket(){

    NS_LOG_FUNCTION (this);    
    
    uint32_t tempValue = 800 + m_random->GetValue (100, 300);
    NS_LOG_FUNCTION (this << "Sending SIFTING packet of size" << tempValue);
    Ptr<Packet> packet = Create<Packet> (tempValue); 
    m_sendSocket_sifting->Send (packet);
    NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

    m_packetNumber_sifting++;

    if(m_packetNumber_sifting < m_maxPackets_sifting){
      Simulator::Schedule (MicroSeconds(400), &QKDPostprocessingApplication::SendSiftingPacket, this);
    }else { 
      m_packetNumber_sifting = 0; 
    }
  }
       
  void QKDPostprocessingApplication::HandleReadKMS (Ptr<Socket> socket)
  {
    if(m_master == true) {
      NS_LOG_FUNCTION(this << "--------------MASTER--------------"); 
    } else {
      NS_LOG_FUNCTION(this << "--------------SLAVE--------------");
    }

    Ptr<Packet> packet;
    Address from;     
    while ((packet = socket->RecvFrom (from)))
    {
        if (packet->GetSize () == 0)
        { //EOF
          break;
        }

        NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

        m_totalRx += packet->GetSize ();
        if (InetSocketAddress::IsMatchingType (from))
          {
            
            NS_LOG_FUNCTION (this << "At time " << Simulator::Now ().GetSeconds ()
                         << "s packet sink received "
                         <<  packet->GetSize () << " bytes from "
                         << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                         << " port " << InetSocketAddress::ConvertFrom (from).GetPort ()
                         << " total Rx " << m_totalRx << " bytes");
          }
          m_rxTraceKMS (packet, from);
    }
  }
  void QKDPostprocessingApplication::HandleRead (Ptr<Socket> socket)
  {
    if(m_master == true) {
      NS_LOG_FUNCTION(this << "--------------MASTER--------------"); 
    } else {
      NS_LOG_FUNCTION(this << "--------------SLAVE--------------");
    }
   
    Ptr<Packet> packet;
    Address from;     
    while ((packet = socket->RecvFrom (from)))
    {
        if (packet->GetSize () == 0)
        { //EOF
          break;
        }

        NS_LOG_FUNCTION (this << packet << "PACKETID: " << packet->GetUid() << " of size: " << packet->GetSize() );

        m_totalRx += packet->GetSize ();
        if (InetSocketAddress::IsMatchingType (from))
          {
            
            NS_LOG_FUNCTION (this << "At time " << Simulator::Now ().GetSeconds ()
                         << "s packet sink received "
                         <<  packet->GetSize () << " bytes from "
                         << InetSocketAddress::ConvertFrom(from).GetIpv4 ()
                         << " port " << InetSocketAddress::ConvertFrom (from).GetPort ()
                         << " total Rx " << m_totalRx << " bytes");
            
          } 

          m_rxTrace (packet, from);
          ProcessIncomingPacket(packet);

    }
  } 


  void QKDPostprocessingApplication::ProcessIncomingPacket(Ptr<Packet> packet)
  {
      /**
      *  POST PROCESSING
      */    
      uint8_t *buffer = new uint8_t[packet->GetSize ()];
      packet->CopyData(buffer, packet->GetSize ());
      std::string s = std::string((char*)buffer);
      delete[] buffer;  

      std::string packetValue;  
      if(s.size() > 5){
 
        NS_LOG_FUNCTION(this << "payload:" << s);

        std::size_t pos = s.find(";");
        std::string payloadRaw = s.substr(0,pos); //remove padding zeros

        NS_LOG_FUNCTION(this << "payloadRaw:" << payloadRaw << payloadRaw.size());

        try{

          std::string label;
          nlohmann::json jresponse;
          jresponse = nlohmann::json::parse(payloadRaw);

          if (jresponse.contains("ACTION")) label = jresponse["ACTION"];
          NS_LOG_DEBUG (this << "\tLABEL:\t" <<  jresponse["ACTION"] << "\tPACKETVALUE:\t" << s);

          if(label == "ADDKEY"){

            if(!m_master){          

              std::string keyId;
              uint32_t keySize = m_keySizeInBits;

              if (jresponse.contains("size")) keySize = uint32_t(jresponse["size"]);
              if (jresponse.contains("uuid")) keyId = jresponse["uuid"];
              if (jresponse.contains("srid")) m_keyId = jresponse["srid"];

              m_lastUUID = keyId;
              NS_LOG_FUNCTION( this << "ADDKEY" << keyId );
              Ptr<QKDKey> newKey = Create<QKDKey> (keyId, m_keyId, keySize);
              SendPacketToKMS(newKey);
              m_packetNumber = 0;
            }

          }

        }catch (...){
            NS_LOG_FUNCTION( this << "!!!!!!!!!!!!!!!!!!!!! JSON parse error! !!!!!!!!!!!!!!!!!!!!! \t"<< payloadRaw << payloadRaw.size());
        }

      } 
      SendData();
  }

  void QKDPostprocessingApplication::HandleReadSifting (Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION (this << socket);

    if(m_master == true)
    {
      NS_LOG_FUNCTION(this << "***MASTER***" );
    }
    else
    {
      NS_LOG_FUNCTION(this << "!!!SLAVE!!!");
    }

    Ptr<Packet> packet;
    packet = socket->Recv (65535, 0);  
  }
 
  void QKDPostprocessingApplication::HandlePeerClose (Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION (this << socket);
  }
  void QKDPostprocessingApplication::HandlePeerCloseKMS (Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION (this << socket);
  }

  void QKDPostprocessingApplication::HandlePeerError (Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION (this << socket);
  }
  void QKDPostprocessingApplication::HandlePeerErrorKMS (Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION (this << socket);
  }

  void QKDPostprocessingApplication::HandleAccept (Ptr<Socket> s, const Address& from)
  {
    NS_LOG_FUNCTION (this << s << from); 
    s->SetRecvCallback (MakeCallback (&QKDPostprocessingApplication::HandleRead, this));
    m_sinkSocketList.push_back (s);
  }
  void QKDPostprocessingApplication::HandleAcceptKMS (Ptr<Socket> s, const Address& from)
  {
    NS_LOG_FUNCTION (this << s << from); 
    s->SetRecvCallback (MakeCallback (&QKDPostprocessingApplication::HandleReadKMS, this)); 
  }
  void QKDPostprocessingApplication::HandleAcceptSifting (Ptr<Socket> s, const Address& from)
  {
    NS_LOG_FUNCTION (this << s << from);
    s->SetRecvCallback (MakeCallback (&QKDPostprocessingApplication::HandleReadSifting, this));
    m_sinkSocketList.push_back (s);
  }
   
  void QKDPostprocessingApplication::ConnectionSucceeded (Ptr<Socket> socket)
  {
      NS_LOG_FUNCTION (this << socket);
      NS_LOG_FUNCTION (this << "QKDPostprocessingApplication Connection succeeded");

      if (m_sendSocket == socket || m_sinkSocket == socket){
        m_connected = true;  

        if(m_master) {
          SendSiftingPacket();
          SendData();
          ScheduleNextReset();
        }
      }
  }

  void QKDPostprocessingApplication::ConnectionSucceededSifting (Ptr<Socket> socket)
  {
      NS_LOG_FUNCTION (this << socket);
      NS_LOG_FUNCTION (this << "QKDPostprocessingApplication SIFTING Connection succeeded");
  }

  void QKDPostprocessingApplication::ConnectionFailed (Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDPostprocessingApplication, Connection Failed");
  }

  void QKDPostprocessingApplication::DataSend (Ptr<Socket> socket, uint32_t value)
  {
      NS_LOG_FUNCTION (this);
  }




  void QKDPostprocessingApplication::ConnectionSucceededKMS (Ptr<Socket> socket)
  {
      NS_LOG_FUNCTION (this << socket);
      NS_LOG_FUNCTION (this << "QKDPostprocessingApplication-KMS Connection succeeded");
  }

  void QKDPostprocessingApplication::ConnectionFailedKMS (Ptr<Socket> socket)
  {
    NS_LOG_FUNCTION (this << socket);
    NS_LOG_FUNCTION (this << "QKDPostprocessingApplication-KMS Connection Failed");
  }

  void QKDPostprocessingApplication::DataSendKMS (Ptr<Socket> socket, uint32_t value)
  {
      NS_LOG_FUNCTION (this);
  }





  void QKDPostprocessingApplication::RegisterAckTime (Time oldRtt, Time newRtt)
  {
    NS_LOG_FUNCTION (this << oldRtt << newRtt);
    m_lastAck = Simulator::Now ();
  }

  Time QKDPostprocessingApplication::GetLastAckTime ()
  {
    NS_LOG_FUNCTION (this);
    return m_lastAck;
  }

  std::string 
  QKDPostprocessingApplication::GenerateRandomString(const int len) {
      std::string tmp_s;
      static const char alphanum[] =
          "0123456789"
          "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          "abcdefghijklmnopqrstuvwxyz"; 
      
      uint32_t randVal = 0;
      for (int i = 0; i < len; ++i){ 
        randVal = round(m_random->GetValue (0, sizeof(alphanum) - 1));
        tmp_s += alphanum[ randVal ];
      } 
      return tmp_s;
  }

} // Namespace ns3
