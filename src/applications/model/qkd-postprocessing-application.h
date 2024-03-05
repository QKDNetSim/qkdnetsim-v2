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

#ifndef QKD_POSTPROCESSING_APPLICATION_H
#define QKD_POSTPROCESSING_APPLICATION_H

#include "ns3/application.h"
#include "ns3/address.h"
#include "ns3/event-id.h"
#include "ns3/nstime.h"
#include "ns3/ptr.h"
#include "ns3/log.h"
#include "ns3/data-rate.h"
#include "ns3/traced-callback.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/ipv4-address.h"
#include "ns3/random-variable-stream.h"
#include "ns3/qkd-key-manager-system-application.h"
#include "ns3/socket-factory.h" 
#include "ns3/tcp-socket-factory.h" 
#include "ns3/udp-socket-factory.h" 
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/uuid.h"
#include "ns3/http.h"

namespace ns3 {

class Address;
class Socket;
class Packet;

/**
 * \ingroup applications
 * \class QKD QKDPostprocessingApplication
 * \brief QKD QKDPostprocessingApplication is a class used to 
 * generate QKD key in key establishment process.
 *
 * \note QKD protocols are used to securely generate new key material. 
 * Although there are different types of QKD protocols, each of them 
 * requires raw material processing through post-processing applications 
 * implementing the following steps: the extraction of the raw key (sifting), 
 * error rate estimation, key reconciliation, privacy amplification and 
 * authentication. However, since the QKDNetSim focus is primarily QKD 
 * network organization, management and network traffic, one uses QKD 
 * post-processing application to imitate the network activity of a QKD 
 * protocol. The goal was to build an application that credibly imitates 
 * the traffic from the existing post-processing applications to reduce 
 * the simulation time and computational resources.
 * Such implementation of QKD post-processing allows analyzing the influence
 * of various parameters on the state of the network, such as: the impact of 
 * key generation rate, the impact of traffic volume of the reconciled 
 * protocol on network capacity and others. 
 */
class QKDPostprocessingApplication : public Application
{
public:
  /**
  * \brief Get the type ID.
  * \return The object TypeId.
  */
  static TypeId GetTypeId (void);

  /**
   * \brief Constructor.
   */
  QKDPostprocessingApplication ();

  /**
   * \brief Donstructor.
   */
  virtual ~QKDPostprocessingApplication ();
 
  /**
   * \brief Get the send socket.
   * \return The send socket.
   */
  Ptr<Socket> GetSendSocket (void) const;

  /**
   * \brief Get the sink socket.
   * \return The sink socket.
   */
  Ptr<Socket> GetSinkSocket (void) const;

  /**
   * \brief Prepare the output data.
   * \param value The output data.
   * \param action The action.
   */
  void PrepareOutput (std::string value, std::string action);
 
  /**
   * \brief Set the socket.
   * \param type The socket type.
   * \param socket The socket to set.
   * \param isMaster The role of the application.
   */
  void SetSocket (std::string type, Ptr<Socket> socket, bool isMaster);
 
  /**
   * \brief Set the sifting socket.
   * \param type The socket type.
   * \param socket The socket to set.
   */
  void SetSiftingSocket (std::string type, Ptr<Socket> socket);

  /**
   * \brief Get the total amount of data received (in bytes).
   * \return The received amount in bytes.
   */
  uint32_t GetTotalRx () const;

  /**
   * \brief Get the listening socket.
   * \return The listening socket.
   */
  Ptr<Socket> GetListeningSocket (void) const;

  /**
   * \brief Get the list of the accepted sockets.
   * \return The list of the accepted sockets.
   */
  std::list<Ptr<Socket> > GetAcceptedSockets (void) const;
  
  /**
   * \brief Get the timestamp of the last acknowledgement.
   * \return The timestamp.
   */
  Time GetLastAckTime ();

  /**
   * \brief Get the source node.
   * \return The source node.
   */
  Ptr<Node> GetSrc();

  /**
   * \brief Set the source node.
   * \param The source node.
   */
  void SetSrc(Ptr<Node>);
  
  /**
   * \brief Get the destination node.
   * \return The destination node.
   */
  Ptr<Node> GetDst();

  /**
   * \return Set the destination node.
   * \param the destination node.
   */
  void SetDst(Ptr<Node>);
  
protected:
  
  virtual void DoDispose (void);

private:

  /**
   * \brief Process data received.
   * \param packet The received packet.
   */
  void ProcessIncomingPacket(Ptr<Packet> packet);

  /**
   * \brief Start the post-processing application.
   */
  void StartApplication (void);    //!< Called at time specified by Start

  /**
   * \brief Stop the post-processing application.
   */
  void StopApplication (void);     //!< Called at time specified by Stop

  /**
   * \brief Send the packet to the socket.
   * \param packet The packet.
   */
  void SendPacket (Ptr<Packet> packet);

  /**
   * \brief Send the packet to the local KMS.
   * \param packet The packet.
   */
  void SendPacketToKMS (Ptr<QKDKey> packet);
  
  /**
   * \brief Send the sifting packet to the socket.
   */
  void SendSiftingPacket (void);

  /**
   * \brief Handle a packet received from the peer application.
   * \param socket The receiving socket.
   */
  void HandleRead (Ptr<Socket> socket);

  /**
   * \brief Handle a packet received from the KMS.
   * \param socket The receiving socket.
   */
  void HandleReadKMS (Ptr<Socket> socket);

  /**
   * \brief Handle a sifting packet received from the application.
   * \param socket The receiving socket.
   */
  void HandleReadSifting (Ptr<Socket> socket);

  /**
   * \brief Handle an incoming connection from the application.
   * \param socket The incoming connection socket.
   * \param from The address the connection is from.
   */
  void HandleAccept (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle an incoming connection from the KMS.
   * \param socket The incoming connection socket.
   * \param from The address the connection is from.
   */
  void HandleAcceptKMS (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle an incoming connection for the sifting.
   * \param socket The incoming connection socket.
   * \param from The address the connection is from.
   */
  void HandleAcceptSifting (Ptr<Socket> socket, const Address& from);
  /**
   * \brief Handle a connection close from the peer application.
   * \param socket The connected socket.
   */
  void HandlePeerClose (Ptr<Socket> socket);
  /**
   * \brief Handle a connection close from the KMS.
   * \param socket The connected socket.
   */
  void HandlePeerCloseKMS (Ptr<Socket> socket);
  /**
   * \brief Handle a connection error from the peer application.
   * \param socket The connected socket.
   */
  void HandlePeerError (Ptr<Socket> socket);
  /**
   * \brief Handle a connection error from the KMS.
   * \param socket The connected socket.
   */
  void HandlePeerErrorKMS (Ptr<Socket> socket);

  /**
   * \brief Callback function after the connection to the peer application is complete.
   * \param socket The connected socket.
   */
  void ConnectionSucceeded (Ptr<Socket> socket);

  /**
   * \brief Callback function after the connection to the peer application has failed.
   * \param socket The connected socket.
   */
  void ConnectionFailed (Ptr<Socket> socket);
  
  /**
   * \brief Callback function after the connection to the KMS is complete.
   * \param socket The connected socket.
   */
  void ConnectionSucceededKMS (Ptr<Socket> socket);

  /**
   * \brief Callback function after the connection to the KMS has failed.
   * \param socket The connected socket.
   */
  void ConnectionFailedKMS (Ptr<Socket> socket);

  /**
   * \brief Callback function after the sifting connection is complete.
   * \param socket The connected socket.
   */
  void ConnectionSucceededSifting (Ptr<Socket> socket);

  /**
   * \brief Callback function after the sifting connection has failed.
   * \param socket The connected socket.
   */
  void ConnectionFailedSifting (Ptr<Socket> socket);

  /**
   * \brief Schedule time slot to send data. 
   */
  void SendData ();

  /**
   * \brief Reset the counter after completing the post-processing round.
   */
  void ResetCounter ();

  /**
   * \brief Schedule a reset of the post-processing round.
   */
  void ScheduleNextReset();

  /**
   * \brief Generate a random seed that will be used to generate key values.
   */
  void GenerateRandomKeyId();
 
  Ptr<Node>       m_src; //!< The source node.
  Ptr<Node>       m_dst; //!< The destination node.

  /**
  * IMITATE post-processing traffic (CASCADE, PRIVACY AMPLIFICATION and etc. )
  */
  Ptr<Socket>     m_sendSocket;       //!< Associated socket
  Ptr<Socket>     m_sinkSocket;       //!< Associated socket
  /**
  * Sockets used for SIFTING
  */
  Ptr<Socket>     m_sendSocket_sifting;       //!< Associated socket for sifting
  Ptr<Socket>     m_sinkSocket_sifting;       //!< Associated socket for sifting
  /**
  * Sockets to talk with LKMS
  */
  Ptr<Socket>     m_sendSocketKMS;       //!< Associated socket
  Ptr<Socket>     m_sinkSocketKMS;       //!< Associated socket
  
  Address         m_peer;         //!< Peer address
  Address         m_local;        //!< Local address to bind to

  Address         m_peer_sifting;         //!< Peer address for sifting 
  Address         m_local_sifting;        //!< Local address for sifting to bind to
  Address         m_kms;

  uint32_t        m_keySizeInBits;     //!< KeyRate of the QKDlink
  bool            m_connected;    //!< Connection Status
  bool            m_master;       //!< Alice (1) or Bob (0)
  uint32_t        m_packetNumber;     // Total number of packets received so far 
  uint32_t        m_totalRx;      //!< Total bytes received  
  Time            m_lastAck;     // Time of last ACK received

  std::list<Ptr<Socket> > m_sinkSocketList; //!< the accepted sockets
  EventId         m_sendEvent;    //!< Event id of pending "send packet" event
 
  DataRate        m_dataRate;      //!< Rate that data is generatedm_pktSize
  DataRate        m_keyRate;      //!< QKD Key rate
  uint32_t        m_pktSize;      //!< Size of packets
  TypeId          m_tid; 
  TypeId          m_tidSifting;

  std::string     m_appId;        //!< Random string marking the app ID

  std::string     m_lastUUID;     //!< The latest UUID of the key
 
  /// Traced Callback: received packets, source address.
  TracedCallback<Ptr<const Packet>, const Address &> m_rxTrace;
  TracedCallback<Ptr<const Packet> > m_txTrace;

  TracedCallback<Ptr<const Packet>, const Address &> m_rxTraceKMS;
  TracedCallback<Ptr<const Packet> > m_txTraceKMS;
 
  uint32_t        m_packetNumber_sifting; //!< How many sifting packets have been sent
  uint32_t        m_maxPackets_sifting;   //!< Limitation for the number of sifting packets
  uint64_t        m_keyId;                //!< ID counter of generated keys

private:
 
  void DataSend (Ptr<Socket> s, uint32_t); // for socket's SetSendCallback  
  void DataSendKMS (Ptr<Socket> s, uint32_t); // for socket's SetSendCallback  
  void RegisterAckTime (Time oldRtt, Time newRtt);  //!< Callback for ack messages

  /**
   * \brief Generate a random string with a given length.
   * \param len The length.
   * \return The random string.
   */
  std::string GenerateRandomString(const int len);
  
  Ptr<UniformRandomVariable> m_random; //!< The uniform random variable.
};

} // namespace ns3

#endif /* QKD_POSTPROCESSING_APPLICATION_H */

