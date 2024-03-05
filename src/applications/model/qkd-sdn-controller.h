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
#ifndef QKD_SDN_CONTROLLER_H
#define QKD_SDN_CONTROLLER_H

#include "ns3/address.h"
#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/data-rate.h"
#include "ns3/traced-callback.h"
#include "ns3/random-variable-stream.h" 
#include "ns3/qkd-buffer.h"
#include "ns3/qkd-connection-register.h"
#include "ns3/qkd-key-association-link-entry.h"
#include "ns3/qkd-application-entry.h"
#include "ns3/qkd-kms-queue-logic.h"  
#include "ns3/json.h"
#include <unordered_map>
#include "ns3/http.h"
#include "ns3/uuid.h"

#include <iostream>
#include <sstream>
#include <unistd.h>
#include <sstream>
#include <string>
#include <regex>
#include <cryptopp/base64.h>
 

namespace ns3 {

class Address;
class Socket; 

/**
 * \ingroup applications
 * \class QKD QKDSDNController
 * \brief QKD QKDSDNController is a class used to 
 * controll the requests from KMSs and manage QKD network
 *
 * \note QKDNetSim implements Software Defined Network (SDN) controller
 * as an application that listens on TCP port 3060. The SDN can be installed
 * on any node within the network. It establishes sockets to all KMSs in the
 * network
 */
class QKDSDNController : public Application
{
public:

  /**
   * \brief Request types
   */
  enum RequestType
  {
    NONE = 50,
    GET_ROUTE = 12, 
    REGISTER_SAE_LINK = 13,
    REGISTER_QKD_LINK = 14,
    KEY_ASSOCIATION_STATUS = 15,
    
    ETSI_QKD_014_GET_STATUS = 0,              ///< Integer equivalent = 0.
    ETSI_QKD_014_GET_KEY = 1,                 ///< Integer equivalent = 1.
    ETSI_QKD_014_GET_KEY_WITH_KEY_IDS = 2,    ///< Integer equivalent = 2.
    ETSI_QKD_004_OPEN_CONNECT = 3,
    ETSI_QKD_004_GET_KEY = 4,
    ETSI_QKD_004_CLOSE = 5,
    NEW_APP = 6,
    REGISTER = 7,
    FILL = 8,
    STORE_PP_KEYS = 9, //Store postprocessing keys
    TRANSFORM_KEYS = 10, //Transform (merge, split) QKD keys
    ETSI_QKD_004_KMS_CLOSE = 11
  };
 
  /**
   * \brief Get the type ID
   * \return the object TypeId
   */
  static TypeId GetTypeId (void);

  /**
   * \brief QKDSDNController constructor
   */
  QKDSDNController ();

  /**
   * \brief QKDSDNController destructor
   */
  virtual ~QKDSDNController (); 

  /**
   * \brief Get sink socket
   * \return pointer to the sink socket
   */
  Ptr<Socket> GetSocket (void) const;

  //void PrepareOutput (std::string key, uint32_t value); @toDo ? not used
 
  /**
   * \brief Set sink socket
   * \param type socket type
   * \param socket pointer to socket to be set
   */
  void SetSocket (std::string type, Ptr<Socket> socket);
 
  /**
   * \brief Get the total amount of bytes received
   * \return the total bytes received in this sink app
   */
  uint32_t GetTotalRx () const;
 
  /**
   * \brief Get list of all accepted sockets
   * \return list of pointers to accepted sockets
   */
  std::map<Ptr<Socket>, Ptr<Socket> > GetAcceptedSockets (void) const;
  

  /**
  *   \brief Get maximum number of keys per request (ETSI QKD 014)
  *   \return uint32_t maximum number of keys per request
  */
  uint32_t GetMaxKeyPerRequest();

  /**
   * \brief Inform KMS about the new QKD connection/link
   * \param uint32_t master SAE ID
   * \param uint32_t slave SAE ID 
   * \param Ipv4Address slave KMS address
   * \param Ptr<QKDBuffer> srcQKDBuffer
   */
  void AddNewLink(
    uint32_t srcSaeId,
    uint32_t dstSaeId,  
    Ipv4Address kmsDstAddress,
    Ptr<QKDBuffer> srcBuffer
  );
  
  /**
   * \brief Inform KMS about the SAE connection
   * \param Ptr<Node> source
   * \param Ptr<Node> destination
   * \param uint32_t source SAE_ID
   * \param uint32_t destination SAE_ID
   * \param std::string type
   */
  void RegisterSaePair(
    Ptr<Node> srcNode, 
    Ptr<Node> dstNode,
    uint32_t  srcSaeId,
    uint32_t  dstSaeId,
    std::string type
  );
  
  /**
   * \brief Set node
   * \param n node to be set
   */
  void SetNode(Ptr<Node> n);

  /**
   * \brief Get node
   * \return pointer to node
   */
  Ptr<Node> GetNode();

  /**
   * \brief Get key menager system ID
   * \return uint32_t key manager system ID
   */
  uint32_t GetId();
   
  /**
   * \brief Set local address
   * \param Ipv4Address address
   */
  void SetAddress(Ipv4Address address) {
    m_local = address;
  }

  /**
   * \brief Get local address
   * \return return local address
   */
  Ipv4Address GetAddress() {
    return m_local;
  }

  /**
   * \brief Set local port
   * \param uint32_t port
   */
  void SetPort(uint32_t port) {
    m_port = port;
  }

  /**
   * \brief Get local port
   * \return return local port
   */
  uint32_t GetPort() {
    return m_port;
  }
  
protected:

  /**
   * \brief @toDo
   */
  virtual void DoDispose (void);

private:
  
  /**
   * \brief Get request type
   * \param s string from HTTP URI
   * \return request type
   */
  QKDSDNController::RequestType FetchRequestType (std::string s );

  /**
   * \brief Hashing for the Address class
   */
  struct AddressHash
  {
    /**
     * \brief operator ()
     * \param x the address of which calculate the hash
     * \return the hash of x
     *
     * Should this method go in address.h?
     *
     * It calculates the hash taking the uint32_t hash value of the ipv4 address.
     * It works only for InetSocketAddresses (Ipv4 version)
     */
    size_t operator() (const Address &x) const
    {
      NS_ABORT_IF (!InetSocketAddress::IsMatchingType (x));
      InetSocketAddress a = InetSocketAddress::ConvertFrom (x);
      return std::hash<uint32_t>()(a.GetIpv4 ().Get ());
    }
  };

  // inherited from Application base class.
  /**
   * \brief Start KMS Application
   */
  void StartApplication (void);    // Called at time specified by Start

  /**
   * \brief Stop KMS Application
   */
  void StopApplication (void);     // Called at time specified by Stop

  /**
   * \brief Send packet to the pair socket
   * \param socket receiving socket
   * \param packet packet to send
   */
  void SendToSocketPair (Ptr<Socket> socket, Ptr<Packet> packet);

  /**
   * \brief Send packet to the pair socket
   * \param socket receiving socket
   * \param packet packet to send
   */
  void SendToSocketPairKMS (Ptr<Socket> socket, Ptr<Packet> packet);
 
  /**
   * \brief Handle a packet received by the KMS application
   * \param socket the receiving socket
   */
  void HandleRead (Ptr<Socket> socket);
 
  /**
   * \brief Handle an incoming connection
   * \param s the incoming connection socket
   * \param from the address the connection is from
   */
  void HandleAccept (Ptr<Socket> s, const Address& from);
 
  /**
   * \brief Handle an connection close
   * \param socket the connected socket
   */
  void HandlePeerClose (Ptr<Socket> socket);
  
  /**
   * \brief Handle an connection error
   * \param socket the connected socket
   */
  void HandlePeerError (Ptr<Socket> socket);

  /**
   * \brief Assemble byte stream to extract HTTPMessage
   * \param p received packet
   * \param from from address 
   *
   * The method assembles a received byte stream and extracts HTTPMessage
   * instances from the stream to export in a trace source.
   */
  void PacketReceived (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);
  
  /**
   * \brief QKD key manager system application process the request
   * from QKDApp, and complete certain actions 
   * to respond on received request.
   * \param header received HTTP header
   * \param packet received packet 
   * \param socket the receiving socket
   *
   * Data structure of key managment respond
   * is described in ETSI014 document.
   */
  void      ProcessRequest(HTTPMessage header, Ptr<Packet> packet, Ptr<Socket> socket);
 
  /*
   * \brief Process OPEN_CONNECT request - ETSI QKD GS 004
   * \param header received request
   * \param socket receiving socket
   */
  void      ProcessOpenConnectRequest(HTTPMessage header, Ptr<Socket> socket); 

  /*
   * \brief Process GET_KEY request - ETSI QKD GS 004
   * \param ksid Unique identifier of the association
   * \param header received request
   * \param socket receiving socket
   */
  void      ProcessGetKey004Request(std::string ksid, HTTPMessage header, Ptr<Socket> socket);

  /*
   * \brief Process CLOSE request - ETSI QKD GS 004
   * \param ksid Unique identifier of the association
   * \param header received request
   * \param socket receiving socket
   */
  void      ProcessCloseRequest(std::string ksid, HTTPMessage header, Ptr<Socket> socket);

  /*
   * \brief Process NEW_APP request
   * \param header received request
   * \param socket receiving socket
   */
  void      ProcessNewAppRequest(HTTPMessage header, Ptr<Socket> socket);
  
  void      ProcessNewAppResponse (HTTPMessage header, Ptr<Socket> socket);

  void      RegisterRequest (std::string ksid);

  void      ProcessRegisterRequest (HTTPMessage header, std::string ksid, Ptr<Socket> socket);

  void      ProcessRegisterResponse(HTTPMessage header, Ptr<Socket> socket);
  
  void      PrepareSinkSocket ();

  /**
   * \brief Process FILL request
   * \param header received request
   * \param socket receiving socket
   * \param ksid Unique identifier of the association
   *
   * Process the proposal of keys to fill the dedicated
   * key store reserved for association identified with KSID.
   */
  void      ProcessAddKeysRequest (HTTPMessage h, Ptr<Socket> socket, std::string ksid);

  /**
   * \brief Process FILL response
   * \param header received http header
   * \param socket receiving socket
   *
   * Process the response on the FILL method
   * where the primary KMS (the initiator) will
   * obtain and store QKD keys that are accepted
   * by the replica KMS for this association.
   */
  void      ProcessAddKeysResponse (HTTPMessage header, Ptr<Socket> socket);
   
  /**
   * \brief release key stream association
   * \param ksid unique key stream identifier
   * \param surplusKeyId unique key identifier for surplus key material in dedicated association buffer
   * \param syncIndex unique key index in dedicated association buffer for synchronisation
   */
  void      ReleaseAssociation (std::string ksid, std::string surplusKeyId, uint32_t syncIndex);

  /**
   * \brief Check the correctness of QKD application request and
   * ability of KMS to fullfil correct request.
   * \param request json structure of application request
   * \param conn connection details
   * \return json error structure defined by ETSI014 document
   */
  //nlohmann::json Check014GetKeyRequest(nlohmann::json request, QKDLocationRegisterEntry conn);

  /**
   * \brief Create key container data structure described in ETSI014 document.
   * \param keys vector of pointers on the QKD key
   * \return json data structure for key container
   */
  nlohmann::json CreateKeyContainer (std::vector<Ptr<QKDKey>> keys);

  /**
   * \brief Base64 encoder
   * \param input input data
   * \return string base64 encoded input
   */
  std::string Base64Encode(std::string input);

  /**
   * \brief Base64 decoder
   * \param input input data
   * \return string decoded input
   */
  std::string Base64Decode(std::string input);


private:

  struct QoS
  {
    uint32_t chunkSize; //Key_chunk_size
    uint32_t maxRate; //Max_bps
    uint32_t minRate; //Min_bps
    uint32_t jitter; //Jitter
    uint32_t priority; //Priority
    uint32_t timeout; //Timeout
    uint32_t TTL; //Time to Live
    //metadata mimetype is left out
  };

  struct ChunkKey
  {
    uint32_t index;
    uint32_t chunkSize;
    bool ready;
    std::string key; //key of key_chunk_size
    //std::vector<std::pair<std::string, std::pair<uint32_t, uint32_t> > > keyIds; //"QKDKey"s that form ChunkKey
                        //keyId                  start      end
  };

  struct HttpQuery
  {
    RequestType method_type; //For every query!
    
    //Specific to TRANSFORM
    uint32_t transform_key_size;
    uint32_t transform_key_number;
    std::vector<std::string> transform_key_IDs;
    std::vector<std::string> to_transform_key_IDs;
    std::string surplus_key_ID;
    uint32_t sae_id; //Needed to specify buffer to fetch the key from

    //Specific to ETSI 004 (NEW_APP)
    uint32_t source_sae;
    uint32_t destination_sae;
    std::string ksid;

    //Specific to ETSI 004 (KMS CLOSE)
    uint32_t sync_index;

  };

  struct Association004 //Holds information of the association and dedicated key store
  {
    uint32_t srcSaeId; //Source application that requested the KSID
    uint32_t dstSaeId; //Destination application 
    uint32_t associationDirection; //0-Outbound, 1-Inbound - Important while monitoring the associations!
    QoS qos; //Quality of service
    Ipv4Address dstKmsNode; //Address of the destination KMS. Important!
    bool peerRegistered; //KMS must know the state of connection for association on peer KMS!
    std::map<uint32_t, ChunkKey> buffer; //index & key ; index is KeyId for key of the association
    uint32_t lastIndex;
    std::vector<std::string> tempBuffer; //Buffer for keys in negotiation. It holds only KeyIds, while keys are in QKDBuffer!
  };

  double          m_qkdLinkDefaultUpdateInterval; //!< Default update interval of QKD link status (seconds)

  std::map<std::string, Association004> m_associations004; //Associations map

  Ptr<Socket>     m_sinkSocket;       // Associated socket
 
  Ipv4Address     m_local;        //!< Local address to bind to

  uint32_t        m_port;        //!< Local port to bind to
       
  uint32_t        m_totalRx;      //!< Total bytes received  

  uint32_t        m_totalRxKMSs;      //!< Total bytes received between KMSs
 
  TypeId          m_tid; 
  
  uint32_t        m_kms_id;

  uint32_t        m_kms_key_id; //key counter to generate unique keyIDs on KMS
  
  EventId         m_closeSocketEvent;  

  std::map<uint32_t, EventId > m_scheduledChecks;

  std::map<Ipv4Address, uint32_t> m_flagedIPAdr;
  uint32_t        m_maliciousBlocking;

  /// Traced Callback: received packets, source address.
  TracedCallback<Ptr<const Packet>, const Address &> m_rxTrace; 
  TracedCallback<Ptr<const Packet> > m_txTrace;
  TracedCallback<Ptr<const Packet>, const Address &> m_rxTraceSDNs; 
  TracedCallback<Ptr<const Packet> > m_txTraceSDNs; 
  /// Traced callback: fired when a packet is dropped
  TracedCallback<const Ipv4Address&, Ptr<const Packet> > m_dropTrace;
 
  TracedCallback<const uint32_t&> m_newKeyGeneratedTraceEmir;
  TracedCallback<const uint32_t&> m_keyServedTraceEmir;

  TracedCallback<const uint32_t& , const uint32_t&> m_newKeyGeneratedTrace;

  TracedCallback<const std::string &, const uint32_t&, Ptr<QKDKey> > m_keyServedETSI014Trace;
  TracedCallback<const std::string &, const uint32_t&, const uint32_t&, const uint32_t& > m_keyServedETSI004Trace;
  
  uint32_t        m_maxKeyPerRequest; //Maximal number of keys per request QKDApp can ask for
  uint32_t        m_minKeySize; //Minimal size of key QKDApp can request from KMS
  uint32_t        m_maxKeySize; //Maximal size of key QKDApp can request from KMS
  uint32_t        m_defaultKeySize; //Default size of key KMS delivers to QKDApp

  std::unordered_map<Address, Ptr<Packet>, AddressHash> m_buffer; //!< Buffer for received packets (TCP segmentation)
  std::unordered_map<Address, Ptr<Packet>, AddressHash> m_bufferKMS; //!< Buffer for received packets (TCP segmentation)

  // In the case of TCP, each socket accept returns a new socket, so the
  // listening socket is stored separately from the accepted sockets
  std::map<Ptr<Socket>, Ptr<Socket> > m_socketPairs;  //!< the accepted sockets

  std::map<Ipv4Address, std::pair<Ptr<Socket>, Ptr<Socket> > > m_socketPairsKMS;  //!< the accepted sockets for communication between KMSs

  Ptr<Node> m_node; //<! node on which KMS is installed 
  std::map<Ptr<Socket>, Ptr<Packet> > m_packetQueues; //!< Buffering unsend messages due to connection problems

  Ptr<QKDKMSQueueLogic> m_queueLogic; //!< KMS Queue Logic for ETSI 004 QoS handling

  /**
    @toDo:following functions
    */
  void ConnectionSucceeded (Ptr<Socket> socket);
  void ConnectionFailed (Ptr<Socket> socket);
  void DataSend (Ptr<Socket>, uint32_t); // for socket's SetSendCallback

  void ConnectionSucceededKMSs (Ptr<Socket> socket);
  void ConnectionFailedKMSs (Ptr<Socket> socket);
  void DataSendKMSs (Ptr<Socket>, uint32_t); // for socket's SetSendCallback


  /**
   *     HTTP handling
   *
   * Each application can open only one connection with its local KMS (current socket).
   * Each KMS can have only one connection with arbitrary KMS (current socket).
   */

  std::map<Ipv4Address, std::vector<HttpQuery> > m_httpRequestsQueryKMS;
  std::multimap<uint32_t, Ptr<Socket> > m_http004App; //SAE_ID, receiving socket

  /**
   * \brief remember HTTP request made to peer KMS
   * \param dstKms destination kms IP address
   * \param request request parameters
   */
  void  HttpKMSAddQuery(Ipv4Address dstKms, HttpQuery request);

  /**
   * \brief remove mapped HTTP response from query
   * \param dstKms destination kms IP address
   */
  void  HttpKMSCompleteQuery(Ipv4Address dstKms);

  /**
   * \brief obtain method_type to map the HTTP response
   * \param dstKms destination KMS IP address
   * \return RequestType method function
   */
  RequestType HttpQueryMethod(Ipv4Address dstKms);

  void  Http004AppQuery (uint32_t saeId, Ptr<Socket> socket);

  void  Http004AppQueryComplete (uint32_t saeId);

  Ptr<Socket> GetSocketFromHttp004AppQuery (uint32_t saeId);

  Ipv4Address GetDestinationKmsAddress (Ptr<Socket> socket);

  /**
   * \brief Prepare send socket to communicate with peer KMS Application
   * \param uint32_t destination SAE ID
   */
  void CheckSocketsKMS (Ipv4Address dstSaeId);

  /**
   * \brief Obtain send socket
   * \param kmsDstAddress Address of the destination KMS
   * \return Socket send socket
   */
  Ptr<Socket> GetSendSocketKMS (Ipv4Address kmsDstAddress);

  /**
   * \brief Convert packet to string
   * \param packet the packet
   * \return string packet
   */
  std::string PacketToString (Ptr<Packet> packet);

  /**
   * \brief Read the parameters from the JSON OPEN_CONNECT structure!
   * \param &dstSaeId destination secure application entity
   * \param &srcSaeId source secure application entity
   * \param &inQos requested QoS
   * \param &ksid Unique identifier of the association
   * \param jOpenConncetRequest JSON structure of the OPEN_CONNECT call
   */
  void  ReadJsonQos (  
      QKDSDNController::QoS &inQos, 
      nlohmann::json jOpenConnectRequest );
  
  /**
   * \brief Create a new assocation
   * \param srcSaeId source secure application entity
   * \param dstSaeId destination secure application entity
   * \param inQos Quality of Service
   * \param dstKms destination KMS address
   * \param ksid Unique identifier of the association
   * \return string Unique identifier of the association
   *
   * Input ksid can be empty if it is not predefined. In that case
   * new ksid is generated for this new association and return from
   * the function.
   */
  std::string CreateNew004Association (
      uint32_t srcSaeId, uint32_t dstSaeId, 
      QKDSDNController::QoS inQos, 
      Ipv4Address dstKms, std::string ksid );


};

} // namespace ns3

#endif /* QKD_APPLICATION_H */

