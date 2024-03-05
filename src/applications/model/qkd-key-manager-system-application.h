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
#ifndef QKD_KEY_MANAGER_SYSTEM_APPLICATION_H
#define QKD_KEY_MANAGER_SYSTEM_APPLICATION_H

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
#include "ns3/random-variable-stream.h"
#include "ns3/http.h" 
#include "ns3/json.h"
#include <unordered_map>
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
 * \class QKD QKDKeyManagerSystemApplication
 * \brief QKD QKDKeyManagerSystemApplication is a class used to 
 * serve requests for cryptographic keys from user's applications.
 *
 * \note QKDNetSim implements Key Management System (KMS) as an 
 * application that listens on TCP port 80. The KMS can be installed
 * on any node but the QKD post-processing application expects the 
 * existence of a local KMS application on the same nodes where the 
 * post-processing application is implemented. The local KMS is 
 * contacted to add the keys to the QKD buffer and is contacted 
 * during the operation of the QKD application to retrieve the keys 
 * from the QKD buffer as described in the following section.
 * Communication between KMS systems installed on different nodes 
 * is under construction and will be based on the ETSI QKD 004 standard.
 * The KMS application tracks REST-full design serving status and 
 * key retrieval requests from QKD applications.
 * The KMS follows HTTP 1.1 specification including Request-URI 
 * for mapping of request-response values. More details available at
 * https://www.w3.org/Protocols/rfc2616/rfc2616-sec5.html
 */
class QKDKeyManagerSystemApplication : public Application
{
public:

  /**
   * Request methods.
   */
  enum RequestType
  {
    
    NONE = 50,
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
   * \brief Get the type ID.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);

  /**
   * \brief Constructor.
   */
  QKDKeyManagerSystemApplication ();

  /**
   * \brief Destructor.
   */
  virtual ~QKDKeyManagerSystemApplication (); 

  /**
   * \brief Get the sink socket.
   * \return The sink socket.
   */
  Ptr<Socket> GetSocket (void) const;

  //void PrepareOutput (std::string key, uint32_t value); @toDo ? not used
 
  /**
   * \brief Set the sink socket.
   * \param type The socket type.
   * \param socket The socket to be set.
   */
  void SetSocket (std::string type, Ptr<Socket> socket);
 
  /**
   * \brief Get the total amount of received bytes.
   * \return The total amount of bytes.
   */
  uint32_t GetTotalRx () const;
 
  /**
   * \brief Get the list of all the accepted sockets.
   * \return The list of accepted sockets.
   */
  std::map<Ptr<Socket>, Ptr<Socket> > GetAcceptedSockets (void) const;
  

  /**
  *   \brief Get maximum number of keys that can be supplied via a single response (ETSI QKD 014).
  *   \return The number of keys.
  */
  uint32_t GetMaxKeyPerRequest();

  /**
   * \brief Register a new QKD link, or a pair of post-processing applications.
   * \param srcSaeId The source application identifier.
   * \param dstSaeId The destination application identifier. 
   * \param kmsDstAddress The destination KMS address.
   * \param srcQKDBuffer The QKD key buffer.
   * \return The key association entry identifier.
   */
  std::string AddNewLink(
    uint32_t srcSaeId,
    uint32_t dstSaeId,  
    Ipv4Address kmsDstAddress,
    Ptr<QKDBuffer> srcBuffer
  );

  /**
   * \brief Register a new QKD link, or a pair of post-processing applications.
   * \param srcSaeId The source application identifier.
   * \param dstSaeId The destination application identifier. 
   * \param kmsDstAddress The destination KMS address.
   * \param srcQKDBuffer The QKD key buffer.
   * \param keyAssociationId The key association identifier.
   * \return The key association entry identifier.
   */
  std::string AddNewLink(
    uint32_t srcSaeId,
    uint32_t dstSaeId,  
    Ipv4Address kmsDstAddress,
    Ptr<QKDBuffer> srcBuffer,
    std::string keyAssociationId
  );
  
  /**
   * \brief Register a new pair of QKD applications.
   * \param keyAssociationId The key association identifier.
   * \param applicationEntryId The application pair entry identifier.
   * \param srcSaeId The source application identifier.
   * \param dstSaeId The destination application identifier.
   * \param type The application type based on the selected key-supply interaface.
   * \param dstKmsAddress The destination KMS address.
   * \param priority The key association priority.
   * \param expirationTime The key association expiration time.
   * \return The QKD application entry.
   */
  QKDApplicationEntry
  RegisterApplicationEntry(
    UUID  keyAssociationId,
    UUID  applicationEntryId,
    UUID  srcSaeId,
    UUID  dstSaeId, 
    std::string type,     
    Ipv4Address dstKmsAddress,
    uint32_t priority, 
    double expirationTime
  );

  /**
   * \brief Register a new pair of QKD applications.
   * \param srcSaeId The source application identifier.
   * \param dstSaeId The destination application identifier.
   * \param type The application type based on the selected key-supply interaface.
   * \param dstKmsAddress The destination KMS address.
   * \param priority The key association priority.
   * \param expirationTime The key association expiration time.
   * \return The QKD application entry.
   */
  QKDApplicationEntry
  RegisterApplicationEntry(
    UUID  srcSaeId,
    UUID  dstSaeId,
    std::string type,
    Ipv4Address dstKmsAddress,
    uint32_t priority, 
    double expirationTime
  );

  /**
   * \brief Set the node.
   * \param n The node to be set.
   */
  void SetNode(Ptr<Node> n);

  /**
   * \brief Get the node.
   * \return The node
   */
  Ptr<Node> GetNode();

  /**
   * \brief Get the KMS identifier.
   * \return The KMS identifier.
   */
  uint32_t GetId();
  
  /**
   * \brief Add new keys to the QKD buffer.
   * \param key The QKD key.
   * \param srcNodeId The source node identifier.
   * \param dstNodeId The destination node identifier.
   */
  bool AddNewKey(Ptr<QKDKey> key, uint32_t srcNodeId, uint32_t dstNodeId);

  /**
   * \brief Set the local IP address.
   * \param address The local IP address.
   */
  void SetAddress(Ipv4Address address) {
    m_local = address;
  }

  /**
   * \brief Get the local IP address.
   * \return The local IP address.
   */
  Ipv4Address GetAddress() {
    return m_local;
  }

  /**
   * \brief Set the local port.
   * \param port The port number.
   */
  void SetPort(uint32_t port) {
    m_port = port;
  };

  /**
   * \brief Get the local port.
   * \return The port number.
   */
  uint32_t GetPort() {
    return m_port;
  }

  /**
   * \brief Connect to the SDN controller
   */
  void ConnectToSDNController();

  /**
   * \brief Set the SDN controller address.
   * \param sdnAddress The address.
   */
  void SetSDNControllerAddress(Address sdnAddress){
    m_sdnControllerAddress = sdnAddress;
    m_sdnSupportEnabled = true;
  }

  /**
   * \brief Send the QKD link statistics to the SDN controller.
   * \param linkId The link identifier.
   * \param updatePeriod The update period.
   */
  void SendQKDLinkStatusToSDN(UUID linkId, double updatePeriod);

  /**
   * \brief Add the key association.
   * \param rt The key association link entry.
   */
  void SaveKeyAssociation(QKDKeyAssociationLinkEntry& rt);
  
protected:

  virtual void DoDispose (void);

private:

  static uint32_t     nKMS;       //!< The number of created KMSs. A static value.

  uint32_t m_sdnSupportEnabled;   //!< The support for the SDN.
  Address m_sdnControllerAddress; //!< The SDN controller address.
  
  /**
   * \brief Get the application connection details
   * \param saeId The application identifier.
   * \return The QKD application connection details.
   */
  QKDApplicationEntry GetApplicationConnectionDetails(std::string saeId);
 
  /**
   * \brief Get the key association link details.
   * \param appId The application identifier.
   * \return The key association link details.
   */
  QKDKeyAssociationLinkEntry GetKeyAssociationLinkDetailsByApplicationId(std::string appId);

  /**
   * \brief Get the key association link details
   * \param srcNodeId The source node identifier.
   * \param dstNodeId The destination node identifier.
   * \return The key association link details.
   */
  QKDKeyAssociationLinkEntry GetKeyAssociationByNodeIds(uint32_t srcNodeId, uint32_t dstNodeId);

  /**
   * \brief Get the key association link details.
   * \param keyAssociationId The key association identifier.
   * \return The key association link details.
   */
  QKDKeyAssociationLinkEntry GetKeyAssociationById(UUID keyAssociationId);

  /**
   * \brief Get the application connection details.
   * \param srcSaeId The source application identifier.
   * \param dstSaeId The destination application identifier.
   * \param type The connection type.
   */
  QKDApplicationEntry GetApplicationConnectionDetailsBySaeIDsAndType(
    std::string srcSaeId, 
    std::string dstSaeId,
    QKDApplicationEntry::ConnectionType type
  );

  /**
   * \brief Read the request method from the request URI.
   * \param s The HTTP request URI.
   * \return The request method.
   */
  QKDKeyManagerSystemApplication::RequestType FetchRequestType (std::string s );

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
   * \brief Start the KMS Application.
   */
  void StartApplication (void);

  /**
   * \brief Stop the KMS Application.
   */
  void StopApplication (void);

  /**
   * \brief Send the packet to the pair socket.
   * \param socket The receiving socket.
   * \param packet The packet to send.
   */
  void SendToSocketPair (Ptr<Socket> socket, Ptr<Packet> packet);

  /**
   * \brief Send the packet to the pair socket.
   * \param socket The receiving socket.
   * \param packet The packet to send.
   */
  void SendToSocketPairKMS (Ptr<Socket> socket, Ptr<Packet> packet);
 
  /**
   * \brief Handle a packet received from the application.
   * \param socket The receiving socket.
   */
  void HandleRead (Ptr<Socket> socket);

  /**
   * \brief Handle a packet received from the KMS.
   * \param socket The receiving socket.
   */
  void HandleReadKMSs (Ptr<Socket> socket);

  /**
   * \brief Handle a packet received from the SDN.
   * \param socket The receiving socket.
   */
  void HandleReadSDN (Ptr<Socket> socket);

  /**
   * \brief Handle an incoming connection from the application.
   * \param s The incoming connection socket.
   * \param from The address the connection is from.
   */
  void HandleAccept (Ptr<Socket> s, const Address& from);
 
  /**
   * \brief Handle an connection close from the application.
   * \param socket The connected socket.
   */
  void HandlePeerClose (Ptr<Socket> socket);
  
  /**
   * \brief Handle a connection error from the application.
   * \param socket The connected socket.
   */
  void HandlePeerError (Ptr<Socket> socket);

  /**
   * \brief Handle an incoming connection from the KMS.
   * \param s The incoming connection socket.
   * \param from The address the connection is from.
   */
  void HandleAcceptKMSs (Ptr<Socket> s, const Address& from);

  /**
   * \brief Handle an incoming connection from the SDN.
   * \param s The incoming connection socket.
   * \param from The address the connection is from.
   */
  void HandleAcceptSDN (Ptr<Socket> s, const Address& from);

  /**
   * \brief Handle a connection close from the KMS.
   * \param socket The connected socket.
   */
  void HandlePeerCloseKMSs (Ptr<Socket> socket);
  
  /**
   * \brief Handle a connection close from the SDN.
   * \param socket The connected socket.
   */
  void HandlePeerCloseSDN (Ptr<Socket> socket);
  
  /**
   * \brief Handle a connection error from the KMS.
   * \param socket The connected socket.
   */
  void HandlePeerErrorKMSs (Ptr<Socket> socket);

  /**
   * \brief Handle a connection error from the SDN.
   * \param socket The connected socket.
   */
  void HandlePeerErrorSDN (Ptr<Socket> socket);

  /**
   * \brief Assemble a byte stream from the application to extract the HTTP message.
   * \param p The received packet.
   * \param from The packet origin address.
   * \param socket The receiving socket.
   */
  void PacketReceived (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);
  
  /**
   * \brief Assemble a byte stream from the peer KMS to extract the HTTP message.
   * \param p The received packet.
   * \param from The packet origin address.
   * \param socket The receiving socket.
   */
  void PacketReceivedKMSs (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

  /**
   * \brief Assemble a byte stream from the SDN to extract the HTTP message.
   * \param p The received packet.
   * \param from The packet origin address.
   * \param socket The receiving socket.
   */
  void PacketReceivedSDN (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);


  /**
   * \brief Process incoming requests from the service layer, i.e., QKD applications.
   * \param header The received HTTP message.
   * \param packet The received packet.
   * \param socket The receiving socket.
   */
  void      ProcessRequest(HTTPMessage header, Ptr<Packet> packet, Ptr<Socket> socket);

  /**
   * \brief Process incoming request at the KM link.
   * \param header The received HTTP message.
   * \param packet The received packet.
   * \param socket The receiving socket.
   */
  void      ProcessPacketKMSs(HTTPMessage header, Ptr<Packet> packet, Ptr<Socket> socket);

  /**
   * \brief Process response from the SDN controller.
   * \param header The received HTTP message.
   * \param packet The received packet.
   * \param socket The receiving socket.
   */
  void      ProcessResponseSDN (HTTPMessage header, Ptr<Packet> packet, Ptr<Socket> socket);

  /**
   * \brief Process request from the SDN controller.
   * \param header The received HTTP message.
   * \param packet The received packet.
   * \param socket The receiving socket.
   */
  void      ProcessRequestSDN (HTTPMessage header, Ptr<Packet> packet, Ptr<Socket> socket);

  /**
   * \brief Process request from the peer KMS.
   * \param header The received HTTP message.
   * \param socket The receiving socket.
   */
  void      ProcessRequestKMS (HTTPMessage header, Ptr<Socket> socket);

  /**
   * \brief Process response from the peer KMS.
   * \param header The received HTTP message.
   * \param packet The received packet.
   * \param socket The receiving socket.
   */
  void      ProcessResponseKMS (HTTPMessage header, Ptr<Packet> packet, Ptr<Socket> socket);

  /**
   * \brief Process request from the QKD post-processing application.
   * \param header The received HTTP message.
   * \param packet The received packet.
   * \param socket The receiving socket.
   */
  void      ProcessPPRequest (HTTPMessage header, Ptr<Packet> packet, Ptr<Socket> socket);

  /*
   * \brief Process the OPEN_CONNECT request - ETSI QKD GS 004.
   * \param header The received HTTP message.
   * \param socket The receiving socket.
   */
  void      ProcessOpenConnectRequest(HTTPMessage header, Ptr<Socket> socket); 

  /*
   * \brief Process the GET_KEY request - ETSI QKD GS 004.
   * \param ksid The key stream identifier.
   * \param header The received HTTP message.
   * \param socket The receiving socket.
   */
  void      ProcessGetKey004Request(std::string ksid, HTTPMessage header, Ptr<Socket> socket);

  /*
   * \brief Process the CLOSE request - ETSI QKD GS 004.
   * \param ksid The key stream identifier.
   * \param header The received HTTP message.
   * \param socket The receiving socket.
   */
  void      ProcessCloseRequest(std::string ksid, HTTPMessage header, Ptr<Socket> socket);

  /*
   * \brief Process the NEW_APP request.
   * \param header The received HTTP message.
   * \param socket The receiving socket.
   *
   * The KMS process the NEW_APP request received from the peer KMS. This request
   * notifies the KMS about a new key stream session.
   */
  void      ProcessNewAppRequest(HTTPMessage header, Ptr<Socket> socket);
  
  /**
   * \brief Process the NEW_APP response.
   * \param header The received HTTP message.
   * \param socket The receiving socket.
   *
   * The KMS receives a response on a NEW_APP request. This response idicates success
   * of registering the key stream session from the peer KMS.
   */
  void      ProcessNewAppResponse (HTTPMessage header, Ptr<Socket> socket);

  /**
   * \brief Send the REGISTER request.
   * \param ksid The key stream identifier.
   * 
   * The KMS notifies peer KMS that receiving application has registered for the established key stream session
   * by submitting OPEN_CONNECT request.
   */
  void      RegisterRequest (std::string ksid);

  /**
   * \brief Process the REGISTER request.
   * \param header The received HTTP message.
   * \param ksid The key stream identifier.
   * \param socket The receiving socket.
   *
   * The KMS process the REGISTER request, and starts assigning key material to the key stream session.
   */
  void      ProcessRegisterRequest (HTTPMessage header, std::string ksid, Ptr<Socket> socket);

  /**
   * \brief Process the REGISTER response.
   * \param header The received message.
   * \param socket The receiving socket.
   *
   * The KMS simply acknowledges that the peer KMS has process the REGISTER request.
   */
  void      ProcessRegisterResponse(HTTPMessage header, Ptr<Socket> socket);
  
  /**
   * \brief Prepare the sink socket.
   */
  void      PrepareSinkSocket ();

  /**
   * \brief Process the FILL request.
   * \param h The received HTTP message.
   * \param socket The receiving socket.
   * \param ksid The key stream session identifier.
   *
   * The KMS processes the proposal of keys to be assigned to the key stream session
   * identifier with the given KSID. The proposal is issued by the initiating KMS, the
   * one that serves the sender application.
   */
  void      ProcessAddKeysRequest (HTTPMessage h, Ptr<Socket> socket, std::string ksid);

  /**
   * \brief Process the FILL response.
   * \param header The received HTTP message.
   * \param socket The receiving socket.
   *
   * Process the response of the FILL request. The KMS assignes QKD keys that have
   * been accepted by the peer KMS, to the key stream session.
   */
  void      ProcessAddKeysResponse (HTTPMessage header, Ptr<Socket> socket);
  
  /**
   * \brief Transform a number of keys to a given size.
   * \param keySize The key size.
   * \param keyNumber The key number.
   * \param slave_SAE_ID The destination (receiver) application identifier.
   * 
   * The KMS uses available keys and transforms them to a given number and size.
   * Transformed keys are assigned a new key identifiers. The transformation request
   * is sent to the peer KMS.
   */
  void      TransformKeys (uint32_t keySize, uint32_t keyNumber, UUID slave_SAE_ID);

  /**
   * \brief Process the transform request.
   * \param header The received HTTP message.
   * \param socket The receiving socket.
   * 
   * The KMS processes transform request by transformim the same set of keys
   * to a given number and size, as requested from the peer KMS. The success indicator
   * is sent as a response.
   */
  void      ProcessTransformRequest(HTTPMessage header, Ptr<Socket> socket);

  /**
   * \brief Process the transform response.
   * \param header The received HTTP message.
   * \param socket The receiving socket.
   *
   * The KMS acknowledges the peer KMS response status. On success, it mark transformed keys are READY.
   */
  void      ProcessTransformResponse(HTTPMessage header, Ptr<Socket> socket);

  /**
   * \brief Process the close request from the peer KMS.
   * \param header The received HTTP message.
   * \param socket The receiving socket.
   * \param ksid The key sream identifier.
   * 
   * When the QKDApp initiates ETSI 004 close request, the local KMS should release QKD keys
   * currently assign to the key stream session. To do so, the KMS should sync with the peer KMS.
   * This function perform the necessery processing on the peer KMS to do sync. 
   */
  void      ProcessKMSCloseRequest (HTTPMessage header, Ptr<Socket> socket, std::string ksid);

  /**
   * \brief Process close response from the peer KMS.
   * \param header The received HTTP message.
   * \param socket The receiving socket.
   */
  void      ProcessKMSCloseResponse(HTTPMessage header, Ptr<Socket> socket);

  /**
   * \brief Release the key stream session.
   * \param ksid The key stream session identifier.
   * \param surplusKeyId The key identifier for the surplus key material in the key stream session buffer.
   * \param syncIndex The key index in the key stream session buffer for synchronisation purposes.
   */
  void      ReleaseAssociation (std::string ksid, std::string surplusKeyId, uint32_t syncIndex);

  /**
   * \brief Validate the request and probe if the KMS can meet the request requirements.
   * \param request The JSON payload of the ETSI 014 GET_KEY request.
   * \param conn The connection details.
   * \return The JSON error structure (if any errors).
   */
  nlohmann::json Check014GetKeyRequest(nlohmann::json request, QKDKeyAssociationLinkEntry conn);

  /**
   * \brief Create the key container data structure.
   * \param keys The vector QKD keys to supply.
   * \return The JSON data structure for the key container.
   */
  nlohmann::json CreateKeyContainer (std::vector<Ptr<QKDKey>> keys);

  /**
   * \brief Base64 encoder.
   * \param input The input data.
   * \return The Base64 encoded input.
   */
  std::string Base64Encode(std::string input);

  /**
   * \brief Base64 decoder.
   * \param input The input data.
   * \return The decoded input.
   */
  std::string Base64Decode(std::string input);

  /**
   * \brief Read the URI parameters in a vector.
   * \param s The HTTP request URI.
   * \return The vector of URI parameters.
   */
  std::vector<std::string> ProcessUriParams(std::string s);

  /**
   * \brief Purge (delete) the expired ETSI 004 key stream sessions based on the QoS - TTL value.
   */
  void PurgeExpiredAssociations();

private:

  /**
   * The Quality of service indicators.
   */
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

  /**
   * The key within the key stream session buffer.
   */
  struct ChunkKey
  {
    uint32_t index;
    uint32_t chunkSize;
    bool ready;
    std::string key; //key of key_chunk_size
    //std::vector<std::pair<std::string, std::pair<uint32_t, uint32_t> > > keyIds; //"QKDKey"s that form ChunkKey
                        //keyId                  start      end
  };

  /**
   * The HTTP request details.
   */
  struct HttpQuery
  {
    RequestType method_type; //For every query!
    
    //Specific to TRANSFORM
    uint32_t transform_key_size;
    uint32_t transform_key_number;
    std::vector<std::string> transform_key_IDs;
    std::vector<std::string> to_transform_key_IDs;
    std::string surplus_key_ID;
    UUID sae_id; //Needed to specify buffer to fetch the key from

    //Specific to ETSI 004 (NEW_APP)
    UUID source_sae;
    UUID destination_sae;
    std::string ksid;

    //Specific to ETSI 004 (KMS CLOSE)
    uint32_t sync_index;

  };

  /**
   * The key stream session details.
   */
  struct Association004 //Holds information of the association and dedicated key store
  {
    UUID ksid;
    UUID srcSaeId; //Source application that requested the KSID
    UUID dstSaeId; //Destination application 
    uint32_t associationDirection; //0-Outbound, 1-Inbound - Important while monitoring the associations!
    QoS qos; //Quality of service
    Ipv4Address dstKmsNode; //Address of the destination KMS. Important!
    bool peerRegistered; //KMS must know the state of connection for association on peer KMS!
    std::map<uint32_t, ChunkKey> buffer; //index & key ; index is KeyId for key of the association
    uint32_t lastIndex;
    std::vector<std::string> tempBuffer; //Buffer for keys in negotiation. It holds only KeyIds, while keys are in QKDBuffer!
  };

  std::map<std::string, Association004> m_associations004; //!< The list of active key stream sessions.
  Ptr<Socket>     m_sinkSocket;           //!< The sink socket
  Ptr<Socket>     m_sendSocketToSDN;      //!< The send socket to the SDN controller.
  Ptr<Socket>     m_sinkSocketFromSDN;    //!< The sink socket from the SND controller.
  Ipv4Address     m_local;                //!< Local address to bind to.
  uint32_t        m_port;                 //!< Local port to bind to.
  uint32_t        m_totalRx;              //!< Total bytes received.
  uint32_t        m_totalRxKMSs;          //!< Total bytes sent between KMSs.
  TypeId          m_tid;                  //!< The object type identifier.
  uint32_t        m_kms_id;               //!< The KMS identifier.
  uint32_t        m_kms_key_id;           //!< The counter value to assure generation of the unique key identifiers.
  EventId         m_closeSocketEvent;     //!< The close socket event.
  Ptr<UniformRandomVariable> m_random;    //!< The uniform random variable.

  std::map<uint32_t, EventId > m_scheduledChecks; //!< The scheduled events.
  std::map<Ipv4Address, uint32_t> m_flagedIPAdr;  //!< A list of flaged IP addresses.
  uint32_t        m_maliciousBlocking;            //!< Should KMS detect and block malicious requests?

  TracedCallback<Ptr<const Packet>, const Address &> m_rxTrace;     //!< A trace for the received packets from the applications.
  TracedCallback<Ptr<const Packet> > m_txTrace;                     //!< A trace for the sent packets to the applications.
  TracedCallback<Ptr<const Packet>, const Address &> m_rxTraceKMSs; //!< A trace for the received packets from the peer KMS.
  TracedCallback<Ptr<const Packet> > m_txTraceKMSs;                 //!< A trace for the sent packets to the peer KMS.
  TracedCallback<Ptr<const Packet>, const Address &> m_rxTraceSDN;  //!< A trace for the received packets from the SDN controller.
  TracedCallback<Ptr<const Packet> > m_txTraceSDN;                  //!< A trace for the sent packets to the SDN controller.
  TracedCallback<const Ipv4Address&, Ptr<const Packet> > m_dropTrace; //!< A trace for the dropped packets.
 
  TracedCallback<const uint32_t&> m_newKeyGeneratedTraceEmir; //!< A trace for the generated keys.
  TracedCallback<const uint32_t&> m_keyServedTraceEmir;       //!< A trace for the consumed keys.

  TracedCallback<const uint32_t& , const uint32_t&> m_newKeyGeneratedTrace; //!< A trace for the generated keys.

  TracedCallback<const std::string &, Ptr<QKDKey> > m_keyServedETSI014Trace; //!< A trace for the consumed keys by the ETSI 014 clients.
  TracedCallback<const std::string &, const uint32_t&, const uint32_t& > m_keyServedETSI004Trace; //!< A trace for the consumed keys by the ETSI 004 clients.

  TracedCallback<   
    const std::string &, 
    const std::string &, 
    const uint32_t&, 
    const uint32_t&, 
    const uint32_t&, 
    const uint32_t&, 
    const uint32_t&
  > m_providedQoS; //!< A trace for the admitted QoS.
  
  uint32_t        m_maxKeyPerRequest; //!< The maximal number of keys per request application can ask for.
  uint32_t        m_minKeySize; //!< The minimal size of the key application can request.
  uint32_t        m_maxKeySize; //!< The maximal size of the key application can request.
  uint32_t        m_defaultKeySize; //!< The default key size KMS will deliver if the size was not defined in the request.

  std::unordered_map<uint64_t, Ptr<Packet>, AddressHash> m_buffer; //!< The buffer for the received packets from the applications (TCP segmentation).
  std::unordered_map<Address, Ptr<Packet>, AddressHash> m_bufferKMS; //!< The buffer for the received packets from the peer KMS (TCP segmentation).

  // In the case of TCP, each socket accept returns a new socket, so the
  // listening socket is stored separately from the accepted sockets
  std::map<Ptr<Socket>, Ptr<Socket> > m_socketPairs;  //!< The accepted sockets.

  std::map<Ipv4Address, std::pair<Ptr<Socket>, Ptr<Socket> > > m_socketPairsKMS;  //!< The accepted sockets for the communication between KMSs.

  Ptr<Node> m_node; //<! The node on which the KMS is installed.
  std::map<Ptr<Socket>, Ptr<Packet> > m_packetQueues; //!< Buffering unsend messages due to the connection problems.
  std::map<Ptr<Socket>, Ptr<Packet> > m_packetQueuesToSDN; //!< Buffering unsend messages due to the connection problems.

  Ptr<QKDKMSQueueLogic> m_queueLogic; //!< The KMS Queue Logic for the ETSI 004 QoS handling.

  std::map<std::string, uint32_t> m_sessionList; //!< A list of sessions.
  double m_qos_maxrate_threshold; //!< The maximal rate threshold.

  /**
   * \brief Check whether a new OPEN_CONNECT was received before the previously established 
   * session expired. If yes, remove the KSID from the m_session_list. 
   * If not, incerment the value in m_session_list for a given KSID.
   * \param ksid The key stream session identifier.
   */
  void CheckSessionList(std::string ksid);


  DataRate        m_maxKeyRate; //!< The maximal key rate.
  DataRate        m_minKeyRate; //!< The minimal key rate.
  uint32_t        m_default_ttl; //!< The default value of TTL.

  bool connectedToSDN; //!< Is conncted to the SDN controller?
  
  /**
   * \brief Callback function after the connection to the APP is complete.
   * \param socket The connected socket.
   */
  void ConnectionSucceeded (Ptr<Socket> socket);

  /**
   * \brief Callback function after the connection to the APP has failed.
   * \param socket The connected socket.
   */
  void ConnectionFailed (Ptr<Socket> socket);

  /**
   * \brief Callback function for the data sent.
   * \param The connected socket.
   * \param The amount of data sent.
   */
  void DataSend (Ptr<Socket>, uint32_t); // for socket's SetSendCallback

  /**
   * \brief Callback function after the connection to the peer KMS is complete.
   * \param socket The connected socket.
   */
  void ConnectionSucceededKMSs (Ptr<Socket> socket);

  /**
   * \brief Callback function after the connection to the peer KMS has failed.
   * \param socket The connected socket.
   */
  void ConnectionFailedKMSs (Ptr<Socket> socket);

  /**
   * \brief Callback function for the data sent to the peer KMS.
   * \param The connected socket.
   * \param The amount of data sent.
   */
  void DataSendKMSs (Ptr<Socket>, uint32_t); // for socket's SetSendCallback

  /**
   * \brief Callback function after the connection to the SDN controller is complete.
   * \param socket The connected socket.
   */
  void ConnectionToSDNSucceeded (Ptr<Socket> socket);

  /**
   * \brief Callback function after the connection to the SDN controller has failed.
   * \param socket The connected socket.
   */
  void ConnectionToSDNFailed (Ptr<Socket> socket);

  /**
   * \brief Callback function for the data sent to the SDN controller.
   * \param The connected socket.
   * \param The amount of data sent.
   */
  void DataToSDNSend (Ptr<Socket>, uint32_t); // for socket's SetSendCallback

  /**
   * \brief Check for the DoS attack.
   * \param header The received HTTP message.
   * \param socket The receiving socket.
   */
  bool CheckDoSAttack(HTTPMessage headerIn, Ptr<Socket> socket);

  std::map<Ipv4Address, std::vector<HttpQuery> > m_httpRequestsQueryKMS; //!< The list of HTTP request (without response) sent to the peer KMS.
  std::multimap<UUID, Ptr<Socket> > m_http004App; //!< The list of HTTP requests (without response) set to the application. 
  
  /**
   * \brief Remember the HTTP request made to the peer KMS.
   * \param dstKms The destination KMS IP address.
   * \param request The HTTP request details.
   */
  void  HttpKMSAddQuery(Ipv4Address dstKms, HttpQuery request);

  /**
   * \brief Remove the HTTP request from the list.
   * \param dstKms The destination KMS IP address.
   */
  void  HttpKMSCompleteQuery(Ipv4Address dstKms);

  /**
   * \brief Map the HTTP response and obtain the request method.
   * \param dstKms The destination KMS IP address.
   * \return The request method.
   */
  RequestType HttpQueryMethod(Ipv4Address dstKms);

  /**
   * \brief Remember the HTTP request received from the application.
   * \param saeId The application identifier.
   * \param socket The receiving socket.
   */
  void  Http004AppQuery (UUID saeId, Ptr<Socket> socket);

  /**
   * \brief Remove the HTTP request from the list.
   * \param saeId The application identifier.
   */
  void  Http004AppQueryComplete (UUID saeId);

  /**
   * \brief Lookup the HTTP request and obtain connected socket.
   * \param saeId The application identifier.
   * \return The connected socket.
   */
  Ptr<Socket> GetSocketFromHttp004AppQuery (UUID saeId);

  /**
   * \brief Get the destiantion KMS IP address based on the connected socket.
   * \param socket The connected socket.
   * \return The KMS IP address.
   */
  Ipv4Address GetDestinationKmsAddress (Ptr<Socket> socket);

  /**
   * \brief Prepare the send socket to communicate with the peer KMS.
   * \param dstSaeId The destination KMS IP address.
   */
  void CheckSocketsKMS (Ipv4Address dstSaeId);

  /**
   * \brief Obtain the send socket.
   * \param kmsDstAddress The destination KMS IP address.
   * \return The send socket.
   */
  Ptr<Socket> GetSendSocketKMS (Ipv4Address kmsDstAddress);

  /**
   * \brief Convert the packet to a string.
   * \param packet The packet.
   * \return The packet content in the string format.
   */
  std::string PacketToString (Ptr<Packet> packet);

  /**
   * \brief Read the QoS parameters from the JSON OPEN_CONNECT structure.
   * \param &inQoS The QoS structure to write read parameters.
   * \param jOpenConncetRequest The JSON structure to read.
   */
  void  ReadJsonQos (  
      QKDKeyManagerSystemApplication::QoS &inQos, 
      nlohmann::json jOpenConnectRequest );
  
  /**
   * \brief Create a new key stream session.
   * \param srcSaeId The source application identifier
   * \param dstSaeId The destination application identifier.
   * \param inQos The Quality of Service details.
   * \param dstKms The destination KMS IP address.
   * \param ksid The key stream identifier.
   * \return The key stream identifier.
   *
   * Input ksid can be empty if it is not predefined. In that case
   * a new ksid is generated for this new association and returned from
   * the function.
   */
  void CreateNew004Association (
      std::string srcSaeId, 
      std::string dstSaeId, 
      QKDKeyManagerSystemApplication::QoS &inQos, 
      Ipv4Address dstKms, 
      std::string &ksid,
      std::string appConnectionId
  );

  /**
   * \brief Process the QoS requirements.
   * \param &appConnection The application connection details.
   * \param &keyAssociation The key association details.
   * \param &inQoS The requested QoS levels.
   * \param &outQoS The best QoS levels that the KMS can meet (in inQoS can not be satified).
   * \param ksid The key stream identifier.
   * \return The QoS check status indicator.
   */
  bool ProcessQoSRequest(
    QKDApplicationEntry &appConnection,
    QKDKeyAssociationLinkEntry &keyAssociation,
    QKDKeyManagerSystemApplication::QoS &inQos,
    QKDKeyManagerSystemApplication::QoS &outQos,
    std::string ksid
  );  

  /**
   * \brief Make a NEW_APP request to the peer KMS.
   * \param ksid The key stream identifier.
   */
  void  NewAppRequest (std::string ksid);

  /**
   * \brief Generate a new key stream session identifier (ksid).
   * \return The key stream identifier.
   */
  std::string GenerateKsid ();

  /**
   * \breif Monitor the state of the existing key stream sessions.
   */
  void  MonitorAssociations ();

  /**
   * \brief Check the state of a single key stream session.
   * \param ksid The key stream identifier.
   */
  void  CheckAssociation (std::string ksid);

  /**
   * \brief Schedule the next event in the attempt to fill the key stream session buffer.
   * \param t The time shift.
   * \param action The name of the action.
   * \param ksid The key stream identifier.
   * \return The scheduled event identifier.
   */
  uint32_t  ScheduleCheckAssociation(Time t, std::string action, std::string ksid);

  /**
   * \brief Add new keys to the key stream session buffer.
   * \param ksid The key stream identifier.
   * \param keyAmount The minimal amount of key material in bits to be assigned to the buffer (1024 bits as default).
   * \param priority The priority of the application (0 as default). Defines whether to mantain the key association after keys are depleted.
   */
  void  NegotiateKeysForAssociation (std::string ksid, uint32_t keyAmount = 1024, uint32_t priority = 0);

  /**
   * \brief Add the key to the key stream session buffer.
   * \param ksid The key stream identifier.
   * \param key The key.
   */
  void  AddKeyToAssociationDedicatedStore (std::string ksid, Ptr<QKDKey> key);

  /**
   * \brief Generate unique key identifier.
   * \return The unique key identifier.
   */
  std::string GenerateKeyId();
 

};

} // namespace ns3

#endif /* QKD_APPLICATION_H */

