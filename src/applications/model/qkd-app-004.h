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
#ifndef QKD_SEND_H004
#define QKD_SEND_H004

#include "ns3/application.h"
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/traced-callback.h"
#include "ns3/address.h"
#include "ns3/core-module.h"
#include "ns3/applications-module.h"
#include "ns3/random-variable-stream.h"
#include "ns3/core-module.h" 
#include "ns3/http.h"
#include "qkd-app-header.h"
#include "ns3/qkd-encryptor.h"
#include <unordered_map> 
#include <string> 
#include "ns3/uuid.h"

#include <iostream>
#include <sstream>
#include <unistd.h>

namespace ns3 {

class Address;
class Socket;
class Packet;

/**
 * \ingroup applications 
 * \defgroup QKDApp QKDApp004
 *
 * The QKDApp004 application implements communication 
 * to Local Key Management System and it establish secure
 * communciation with counter-part QKDApp.
 */

/**
 * \ingroup QKDApp
 *
 * \brief Establish secure communication on application lavel to use the key and test LKSM
 *
 * This application was written to complement simple application to consume keys
 * so a generic QKDApp name was selected. The application (Alice) implements sockets for
 * connection with counter-party application (Bob) and implements sockets for 
 * communication with local key management system. The applications use ETSI QKD 004 interface
 * to communicate with LKSM, hence the name "QKDApp004".
 *
 */
class QKDApp004 : public Application 
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
    QKDApp004 ();

    /**
     * \brief Destructor.
     */
    virtual     ~QKDApp004();

    /**
     * \brief Set encryption key stream identifier.
     * \param val The key stream identifier.
     */
    void SetKsidEncryption(UUID val){
        m_ksid_enc = val;
    }

    /**
     * \brief Set authentication key stream identifier.
     * \param val The key stream identifier.
     */
    void SetKsidAuthentication(UUID val){
        m_ksid_auth = val;
    }
    
    /**
     * The QKD application states.
     */
    enum QKDAppState {
        NOT_STARTED,
        INITIALIZED,
        ESTABLISHING_ASSOCIATIONS,
        ASSOCIATIONS_ESTABLISHED,
        ESTABLISHING_KEY_QUEUES,
        KEY_QUEUES_ESTABLISHED, 
        READY,
        WAIT,
        SEND_DATA,
        DECRYPT_DATA,
        STOPPED
    };

    /**
     * \brief Configure the application.
     * \param socketType The socket type.
     * \param src The source address.
     * \param dst The destination address.
     * \param kms The local key manager address.
     * \param dstSaeId The remote application identifier.
     * \param type Type of the application, the sender or the receiver.
     */
    void        Setup (
        std::string socketType,
        Address src,  
        Address dst,   
        Address kms,   
        UUID dstSaeId,
        std::string type
    );

    /**
     * \brief Configure the application.
     * \param socketType The socket type.
     * \param src The source address.
     * \param dst The destination address.
     * \param kms The local key manager address.
     * \param dstSaeId The remote application identifier.
     * \param packetSize The packet size that is transmitted.
     * \param dataRate The rate at which packets are transmitted.
     * \param type Type of the application, the sender or the receiver.
     */
    void        Setup (
        std::string socketType,
        Address src,
        Address dst, 
        Address kms,   
        UUID dstSaeId,
        uint32_t packetSize,
        uint32_t nPackets,
        DataRate dataRate,
        std::string type
    );

    /**
     * The KMS packet.
     */
    struct      KMSPacket
    {
        Ptr<Packet> packet = 0;
        uint32_t methodType = 0;
        uint32_t keyType = 0;
        std::string ksid = "";
        std::string uri = "";
    };

    /**
     * \brief Schedule the action.
     * \param t The scheduled time.
     * \param action The action.
     * \return The identifier of the scheduled event.
     */
    uint32_t    ScheduleAction(Time t, std::string action);
 

    /**
     * \brief Cancel the scheduled event.
     * \param The identifier of the scheduled event.
     */
    void        CancelScheduledAction(uint32_t eventId);

    /**
     * \brief Callback function after the connection to the KMS has failed.
     * \param socket The connected socket.
     */
    void        ConnectionToKMSFailed (Ptr<Socket> socket);

    /**
     * \brief Callback function after the connection to the KMS is complete.
     * \param socket The connected socket.
     */
    void        ConnectionToKMSSucceeded (Ptr<Socket> socket);

    /**
     * \brief Callback function after the connection to the APP has failed.
     * \param socket The connected socket.
     */
    void        ConnectionToAppFailed (Ptr<Socket> socket);

    /**
     * \brief Callback function after the connection to the APP is complete.
     * \param socket The connected socket.
     */
    void        ConnectionToAppSucceeded (Ptr<Socket> socket);

    /**
     * \brief Callback function after the signaling connection to the APP has failed.
     * \param socket The connected socket.
     */
    void        ConnectionSignalingToAppFailed (Ptr<Socket> socket);

    /**
     * \brief Callback function after the signaling connection to the APP is complete.
     * \param socket The connected socket.
     */
    void        ConnectionSignalingToAppSucceeded (Ptr<Socket> socket);

    /**
     * \brief Callback function to notify that data to KMS has been sent.
     * \param The connected socket.
     * \param The amount of data sent.
     */
    void        DataToKMSSend (Ptr<Socket>, uint32_t);

    /**
     * \brief Handle a packet received by the QKD application from the KMS application.
     * \param socket The receiving socket.
     */
    void        HandleReadFromKMS (Ptr<Socket> socket);

    /**
     * \brief Handle a connection close from the KMS.
     * \param socket The connected socket.
     */
    void        HandlePeerCloseFromKMS (Ptr<Socket> socket);

    /**
     * \brief Handle a connection close to the KMS.
     * \param socket The connected socket.
     */
    void        HandlePeerCloseToKMS (Ptr<Socket> socket);

    /**
     * \brief Handle a connection error from the KMS.
     * \param socket The connected socket.
     */
    void        HandlePeerErrorFromKMS (Ptr<Socket> socket);
    
    /**
     * \brief Handle a connection error to the KMS.
     * \param socket The connected socket.
     */
    void        HandlePeerErrorToKMS (Ptr<Socket> socket);
    
    /**
     * \brief Handle an incoming connection from the KMS.
     * \param s The incoming connection socket.
     * \param from The address the connection is from.
     */
    void        HandleAcceptFromKMS (Ptr<Socket> s, const Address& from);

    /**
     * \brief Handle a packet received from the peer QKD application.
     * \param socket The receiving socket.
     */
    void        HandleReadFromApp (Ptr<Socket> socket);

    /**
     * \brief Handle a connection close from the peer QKD application.
     * \param socket The connected socket.
     */
    void        HandlePeerCloseFromApp (Ptr<Socket> socket);

    /**
     * \brief Handle a connection error from the peer QKD application.
     * \param socket The connected socket.
     */
    void        HandlePeerErrorFromApp (Ptr<Socket> socket);
    
    /**
     * \brief Handle an incoming connection from the peer QKD application.
     * \param s The incoming connection socket.
     * \param from The address the connection is from.
     */
    void        HandleAcceptFromApp (Ptr<Socket> s, const Address& from);

    /**
     * \brief Handle a signaling packet received from the peer QKD application.
     * \param socket The receiving socket.
     */
    void        HandleReadSignalingFromApp (Ptr<Socket> socket);

    /**
     * \brief Handle a signaling connection close from the peer QKD application.
     * \param socket The connected socket.
     */
    void        HandlePeerCloseSignalingFromApp (Ptr<Socket> socket);

    /**
     * \brief Handle a signaling connection error from the peer QKD application.
     * \param socket The connected socket.
     */
    void        HandlePeerErrorSignalingFromApp (Ptr<Socket> socket);
    
    /**
     * \brief Handle a signaling incoming connection from the peer QKD application.
     * \param s The incoming connection socket.
     * \param from The address the connection is from.
     */
    void        HandleAcceptSignalingFromApp (Ptr<Socket> s, const Address& from);

    /**
     * \brief Register the acknowledgement time.
     * \param oldRtt The previous round-trip time.
     * \param newRtt The new rount-trip time.
     */
    void        RegisterAckTime (Time oldRtt, Time newRtt);

    /**
     * \brief Callback function after the connection for response from the KMS has been received.
     * \param socket The connected socket.
     * \param address The address of the KMS.
     */
    bool        ConnectionRequestedFromKMS (Ptr<Socket> socket, const Address &address);

    /**
     * \brief Prepare the sink socket to listen from the KMS Application.
     */
    void        PrepareSinkSocketFromKMS();

    /**
     * \brief Prepare the send socket to communicate with the KMS Application.
     */
    void        PrepareSendSocketToKMS();

    /**
     * \brief Prepare the sink socket to listen from the peer QKD Application.
     */
    void        PrepareSinkSocketFromApp();

    /**
     * \brief Prepare the send socket to communicate with the peer QKD Application.
     */
    void        PrepareSendSocketToApp();
    
    /**
     * \brief Check for the tcp segmentation of packets received from the KMS.
     * \param p The received packet.
     * \param from The address of the KMS.
     * \param socket The connected socket.
     */
    void        PacketReceivedFromKMS (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

    /**
     * \brief Check for the tcp segmentation of the signaling packets received from the peer application.
     * \param p The received packet.
     * \param from The address of the KMS.
     * \param socket The connected socket.
     */
    void        SignalingPacketReceivedFromApp (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

    /**
     * \brief Check for the tcp segmentation of the signaling packets received from the KMS.
     * \param p The received packet.
     * \param from The address of the KMS.
     * \param socket The connected socket.
     */
    void        DataPacketReceivedFromApp (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

    /**
     * \brief Process a response from the KMS application.
     * \param header The received HTTP message.
     * \param packet The received packet.
     * \param socket The receiving socket.
     */
    void        ProcessResponseFromKMS(HTTPMessage& header, Ptr<Packet> packet, Ptr<Socket> socket);

    /**
     * \brief Process a signaling packets from the peer QKD application.
     * \param header The received HTTP message.
     * \param packet The received packet.
     * \param socket The receiving socket.
     */
    void        ProcessSignalingPacketFromApp(HTTPMessage& header, Ptr<Socket> socket);

     /**
     * \brief Process data packets from the peer QKD application.
     * \param header The received QKDApp packet header.
     * \param packet The received packet.
     * \param socket The receiving socket.
     */
    void        ProcessDataPacketFromApp(QKDAppHeader header, Ptr<Packet> packet, Ptr<Socket> socket);

    /**
     * \brief Request a key stream session (an association) from the local KMS.
     * \param ksid The key stream session identifier.
     * \param keyType The key type.
     *
     * Replica (or receiving) QKDApp always states KSID in OPEN_CONNECT call.
     * Primary (or sender) QKDApp does not state KSID (design decision).
     * Each QKDApp is limited (by design decisions) to establish up to 2
     * associations (one for the encryption and one for the authentification).
     * QKDApps are able to establish unidirectional communication
     * with one peer QKDApp.
     */
    void        OpenConnect (std::string ksid, uint32_t keyType = 0);

    /**
     * \brief Get key for the key stream.
     * \param ksid The key stream session identifier.
     * \param index The position of the key within the key stream. (optional)
     *
     * Note QKDApps request keys in an ordered manner. Access by the index is currently not supported.
     */
    void        GetKeyFromKMS (std::string ksid, uint32_t index = 0);
 
    /**
     * \brief Close the keys stream session (the association).
     * \param ksid The key stream session identifier.
     */
    void        Close (std::string ksid);

    /**
     * \brief Process the OPEN_CONNECT response.
     * \param header The received HTTP message.
     */
    void        ProcessOpenConnectResponse (HTTPMessage& header);

    /**
     * \brief Process the GET_KEY response.
     * \param header The received HTTP message.
     */
    void        ProcessGetKeyResponse (HTTPMessage& header);

    /**
     * \brief Process the CLOSE response.
     * \param header The received HTTP message.
     */
    void        ProcessCloseResponse (HTTPMessage& header);

    /**
     * \brief Inform the peer QKD application of the established key stream session.
     * \param ksid The key stream session identifier.
     * \param input The key stream session purpose.
     */
    void    SendKsidRequest (std::string ksid, uint32_t input);
    
    /**
     * \brief Send a response on the SEND_KSID request.
     * \param httpStatus The HTTP status code.
     * \param msg The error message (if any).
     */
    void    SendKsidResponse (HTTPMessage::HttpStatus httpStatus, std::string msg = "");

    /**
     * \brief Process the SEND_KSID response.
     * \param header The received HTTP message.
     * \param ksid The key stream indentifier.
     */
    void    ProcessSendKsidResponse (HTTPMessage& header, std::string ksid);

    /*
     * \brief Create a key stream session entry.
     */
    void    CreateKeyStreamAssociations ();

    /**
     * \brief Set the encryption and the authentication algorithms.
     * \param ecryptionType The encryption algorithm.
     * \param authenticationType The authentication algorithm.
     * \param authenticationTagLengthInBits The size of the authentication tag.
     */ 
    void        SetEncryptionAndAuthenticationSettings(
      uint32_t encryptionType, 
      uint32_t authenticationType,
      uint32_t authenticationTagLengthInBits
    );

    /**
     * \brief Get the required key size for the choosen encryption algorithm.
     * \return The key size.
     */
    uint32_t    GetEncryptionKeySize();

    /**
     * \brief Get the required key size for the choosen authentication algorithm.
     * \return The key size.
     */
    uint32_t    GetAuthenticationKeySize ();

    /**
     * \brief Get the maximum key rate required for the encryption (QoS settings).
     * \return The key rate (bps).
     */
    uint64_t    GetMaxEncryptionKeyRate();

    /**
     * \brief Get the maximum key rate required for the authentication (QoS settings).
     * \return The key rate (bps).
     */
    uint64_t    GetMaxAuthenticationKeyRate();
  
    /**
     * \brief Get the current state of the application.
     * \return The current state.
     */
    QKDAppState GetAppState () const;

    /**
     * \brief Get the current state of the application in a string notation.
     * \return The current state.
     */
    std::string GetAppStateString () const;

    /**
     * \brief Convert application state to a string notation.
     * \param state The application state.
     * \return The application state in the string notation.
     */
    static std::string GetAppStateString (QKDAppState state);

    /**
     * \brief Change the state of the application.
     * \param state The new application state.
     */
    void SwitchAppState (QKDAppState state);

    /**
     * \brief Get the application identifier.
     * \return The application identifier.
     */
    UUID GetId (void) {
        return m_id;
    }

    /**
    * \brief Generate a random packet payload (the message).
    * \param msgLength The length of the message.
    * \return The random message.
    */
    std::string GetPacketContent(uint32_t msgLength = 0);

    TracedCallback<Ptr<const Packet>, std::string > m_txTrace; //<! A trace for transmitted data packets.
    TracedCallback<Ptr<const Packet> > m_txSigTrace; //!< A trace for transmitted signaling packets.
    TracedCallback<Ptr<const Packet> > m_txKmsTrace; //!< A trace for transmitted packets to the KMS.
    TracedCallback<Ptr<const Packet>, std::string > m_rxTrace; //!< A trace for received data packets.
    TracedCallback<Ptr<const Packet> > m_rxSigTrace; //!< A trace for received signaling packets.
    TracedCallback<Ptr<const Packet> > m_rxKmsTrace; //!< A trace for received packets from the KMS.
    ns3::TracedCallback<const std::string &, const std::string &> m_stateTransitionTrace; //!< A trace for the application state transitions.
    TracedCallback<Ptr<const Packet>, std::string > m_mxTrace; //!< A trace for the missed time slots to send data (due to the lack of keys).

    /**
     * \brief Get the sending socket to the KMS.
     * \return The sending socket.
     */
    Ptr<Socket> GetSendSocketToKMS() {
        return m_sendSocketToKMS;
    }

    /**
     * \brief Get the receiving socket from the KMS.
     * \return The receiving socket.
     */
    Ptr<Socket> GetSinkSocketFromKMS() {
        return m_sinkSocketFromKMS;
    }

private:

    UUID            m_ksid_enc; //!< The encryption key stream identifier.
    UUID            m_ksid_auth; //!< The authentication key stream identifier.
    
    /**
     * A cryptographic key at the application layer.
     */
    struct QKDAppKey
    {
        uint32_t index;
        std::string key;
        uint32_t lifetime; //Lifetime in bytes!
    };

    /**
     * The key stream session details.
     */
    struct Association004
    {
        std::string ksid;
        bool verified;
        uint32_t queueSize;
        uint32_t keyActive;
        std::map<uint32_t, QKDAppKey> buffer; //queue
    };

    std::pair<Association004, Association004> m_associations; //!< A pair (encryption/authentication) of the establihed key stream session.

    bool m_primaryQueueEstablished; //!< Is the queue established at the sender application?
    bool m_replicaQueueEstablished; //!< Is the queue established at the receiver application?

    Ptr<UniformRandomVariable> m_random; //!< The uniform random variable.

    /**
     * \brief Initialize the key stream sessions.
     *
     * Delete all the records of the key stream sessions (as well as the remaining keys).
     */
    void                InitializeAssociations ();

    /**
     * \brief Check if the required key stream sessions are successfuly established.
     */
    void                CheckAssociationsState ();

    /**
     * \brief Create the required key queues to store a set amount of keys from the respective key stream sessions.
     */
    void                CreateKeyQueues ();

    /**
     * \brief Request new keys from the KMS until the key queues at the application layer are established with a set amount of keys.
     * 
     * The pplication establishes key queues of desired number of keys prior to the secure communication
     * to support a fast rekeying.
     */
    void                CheckQueues ();

    /**
     * \brief Once the receiving application establishes the queues, it sends a response to the sender application.
     */
    void                CreateKeyQueuesResponse ();

    /**
     * \brief Delete all records of key stream session identified with a given KSID.
     * \param ksid The key stream identifier (KSID).
     */
    void                ClearAssociation (std::string ksid);

    /**
     * \brief Start establishing key queues at the reciving application once requested by the sender.
     */
    void                ProcessCreateQueuesResponse ();

    /**
     * \brief Get the encryption key from the queue.
     * \return The encryption key.
     */
    QKDAppKey           GetEncKey ();

    /**
     * \brief Get the authentication key from the queue.
     * \return The authentication key.
     */
    QKDAppKey           GetAuthKey ();

    /**
     * \brief Memories the HTTP request made to the local KMS.
     * \param uri The HTTP request URI.
     * \param ksid The key stream session identifier.
     * \param keyType The key type.
     *
     * HTTP requests are memorised in a vector for the purpose of mapping received responses.
     */
    void                Http004KMSQuery (std::string uri, std::string ksid, uint32_t keyType);

    /**
     * \brief Memories the HTTP request made to the peer QKD application.
     * \param methodType The request method.
     * \param ksid The key stream identifier.
     */
    void                Http004AppQuery (uint32_t methodType, std::string ksid);

    /**
     * \brief Remove the request from the vector of HTTP requests made to the KMS.
     * \param uri The HTTP request URI.
     */
    void                Http004KMSQueryComplete (std::string uri);

    /**
     * \brief Remove the request from the vector of HTTP requests made to the peer QKD application.
     */
    void                Http004AppQueryComplete (void);

    /**
     * \brief Read the ETSI request method from the URI.
     * \return The ETSI request method.
     */
    uint32_t            GetMethodFromHttp004KMSQuery (std::string uri);

    /**
     * \brief Map the HTTP response from the KMS and obtain the key stream identifier.
     * \return The key stream identifier.
     */
    std::string         GetKsidFromHttp004KMSQuery (std::string uri);

    /**
     * \brief Map the HTTP reponse from the KMS and obtain the key type.
     * \param uri The HTTP request URI.
     * \return The key type.
     */
    uint32_t            GetKeyTypeFromHttp004KMSQuery (std::string uri);

    /**
     * \brief Map the HTTP response from the peer QKD application and obtain the ETSI method type.
     * \return The ETSI method type.
     */
    uint32_t            GetMethodFromHttp004AppQuery (void);

    /**
     * \brief Map the HTTP response from the peer QKD application and obtain the key stream identifier.
     * \return The key stream identifier.
     */
    std::string         GetKsidFromHttp004AppQuery (void);

    
    /**
    * Hashing for the Address class.
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

    virtual void StartApplication (void);
    virtual void StopApplication (void);

    /**
     * \brief Schedule the next time slot to send the data.
     */
    void    ScheduleTx (void);

    /**
     * \brief Transition through a tree of the application states and trigger actions.
     */
    void    AppTransitionTree (void);

    /**
     * \brief Convert the packet to a string.
     * \param packet The packet.
     * \return The packet in the string format.
     */
    std::string         PacketToString (Ptr<Packet> packet);

    /**
     * \brief Send the application packet (includes the generation of a random message and optional encryption or/and authentication on the message).
     */
    void SendPacket (void);

    /**
     * \brief Send a malicious request to the KMS.
     * 
     * This funtion is used in the simulation of the Denail-of-Service attacks on the KMS using malicios/incorrect requests.
     */
    void SendMaliciousRequestToKMS ();

    /**
     * \brief Process and send any remaining packets to the KMS.
     */
    void ProcessPacketsToKMSFromQueue();

    /**
     * \brief Close the connecting sockets with the KMS.
     */
    void CloseSocketToKms();
     
    Ptr<Socket>     m_sendSignalingSocketApp;  //!< The sending socket for the signaling messages.
    Ptr<Socket>     m_sinkSignalingSocketApp; //!< The receiving socket for the signaling messages.
    Ptr<Socket>     m_sendDataSocketApp; //!< The sending socket for the data.
    Ptr<Socket>     m_sinkDataSocketApp;  //!< The receiving socket for the data.
    
    Ptr<Socket>     m_sendSocketToKMS; //!< The sending socket to the KMS.
    Ptr<Socket>     m_sinkSocketFromKMS; //!< The receiving socket from the KMS.

    Address         m_peer; //!< The address of the peer for the data transmission.
    Address         m_peerSignaling; //!< The address of the peer for the signaling data transmission.

    Address         m_local; //!< The local address for the data transmission.
    Address         m_localSignaling; //!< The local address for the signaling data transmission.

    Address         m_kms; //!< The local KMS address.

    std::string     m_socketType; //!< The sockets type.
    
    uint32_t        m_packetSize;  //!< The data packet size.
    double          m_delay; //!< The time interval between two successive data transmissions (calculated based on the application data rate).

    DataRate        m_dataRate; //!< The application data rate.
    DataRate        m_minDataRate;  //!< The minimum application data rate.
    
    EventId         m_sendEvent; //!< The data transmission event.
    EventId         m_closeSocketEvent;  //!< The closing socket event.
    Time            m_holdTime; //!< The holding time before closing sockets.

    uint32_t        m_packetsSent; //!< The number of sent data packets.
    uint32_t        m_dataSent; //!< The amount of the sent data.
    TypeId          m_tid; //!< The type identifier.
    uint32_t        m_master; //!< Is a master (sender/primary) application?
    uint32_t        m_malicious; //!< Is a malicious application?

    Ptr<Packet>     m_maliciousPacket; //!< The malicious packet.
    Time            m_dosAttackIntensity; //!< The intensity of the DoS attack.


    uint32_t        m_priority; //!< The application priority (QoS).
    uint32_t        m_ttl; //!< The time-to-live of the key stream session.

    //HTTP mapping responses to requests!
    std::vector<std::pair<uint32_t, std::string> > m_httpRequestsApp; //!< A vector of HTTP requests sent to the peer application.
    std::map<std::string, std::pair<std::string, uint32_t> > m_httpRequestsKMS; //!< A vector of HTTP requests set to the KMS.
    
    UUID            m_id; //!< The application identifier.
    UUID            m_dstSaeId; //!< The peer application identifier.
    
    static uint32_t m_applicationCounts; //!< The number of running applications.

    //Crypto params
    uint32_t    m_useCrypto; //!< Execute actual cryptographic algorithms?
    uint32_t    m_encryptionTypeInt; //!< The encryption algorithm.
    uint32_t    m_authenticationTypeInt; //!< The authentication algorithm.
    uint32_t    m_authenticationTagLengthInBits; //!< The size of the authentication tag in bits (32 by default).
    uint32_t    m_aesLifetime; //!< The AES key lifetime.
    TracedCallback<Ptr<Packet> > m_encryptionTrace; //!< A trace callback for the encryption event.
    TracedCallback<Ptr<Packet> > m_decryptionTrace; //!< A trace callback for the decryption event.
    TracedCallback<Ptr<Packet>, std::string > m_authenticationTrace; //!< A trace callback for the authentication event.
    TracedCallback<Ptr<Packet>, std::string > m_deauthenticationTrace; //!< A trace callback for the authentication check event.
    
    TracedCallback<const uint32_t&> m_obtainedKeyMaterialTrace; //!< A trace callback for the obtained key material.
    QKDEncryptor::EncryptionType m_encryptionType; //!< The encryption algorithm.
    QKDEncryptor::AuthenticationType m_authenticationType; //!< The authentication algorithm.
    Ptr<QKDEncryptor> m_encryptor; //!< The QKD encryptor.
    uint32_t    m_keyBufferLengthEncryption; //!< The size of the encryption key queue at the application layer.
    uint32_t    m_keyBufferLengthAuthentication; //!< The size of the authentication key queue at the application layer.

    QKDAppState m_appState; //!< The application state.

    std::vector<KMSPacket > m_queue_kms; //!< The queue of packets waiting for the transmission to the KMS.

    std::unordered_map<Address, Ptr<Packet>, AddressHash> m_buffer_kms; //!< The buffer for the received packets from the KMS (fragmentation).
    std::unordered_map<Address, Ptr<Packet>, AddressHash> m_buffer_sig; //!< The buffer for the received signaling packets (fragmentation).
    std::unordered_map<Address, Ptr<Packet>, AddressHash> m_buffer_qkdapp; //!< The buffer for received data packets (fragmentation).

    std::map<uint32_t, EventId > m_scheduledEvents;  //!< The map of scheduled events.
    std::multimap<std::string, std::string> m_transitionMatrix; //!< The map of the possible state transitions.

};


} // namespace ns3

#endif /* QKD_SINK_H004 */
