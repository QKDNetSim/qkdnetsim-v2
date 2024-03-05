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
#ifndef QKD014_SEND_H
#define QKD014_SEND_H

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
 * \defgroup QKDApp014 QKDApp014
 *
 * The QKDApp014 application implements communication 
 * to Local Key Management System and it establish secure
 * communciation with counter-part QKDApp014.
 */

/**
 * \ingroup QKDApp014
 *
 * \brief Establish secure communication on application lavel to use the key and test LKSM
 *
 * This application was written to complement simple application to consume keys
 * so a generic QKDApp014 name was selected. The application (Alice) implements sockets for
 * connection with counter-party application (Bob) and implements sockets for 
 * communication with local key management system. At the moment, application follows
 * ETSI QKD 014 standardization exchanging HTTP requests/responses to obtain details about
 * the key from its local key management system. Obtained keys from Get key response are stored
 * in temporary memory on master QKDApp014 (Alice) in JSON data structure, from where they are moved
 * to an application key buffer when confirmation of keys from peer application (Bob) is recieved.
 * Keys obtained from Get key with key IDs are directly stored to the application key buffer and 
 * confirmation message for keys is sent to its peer application (Alice). Application (Alice) use
 * keys from the application key buffer to apply security services on its data. QKD application 
 * header is then added to the protected data and sent to peer application. Slave QKD 
 * application (Bob) will process recieved protected packet based on information in QKD header
 * and keys from the application key buffer. Communication between peers needed to negotiate keys
 * was not included in ETSI014, and this application use HTTP messages for this purpose.
 *
 */
class QKDApp014 : public Application 
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
    QKDApp014 ();

    /**
     * \brief Destructor.
     */
    virtual     ~QKDApp014();

    /**
     * \brief Set the encryption identifier.
     * \param val The encryption identifier.
     */
    void SetKsidEncryption(UUID val){
        m_ksid_enc = val;
    }

    /**
     * \brief Set the authentication identifier.
     * \param val The authentication identifier.
     */
    void SetKsidAuthentication(UUID val){
        m_ksid_auth = val;
    }
    
    /**
     * The cryptographic key at the application layer.
     */
    struct      QKDApp014Key
    {
        std::string key;
        std::string keyId;
        uint32_t keyType; //0-enc key, 1-auth key
        uint64_t lifetime; //Value of lifetime used with ciphers such as AES! Value is exspresed in seconds!
                                            //Lifetime is counted from the first use!
    };

    /**
     * The key buffer at the application layer. It stores keys obtained from the KMS. Keys are stored until their lifetime is valid.
     */
    struct      QKDApp014KeyBuffer
    {
        std::map<std::string, QKDApp014Key> outboundEncKeyStore; //Store for enc keys used for outbound traffic!
        std::map<std::string, QKDApp014Key> outboundAuthKeyStore; //Store for auth keys used for outbound traffic!
        std::map<std::string, QKDApp014Key> inboundKeyStore; //Store for enc/auth keys used for inbound traffic!        
        std::map<std::string, QKDApp014Key> temporaryKeyStoreMaster; //Temporary memory for keys to be negotiated with peer QKDApp014!

    };

    /**
     * The application states.
     */
    enum QKDApp014State {
        NOT_STARTED,
        INITIALIZED,
        READY,
        WAIT,
        SEND_DATA,
        DECRYPT_DATA,
        STOPPED
    };

    /**
     * \brief Configure the application.
     * \param socketType The socket type.
     * \param src The source application address.
     * \param dst The destination application address.
     * \param kms The local KMS address.
     * \param dstSaeId The peer application identifier.
     * \param type The application type, the sender or the receiver.
     */
    void        Setup (
        std::string socketType,
        Address src,  
        Address dst,  
        Address kms,  
        UUID    dstSaeId,
        std::string type
    );

    /**
     * \brief Configure the application.
     * \param socketType The socket type.
     * \param src The source application address.
     * \param dst The destination application address.
     * \param kms The local KMS address.
     * \param dstSaeId The peer application identifier.
     * \param packetSize The size of the data packet.
     * \param nPackets The number of data packets.
     * \param dataRate The data rate.
     * \param type The application type, the sender or the receiver.
     */
    void        Setup (
        std::string socketType,
        Address src,
        Address dst, 
        Address kms,
        UUID    dstSaeId,
        uint32_t packetSize,
        uint32_t nPackets,
        DataRate dataRate,
        std::string type
    );


    /**
     * \brief Initialize the application key buffer.
     */
    void        InitializeAppKeyBuffer();

    /**
     * \brief Remove keys from the temporary key store.
     * \param keyIds The key identifiers.
     */
    void        RemoveKeysFromTemporaryKeyStore (std::vector<std::string> keyIds);


    /**
     * \brief Add a new key to the inbound key store.
     * \param key The application key.
     */
    void        AddKeyInInboundKeyStore (QKDApp014::QKDApp014Key& key);

    /**
     * \brief Add a new key to the encryption key store.
     * \param key The application encryption key.
     */
    void        AddEncKeyInKeyStore (QKDApp014::QKDApp014Key& key);

    /**
     * \brief Add a new key to the authentication key store.
     * \param key The application authentication key.
     */
    void        AddAuthKeyInKeyStore (QKDApp014::QKDApp014Key& key);

    /**
     * \brief Print the content of the temporary key store.
     */
    void        PrintTemporaryKeyStoreContent ();

    /**
     * \brief Print the status information on the application key buffer.
     */
    void        PrintAppBufferStatusInformation ();

    /**
     * \brief Check the state of the application key buffer.
     * 
     * This function checks the state of the application key buffer and submits
     * a new GET_KEY request if neccessary.
     */
    void        CheckAppBufferState ();

    /**
     * \brief Check the conditions to change the application state.
     * 
     * Based on the state of the application key buffer, the application
     * changes the state between READY and WAIT.
     */
    void        CheckAppState ();

    /**
     * \brief Request status information from the KMS (ETSI QKD 014 - Get status method).
     * \param keyType The key type (encryption or authentication).
     */
    void        GetStatusFromKMS (uint32_t keyType);

    /**
     * \brief Request keys from the KMS (ETSI QKD 014 - Get key method).
     * \param keyType The key type (encryption or authentication).
     */
    void        GetKeysFromKMS (uint32_t keyType);
 
    /**
     * \brief Requests keys with given identifiers from the KMS (ETSI QKD 014 - Get key with key IDs method).
     * 
     * The key identifiers are locally stored at the application, and that's why the input to this function is void.
     */
    void        GetKeyWithKeyIDs();

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
     * \param The amount of data.
     */
    void        DataToKMSSend (Ptr<Socket>, uint32_t);

    /**
     * \brief Handle a packet received from the KMS application.
     * \param socket The receiving socket.
     */
    void        HandleReadFromKMS (Ptr<Socket> socket);

    /**
     * \brief Handle a connection close from the KMS.
     * \param socket The connected socket.
     */
    void        HandlePeerCloseFromKMS (Ptr<Socket> socket);

    /**
     * \brief Handle a connection error from the KMS.
     * \param socket The connected socket.
     */
    void        HandlePeerErrorFromKMS (Ptr<Socket> socket);
    
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
     * \param socket the connected socket.
     */
    void        HandlePeerErrorSignalingFromApp (Ptr<Socket> socket);
    
    /**
     * \brief Handle a signaling incoming connection from the peer QKD application.
     * \param s The incoming connection socket.
     * \param from The address the connection is from.
     */
    void        HandleAcceptSignalingFromApp (Ptr<Socket> s, const Address& from);

    /**
     * \brief Callback function after the connection response from the KMS has been received.
     * \param socket The connected socket.
     * \param address The address of the KMS.
     */
    bool        ConnectionRequestedFromKMS (Ptr<Socket> socket, const Address &address);
    
    /**
     * \brief Check for the TCP segmentation of the packets received from the KMS.
     * \param p The received packet.
     * \param from The address of the KMS.
     * \param socket The connected socket.
     */
    void        PacketReceivedFromKMS (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

    /**
     * \brief Check for the TCP segmentation of the signaling packets received from the peer QKD application.
     * \param p The received signaling packet.
     * \param from The address of the peer application.
     * \param socket The connected socket.
     */
    void        SignalingPacketReceivedFromApp (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

    /**
     * \brief Check for the TCP segmentation of the data packets received from the peer QKD application.
     * \param p The received data packet.
     * \param from The address of the peer application.
     * \param socket The connected socket.
     */
    void        DataPacketReceivedFromApp (const Ptr<Packet> &p, const Address &from, Ptr<Socket> socket);

    /**
     * \brief Process the response from the KMS application.
     * \param header The received HTTP message.
     * \param packet The received packet.
     * \param socket The receiving socket.
     */
    void        ProcessResponseFromKMS(HTTPMessage& header, Ptr<Packet> packet, Ptr<Socket> socket);

    /**
     * \brief Process the status response from the KMS.
     * \param header The received HTTP message.
     * \param jstatusResponse The JSON response payload.
     */
    void        ProcessStatusResponse (HTTPMessage& header, nlohmann::json jstatusResponse);

    /**
     * \brief Process the GET_KEY response from the KMS.
     * \param header The received HTTP message.
     * \param jGetKeyResponse The JSON response payload.
     */
    void        ProcessGetKeyResponse (HTTPMessage& header, nlohmann::json jGetKeyResponse);

    /**
     * \brief Process the Get Key with Key IDs response from the KMS.
     * \param header The received HTTP message.
     * \param jGetKeyWithKeyIDsResponse The JSON response payload.
     */
    void        ProcessGetKeyWithKeyIDsResponse(HTTPMessage& header, nlohmann::json jGetKeyWithKeyIDsResponse);

    /**
     * \brief Process the signaling packets received from the peer QKD application.
     * \param header The received HTTP message.
     * \param packet The received packet.
     * \param socket The receiving socket.
     */
    void        ProcessSignalingPacketFromApp(HTTPMessage& header, Ptr<Packet> packet, Ptr<Socket> socket);

     /**
     * \brief Process the data packets from the peer QKD application.
     * \param header The QKDApp014 packet header.
     * \param packet The received packet.
     * \param socket The receiving socket.
     */
    void        ProcessDataPacketFromApp(QKDAppHeader header, Ptr<Packet> packet, Ptr<Socket> socket);

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
     * \brief Schedule the action.
     * \param t The time slot to perform action.
     * \param action The action.
     * \return The identifier of the scheduled event/action.
     */
    uint32_t    ScheduleAction(Time t, std::string action);
 
    /**
     * \brief Cancel the scheduled event/action. 
     * \param eventId The identifier of the scheduled action.
     */
    void        CancelScheduledAction(uint32_t eventId);

    /**
     * \brief Set the encryption and the authentication algorithms
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
     * \brief Get required key size for the choosen encryption algorithm.
     * \return The key size.
     */
    uint32_t    GetEncryptionKeySize();

    /**
     * \brief Get required key size for the choosen authentication algorithm.
     * \return The key size.
     */
    uint32_t    GetAuthenticationKeySize ();

    /**
     * \brief Get the key from the application key buffer.
     * \param keyType The type of the key to obtain: 0-encryption key, 1-authentication key.
     * \return The application key.
     */
    QKDApp014::QKDApp014Key   GetKeyFromAppKeyBuffer (uint32_t keyType);

    /**
     * \brief Get the key from the application key buffer.
     * \param keyId The key identifier.
     * \param keyType The key type.
     * \return The application key.
     */
    QKDApp014::QKDApp014Key   GetKeyFromAppKeyBuffer (std::string keyId, std::string keyType);
  
    /**
     * \brief Get the current state of the application.
     * \return The current state of the application.
     */
    QKDApp014State GetAppState () const;

    /**
     * \brief Get the current state of the application in the string format.
     * \return The current state of the application in the string format.
     */
    std::string GetAppStateString () const;

    /**
     * \brief Convert application state to the string format.
     * \param state The state.
     * \return The state in the string format.
     */
    static std::string GetAppStateString (QKDApp014State state);

    /**
     * \brief Get the application identifier.
     * \return The application identifier.
     */
    UUID GetId (void) {
        return m_id;
    }
    
    /**
     * \brief Change the state of the application.
     * \param state The new application state.
     */
    void SwitchAppState (QKDApp014State state);


    /**
    * \brief Generate a random packet (message) of a given size.
    * \param msgLength The message size.
    * \return The random message.
    */
    std::string GetPacketContent(uint32_t msgLength = 0);

    TracedCallback<Ptr<const Packet>, std::string > m_txTrace; //!< A trace for transmitted data packets.
    TracedCallback<Ptr<const Packet> > m_txSigTrace; //!< A trace for transmitted signaling packets.
    TracedCallback<Ptr<const Packet> > m_txKmsTrace; //!< A trace for transmitted packets to the KMS.
    TracedCallback<Ptr<const Packet>, std::string > m_rxTrace; //!< A trace for received data packets.
    TracedCallback<Ptr<const Packet> > m_rxSigTrace; //!< A trace for received signaling packets.
    TracedCallback<Ptr<const Packet> > m_rxKmsTrace; //!< A trace for received packets from the KMS.
    ns3::TracedCallback<const std::string &, const std::string &> m_stateTransitionTrace; //!< The posible application state transitions.
    TracedCallback<Ptr<const Packet>, std::string > m_mxTrace; //!< A trace for the missed time slots to send data packets.

private:


    /**
     * \brief Memories the HTTP request made to the local KMS.
     * \param methodType The request method.
     * \param keyType The key type.
     *
     * HTTP requests are memorised in a vector in order to map the responses.
     */
    void MemoriesRequestKMS (uint32_t methodType, uint32_t keyType = 0);

    /**
     * \brief Adjust the encryption key identifier for the QKDApp header.
     * \param keyId The key identifier.
     * \return The adjusted key identifier.
     * 
     * This function only removes '-' symbols from the key identifier which is in UUID format.
     */
    std::string CreateKeyIdField(std::string keyId);

    /**
     * \brief Rebuild the key identifier for the QKDApp header.
     * \param keyId The key identifier from the QKDApp header.
     * \return The key identifier in the UUID format.
     */
    std::string ReadKeyIdField(std::string keyId);

    /**
     * \brief Memories the HTTP request made to the peer QKD application.
     * \param keyIds The vector of key identifiers.
     */
    void MemoriesRequestApp (std::vector<std::string> keyIds);

    /**
     * \brief Remove the request from the HTTP requests store (once the response from the KMS has been processed).
     */
    void RequestProcessedKMS (void);

    /**
     * \brief Remove request from the HTTP requests store (once the response from the peer application has been processed).
     */
    void RequestProcessedApp (void);

    /**
     * \brief Map the HTTP response and obtrain the request method.
     * \return The request method.
     */
    uint32_t GetETSIMethod (void);

    /**
     * \brief Map the HTTP response and obtain the key type.
     * \return The key type.
     */
    uint32_t GetKeyType (void);

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

    virtual void StartApplication (void);
    virtual void StopApplication (void);

    /**
     * Schedule the time slot to send the data packets.
     */
    void ScheduleTx (void);

    /**
     * \brief Transition through a tree of the application states and trigger actions.
     */
    void AppTransitionTree (void);

    /**
     * \brief Exchange key identifiers between sending and receiving application.
     * \param ksid The key stream identifier.
     * \param keyIds The vector cointaning key identifiers to negotiate.
     * \param statusCode The HTTP status code of the response (the default status is 200:Ok).
     * 
     * Primary (sender) application sends vector of key identifiers previously obtained from the KMS.
     * Replica (receiver) application obtains the keys from the KMS using received identifiers.
     * The success of this operation is reported to the primary application.
     */
    void ExchangeInfoMessages(
        std::string ksid, 
        std::vector<std::string> keyIds, 
        HTTPMessage::HttpStatus statusCode = HTTPMessage::Ok
    );
    
    /**
     * \brief Send the application packet (includes the generation of a random message and optional encryption or/and authentication on the message).
     */
    void SendPacket (void);

    Ptr<Socket>     m_sendSignalingSocketApp;  //!< The sending socket for the signaling messages.  
    Ptr<Socket>     m_sinkSignalingSocketApp;  //!< The receiving socket for the signaling messages.
    Ptr<Socket>     m_sendDataSocketApp; //!< The sending socket for the data.
    Ptr<Socket>     m_sinkDataSocketApp; //!< The receiving socket for the data.
    
    Ptr<Socket>     m_sendSocketToKMS;      //!< The sending socket to the KMS.
    Ptr<Socket>     m_sinkSocketFromKMS;    //!< The receiving socket from the KMS.

    Address         m_peer;             //!< The address of the peer for the data transmission.
    Address         m_peerSignaling;    //!< The address of the peer for the signaling data transmission.

    Address         m_local;            //!< The local address for the data transmission.
    Address         m_localSignaling;   //!< The local address for the signaling data transmission.

    Address         m_kms;              //!< The local KMS address.

    std::string     m_socketType;       //!< The sockets type.
    
    uint32_t        m_packetSize;       //!< The data packet size.
    DataRate        m_dataRate;         //!< The application data rate.
    EventId         m_sendEvent;        //!< The data transmission event.
    uint32_t        m_packetsSent;      //!< The number of sent data packets.
    uint32_t        m_dataSent;         //!< The amount of the sent data.
    TypeId          m_tid;              //!< The type identifier.
    uint32_t        m_master;           //!< Is a master (sender/primary) application?

    Time            m_waitInsufficient; //!< The amount of time spent waiting before issuing a new GET_KEY request when the previous one resulted in an error "inssuficient amount of keys".
    Time            m_waitTransform;    //!< The amount of time spent waiting before issuing a new GET_KEY request when the previous one resulted in an error "keys are being transformed".
 
    Ptr<UniformRandomVariable> m_random;//!< The uniform random variable.

    QKDApp014KeyBuffer m_appKeyBuffer;  //!< The application key buffer.
    nlohmann::json  m_keyIDs;           //!< The latest received key identifiers from the sender application.

    //HTTP mapping responses to requests!
    std::vector<std::pair<uint32_t, uint32_t> > m_httpRequestsKMS;  //!< A vector of HTTP requests set to the KMS.
    std::vector<std::vector<std::string> > m_httpRequestsApp;       //!< A vector of HTTP requests sent to the peer application.

    UUID            m_id;               //!< The application identifier.
    UUID            m_dstSaeId;         //!< The peer application identifier.

    UUID            m_ksid_enc;         //!< The encryption key stream identifier.
    UUID            m_ksid_auth;        //!< The authentication key stream identifier.

    static uint32_t m_applicationCounts; //!< The number of running applications.

    //LKMS PARAMS
    uint32_t        m_numberOfKeysKMS; //!< The number of keys to fetch per request.

    //Crypto params
    uint32_t    m_useCrypto;                                //!< Execute actual cryptographic algorithms?
    uint32_t    m_encryptionTypeInt;                        //!< The encryption algorithm.
    uint32_t    m_authenticationTypeInt;                    //!< The authentication algorithm.
    uint32_t    m_authenticationTagLengthInBits;            //!< The size of the authentication tag in bits (32 by default).
    uint64_t    m_aesLifetime;                              //!< The AES key lifetime.
    TracedCallback<Ptr<Packet> > m_encryptionTrace; //!< A trace callback for the encryption event.
    TracedCallback<Ptr<Packet> > m_decryptionTrace; //!< A trace callback for the decryption event.
    TracedCallback<Ptr<Packet>, std::string > m_authenticationTrace; //!< A trace callback for the authentication event.
    TracedCallback<Ptr<Packet>, std::string > m_deauthenticationTrace; //!< A trace callback for the authentication check event.
    QKDEncryptor::EncryptionType m_encryptionType; //!< The encryption algorithm.
    QKDEncryptor::AuthenticationType m_authenticationType; //!< The authentication algorithm.
    Ptr<QKDEncryptor> m_encryptor; //!< The QKD encryptor.

    TracedCallback<const uint32_t&> m_obtainedKeyMaterialTrace; //!< A trace callback for the obtained key material.

    QKDApp014State m_appState; //!< The application state.

    std::unordered_map<Address, Ptr<Packet>, AddressHash> m_buffer_kms; //!< The buffer for the received packets from the KMS (fragmentation).
    std::unordered_map<Address, Ptr<Packet>, AddressHash> m_buffer_sig; //!< The buffer for the received signaling packets (fragmentation).
    std::unordered_map<Address, Ptr<Packet>, AddressHash> m_buffer_QKDApp014; //!< The buffer for received data packets (fragmentation).

    bool m_internalAppWait; //!< The indicator for the longer wait (used after the GetKey error!).
    std::map<uint32_t, EventId > m_scheduledEvents;  //!< The map of scheduled events.
    std::multimap<std::string, std::string> m_transitionMatrix; //!< The map of the possible state transitions.

};


} // namespace ns3

#endif /* QKD_SINK_H */
