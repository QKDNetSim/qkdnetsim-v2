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
#ifndef QKD_APPLICATION_ENTRY_H
#define QKD_APPLICATION_ENTRY_H
 
#include "ns3/event-id.h"
#include "ns3/ptr.h"
#include "ns3/data-rate.h"
#include "ns3/traced-callback.h" 
#include "ns3/output-stream-wrapper.h"
#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/node.h" 
#include "ns3/core-module.h"
#include "ns3/log.h"
#include "ns3/uuid.h"

#include <map>
#include <iostream>
#include <vector>
#include <sstream>

namespace ns3 {

/**
 * \ingroup qkd
 * \class QKD applicaton entry
 * \brief From the perspective of the SD-QKD node, a QKD application is defined as any 
 * entity requesting QKD-derived keys from the key manager within the node. 
 * These applications might be external (e.g. an end-user application, 
 * a Hardware Security Module (HSM), a virtual network function, an encryption card,
 * security protocols, etc.) or internal (keys used for authentication, to create a 
 * virtual link - for key transport, e.g. a forwarding module). From the software perspective, 
 * an application is a concrete running instance or process consuming keys at a given point in time. 
 * A single instance or process may also require to open different isolated sessions 
 * (with a unique ID) with the SD-QKD node.
 * More details in ETSI GS QKD 015 V2.1.1 (2022-04)
 */ 

inline std::string GetQKDApplicationEntryText(const uint16_t statusCode)
{
    switch (statusCode)
    {
      case 1:
          return "ETSI_QKD_014_ENCRYPTION Protocol";
      case 2:
          return "ETSI_QKD_014_AUTHENTICATION";
      case 3:
          return "ETSI_QKD_004_ENCRYPTION";
      case 4:
          return "ETSI_QKD_004_AUTHENTICATION";
      default:
          return "None";
    }
}

class QKDApplicationEntry : public Object 
{
  public:

    /**
     * \brief The connection types.
     */
    enum ConnectionType
    {
      NONE                        = 0,
      ETSI_QKD_014_ENCRYPTION     = 1,
      ETSI_QKD_014_AUTHENTICATION = 2,
      ETSI_QKD_004_ENCRYPTION     = 3,
      ETSI_QKD_004_AUTHENTICATION = 4
    };   


    /**
    * \brief Get the type ID.
    * \return The object TypeId.
    */
    static TypeId GetTypeId (void);

    /**
    * \brief Get the type ID for the instance.
    * \return The instance TypeId.
    */
    virtual TypeId GetInstanceTypeId (void) const;

    /**
     * \brief Empty constructor.
     */
    QKDApplicationEntry ();

    /**
     * \brief Constructor.
     * \param keyAssociationId The key association identifier.
     * \param srcSaeId The source (sender) application identifier (UUID).
     * \param dstSaeId The destination (receiver) application identifier (UUID).
     * \param type The connection type.
     * \param priority The association priority.
     * \param expirationTime The association expiration time.
     * \param srcKMSAddress The source KMS IP address.
     * \param dstKMSAddress The destination KMS IP address.
     */
    QKDApplicationEntry (
        UUID keyAssociationId,
        UUID srcSaeId,
        UUID dstSaeId,
        ConnectionType type,
        uint32_t priority,
        double expirationTime,
        Ipv4Address srcKMSAddress,
        Ipv4Address dstKMSAddress
    );

    /**
     * \brief Destructor.
     */
    ~QKDApplicationEntry ();
    
    /**
     * \briet Get the source KMS IP address.
     * \returns The source KMS IP address.
     */
    Ipv4Address
    GetSourceKmsAddress () const
    {
      return m_kmsSrcAddress;
    } 
    /**
     * \brief Get the destination KMS IP address.
     * \returns The destination KMS IP address.
     */
    Ipv4Address
    GetDestinationKmsAddress () const
    {
      return m_kmsDstAddress;
    } 
    /**
     * \brief Print the registry information.
     */
    void 
    PrintRegistryInfo ();
    /**
     * \brief Print the routing table entry.
     * \param The stream the output stream.
     */
    void
    Print (Ptr<OutputStreamWrapper> stream) const;

    /**
     * \brief Get the source (sender) application identifier.
     * \return The source application identifier (UUID).
     */
    UUID GetSrcSaeId(){
      return m_client_app_id;
    }
    /**
     * \brief Get the destination (receiver) application identifier.
     * \return The destination application identifier (UUID).
     */
    UUID GetDestinationSaeId(){
      return m_server_app_id;
    }
    /**
     * \brief Get the application identifier.
     * \return The application identifier.
     */
    UUID GetId(){
      return m_app_id;
    }
    /**
     * \brief Set the application identifier.
     */
    void SetId(UUID value){
      m_app_id = value;
    }
    /**
     * \brief Check if entry is valid.
     * \return Validity of the entry.
     */
    bool
    IsValid(){
      return m_valid;
    }  
    /**
     * \brief Get the connection type.
     * \return The connection type.
     */
    QKDApplicationEntry::ConnectionType GetType(){
      return m_app_type;
    }
    /**
     * \brief Get the association identifier.
     * \return The association identifier.
     */
    UUID GetKeyAssociationId(){
      return m_backing_qkdl_id;
    }
 
    UUID      m_app_id;     // !< This value uniquely identifies a QKD application consisting of a set of entities that are allowed to receive keys shared with each other from the SD-QKD nodes they connect to. This value is similar to a key ID or key handle.
    double    m_qos_max_bandwidth; // !< Maximum bandwidth (in bits per second) allowed for this specific application. Exceeding this value will raise an error from the local key store to the appl. This
    double    m_qos_min_bandwidth; // !< This value is an optional QoS parameter that enables a minimum key rate (in bits per second) for the application
    double    m_qos_jitter; // !< This value allows to specify the maximum jitter (in msec) to be provided by the key delivery API for applications requiring fast rekeying.
    double    m_qos_ttl; // !< This value is used to specify the maximum time (in seconds) that a key could be kept in the key store for a given application without being used.
    bool      m_qos_clients_shared_path_enable; // !< If true, multiple clients for this application might share keys to reduce service impact (consumption)
    bool      m_clients_shared_keys_required; // !< If true, multiple clients for this application might share keys to reduce service impact (consumption)
    QKDApplicationEntry::ConnectionType  m_app_type; // !< Type of the registered application. These values, defined within the types module, can be client (if an external application is requesting keys) or internal (if the application is defined to maintain the QKD - e.g. multi-hop, authentication or other encryption operations).
    UUID      m_client_app_id; // !< List of IDs that identifies the one or more entities that are allowed to receive keys from SD-QKD node(s) under the QKD application in addition to the initiating entity identified by server_app_id.
    UUID      m_server_app_id; // !< ID that identifies the entity that initiated the creation of the QKD application to receive keys shared with one or more specified target entity identified by client_app_id. It is a client in the interface to the SD-QKD node and the name server_app_id reflects that it requested the QKD application to be initiated
    UUID      m_backing_qkdl_id; // !< Unique ID of the key association link which is providing QKD keys to these applications
    uint32_t  m_local_qkdn_id; // !< Unique ID of the local SD-QKD node which is providing QKD keys to the local application.
    uint32_t  m_remote_qkdn_id; // !< Unique ID of the remote SD-QKD node which is providing QKD keys to the remote application. While unknown, the local SD-QKD will not be able to provide keys to the local application.
    uint32_t  m_app_priority; // !< The application priority.
    double    m_creation_time; // !< The association creation time.
    double    m_expiration_time; // !< The association expiration time.
    uint32_t  m_app_statistics_statistic_consumed_bits; // !< The consumption statistics.
    bool      m_valid; // !< Internal check whether all fields are set correctly
    Ipv4Address m_kmsSrcAddress; // !< IP address of master KMS
    Ipv4Address m_kmsDstAddress; // !< IP address of slave KMS
 
};

} // namespace ns3

#endif /* QKD_APPLICATION_ENTRY_H */

