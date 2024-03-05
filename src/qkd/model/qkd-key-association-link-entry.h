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
#ifndef QKD_KEY_ASSOCIATION_LINK_H
#define QKD_KEY_ASSOCIATION_LINK_H
 
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
#include "ns3/qkd-buffer.h"

#include <map>
#include <iostream>
#include <sstream>
#include <vector>

namespace ns3 {
 
/**
 * \ingroup applications
 * \class QKD QKD key association link
 * \brief A QKD Key Association Link is a logical key association between two remote SD-QKD nodes.
 *  These links associations can be of two different types: direct (also called physical), 
 * if there is a direct quantum channel through which keys are generated, 
 * i.e. a physical QKD link connecting the pair of QKD modules, or virtual if keys are forwarded (key relay) 
 * through several SD-QKD -trusted- nodes to form an end-to-end key association. 
 * i.e. there is no direct quantum channel connecting the endpoints, and a set of them have to be 
 * concatenated such that for each a secret key is produced and then used to relay a key from the 
 * initial to the endpoint in a multi-hop way.
 * Any new key association link created in an SD-QKD node has to be tracked, 
 * labelled and isolated from other links. Virtual links are also registered as internal applications,
 * as they make use of QKD-derived keys from other QKD key association links for the key transport.
 * More details in ETSI GS QKD 015 V2.1.1 (2022-04)
 */
class QKDKeyAssociationLinkEntry : public Object 
{
  public:

    /**
    * \brief Get the type ID.
    * \return the object TypeId
    */
    static TypeId GetTypeId (void);

    /**
    * \brief Get the type ID for the instance
    * \return the instance TypeId
    */
    virtual TypeId GetInstanceTypeId (void) const;

    QKDKeyAssociationLinkEntry ();

    QKDKeyAssociationLinkEntry (
      uint32_t local_qkd_node_id,
      uint32_t remote_qkd_node_id,
      uint32_t nextHop,
      uint32_t hops,   
      uint32_t type, //Virtual (multi-hop) - value 1  or Direct - value 0.
      Ipv4Address kmsSrcAddress,
      Ipv4Address kmsDstAddress,
      Ptr<QKDBuffer> qkdBuffer
    );

    QKDKeyAssociationLinkEntry (
      UUID qkdl_id,
      uint32_t local_qkd_node_id,
      uint32_t remote_qkd_node_id,
      uint32_t nextHop,
      uint32_t hops,   
      uint32_t type, //Virtual (multi-hop) - value 1  or Direct - value 0.
      Ipv4Address kmsSrcAddress,
      Ipv4Address kmsDstAddress,
      Ptr<QKDBuffer> qkdBuffer
    );

    ~QKDKeyAssociationLinkEntry ();
    
    /**
     * Get source KMS Address
     * \returns the source KMS Address
     */
    Ipv4Address
    GetSourceKmsAddress () const
    {
      return m_kmsSrcAddress;
    } 
    /**
     * Get destination KMS Address
     * \returns the destination KMS Address
     */
    Ipv4Address
    GetDestinationKmsAddress () const
    {
      return m_kmsDstAddress;
    } 
    uint32_t
    GetSourceNodeId(){
      return m_qkdl_local_qkdn_id;
    }
    uint32_t
    GetDestinationNodeId(){
      return m_qkdl_remote_qkdn_id;
    }
    UUID
    GetId(){
      return m_qkdl_id;
    }
    void
    SetId(UUID id){
      m_qkdl_id = id;
    }
    Ptr<QKDBuffer>
    GetSourceBuffer() {
      return m_srcQKDBuffer;
    }
    
    void 
    UpdateQKDApplications(UUID saeId);

    bool
    CheckSAEApplicationExists(UUID saeId);

    void
    PrintSAEApplications();

    uint32_t 
    GetHop(){ 
      return (uint32_t) m_hops;
    }
    uint32_t 
    GetType(){ 
      return m_qkdl_type;
    }
    bool
    IsValid(){
      return m_valid;
    }

    void SetUpdateStatusInterval(double statusInterval);

    double GetUpdateStatusInterval();

    double GetSKR();

    void SetSKR(double value);

    double GetExpectedConsumption();

    void SetExpectedConsumption(double value);

    double GetEffectiveSKR();

    void SetEffectiveSKR(double value);

    /**
     * \brief Print registry info
     */
    void 
    PrintRegistryInfo ();
    /**
     * Print routing table entry
     * \param stream the output stream
     */
    void
    Print (Ptr<OutputStreamWrapper> stream) const;
 
    UUID      m_qkdl_id;     // !< Unique ID of the QKD link (key association).
    bool      m_qkdl_enable; // !< This value allows to enable or disable the key generation process for a given link.
    uint32_t  m_qkdl_local_qkdn_id; // !< Unique ID of the local SD-QKD node.
    uint32_t  m_qkdl_local_qkdi_id; // !< Interface used to create the key association link
    uint32_t  m_qkdl_remote_qkdn_id; // !< Unique ID of the remote QKD node. This value is provided by the SDN controller when the key association link request arrives.
    uint32_t  m_qkdl_remote_qkdi_id; // !< Interface used to create the link.
    uint32_t  m_qkdl_type; // !< Key Association Link type: Virtual (multi-hop) - value 1  or Direct - value 0.
    std::vector<UUID> m_qkdl_applications; // !<  SAE Applications which are consuming keys from this key association link.
    uint32_t  m_virt_prev_hop; // !< Previous hop in a multi-hop/virtual key association link config
    uint32_t  m_virt_next_hop; // !< Next hop(s) in a multi-hop/virtual key association link config. Defined as a list for multicast over shared sub-paths.
    double    m_virt_bandwidth; // !< Required bandwidth (in bits per second) for that key association link. Used to reserve bandwidth from the physical QKD links to support the virtual key association link as an internal application
    double    m_phys_channel_att; // !< Expected attenuation on the quantum channel (in dB) between the Source/qkd_node and Destination/qkd_node.
    double    m_phys_wavelength; // !< Wavelength (in nm) to be used for the quantum channel. If the interface is not tunable, this configuration could be bypassed.
    uint32_t  m_phys_qkd_role; // !< Transmitter/receiver mode for the QKD module. If there is no multi-role support, this could be ignored
    
    double    m_qkdl_performance_expected_consumption; // !< Sum of all the application's bandwidth (in bits per second) on this particular key association link.
    double    m_qkdl_performance_skr; // !< Secret key rate generation (in bits per second) of the key association link.
    double    m_qkdl_performance_eskr; // !< Effective secret key rate (in bits per second) generation of the key association link available after internal consumption
    
    double    m_update_status_interval; // !< Time (Seconds) period to send update to SDN

    Ipv4Address m_kmsSrcAddress; // !< IP address of master KMS
    Ipv4Address m_kmsDstAddress; // !< IP address of slave KMS
    uint32_t  m_hops; // !< Total number of hops forming the link. If dirrect - value 0
    bool      m_valid; // !< Internal check whether all fields are set correctly

    Ptr<QKDBuffer> m_srcQKDBuffer;

};

} // namespace ns3

#endif /* QKD_KEY_ASSOCIATION_LINK_H */

