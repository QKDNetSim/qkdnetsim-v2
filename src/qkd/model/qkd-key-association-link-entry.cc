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
#include "ns3/log.h"
#include "ns3/address.h"
#include "ns3/node.h"
#include "ns3/nstime.h" 
#include "ns3/simulator.h"  
#include "ns3/uinteger.h"
#include "ns3/trace-source-accessor.h"  
#include <iostream>
#include <fstream> 
#include <string>
 
#include "ns3/qkd-key-association-link-entry.h"

namespace ns3 {

    NS_LOG_COMPONENT_DEFINE ("QKDKeyAssociationLinkEntry");

    NS_OBJECT_ENSURE_REGISTERED (QKDKeyAssociationLinkEntry);
          
    TypeId 
    QKDKeyAssociationLinkEntry::GetTypeId (void) 
    {
      static TypeId tid = TypeId ("ns3::QKDKeyAssociationLinkEntry")
        .SetParent<Object> () 
        .SetGroupName ("QKDKeyAssociationLinkEntry")
        .AddConstructor<QKDKeyAssociationLinkEntry> ()
        ;
      return tid;
    } 

    TypeId
    QKDKeyAssociationLinkEntry::GetInstanceTypeId (void) const
    {
      return GetTypeId ();
    }

    QKDKeyAssociationLinkEntry::QKDKeyAssociationLinkEntry(){
      m_valid = false;
    }

    QKDKeyAssociationLinkEntry::QKDKeyAssociationLinkEntry (
        uint32_t local_qkd_node_id,
        uint32_t remote_qkd_node_id,
        uint32_t nextHop,
        uint32_t hops,   
        uint32_t type, //Virtual (multi-hop) - value 1  or Direct - value 0.
        Ipv4Address kmsSrcAddress,
        Ipv4Address kmsDstAddress,
        Ptr<QKDBuffer> srcBuffer
    )
      : m_qkdl_local_qkdn_id (local_qkd_node_id),
        m_qkdl_remote_qkdn_id (remote_qkd_node_id), 
        m_qkdl_type (type),
        m_virt_next_hop (nextHop), 
        m_kmsSrcAddress (kmsSrcAddress),
        m_kmsDstAddress (kmsDstAddress),
        m_hops (hops),
        m_srcQKDBuffer(srcBuffer)
    {
        m_qkdl_id = UUID::Random();
        m_qkdl_performance_eskr = 0;
        m_qkdl_performance_expected_consumption = 0;
        m_qkdl_performance_skr = 0; //init value
        m_qkdl_enable = true;
        m_valid = true;
        
        NS_LOG_FUNCTION(this 
          << "CREATE NEW KEY ASSOCIATION ENTRY!"
          << m_qkdl_id 
          << m_qkdl_local_qkdn_id 
          << m_qkdl_remote_qkdn_id 
          << m_virt_next_hop 
          << m_hops
          << m_kmsSrcAddress
          << m_kmsDstAddress
          << m_qkdl_performance_skr
        );
    }

     QKDKeyAssociationLinkEntry::QKDKeyAssociationLinkEntry (
        UUID qkd_id,
        uint32_t local_qkd_node_id,
        uint32_t remote_qkd_node_id,
        uint32_t nextHop,
        uint32_t hops,   
        uint32_t type, //Virtual (multi-hop) - value 1  or Direct - value 0.
        Ipv4Address kmsSrcAddress,
        Ipv4Address kmsDstAddress,
        Ptr<QKDBuffer> srcBuffer
    )
      : m_qkdl_id (qkd_id),
        m_qkdl_local_qkdn_id (local_qkd_node_id),
        m_qkdl_remote_qkdn_id (remote_qkd_node_id), 
        m_qkdl_type (type),
        m_virt_next_hop (nextHop), 
        m_kmsSrcAddress (kmsSrcAddress),
        m_kmsDstAddress (kmsDstAddress),
        m_hops (hops),
        m_srcQKDBuffer(srcBuffer)
    {
        m_qkdl_performance_eskr = 0;
        m_qkdl_performance_expected_consumption = 0;
        m_qkdl_performance_skr = 0; //init value
        m_qkdl_enable = true;
        m_valid = true;
        
        NS_LOG_FUNCTION(this 
          << "CREATE NEW KEY ASSOCIATION ENTRY!"
          << m_qkdl_id 
          << m_qkdl_local_qkdn_id 
          << m_qkdl_remote_qkdn_id 
          << m_virt_next_hop 
          << m_hops
          << m_kmsSrcAddress
          << m_kmsDstAddress
          << m_qkdl_performance_skr
        );
    }

    QKDKeyAssociationLinkEntry::~QKDKeyAssociationLinkEntry () {}

    bool
    QKDKeyAssociationLinkEntry::CheckSAEApplicationExists(UUID appId){

      NS_LOG_FUNCTION(this << appId << m_qkdl_applications.size());

      std::vector<UUID>::iterator it = std::find(
        m_qkdl_applications.begin(), 
        m_qkdl_applications.end(), 
        appId
      );
      
      if(it == m_qkdl_applications.end()) {
        NS_LOG_FUNCTION(this << "No SAE application found with UUID " << appId);
        return false;
      }
      NS_LOG_FUNCTION(this << "SAE application with UUID " << appId << " FOUND!");
      return true;
    }

    void
    QKDKeyAssociationLinkEntry::PrintSAEApplications(){

      NS_LOG_FUNCTION(this << m_qkdl_applications.size());

      for(std::vector<UUID>::size_type i = 0; i != m_qkdl_applications.size(); i++) {
        NS_LOG_FUNCTION(this << i << ": " << m_qkdl_applications[i]);
      }
    }

    void
    QKDKeyAssociationLinkEntry::UpdateQKDApplications(UUID appId){ 
      m_qkdl_applications.push_back(appId);
    }

    void
    QKDKeyAssociationLinkEntry::PrintRegistryInfo ()
    {
        NS_LOG_FUNCTION(this 
          << m_qkdl_id 
          << m_qkdl_local_qkdn_id 
          << m_qkdl_remote_qkdn_id 
          << m_virt_next_hop 
          << m_hops
          << "apps:" << m_qkdl_applications.size()
          << m_kmsSrcAddress
          << m_kmsDstAddress
          << m_qkdl_performance_skr
        );
    }

    void
    QKDKeyAssociationLinkEntry::Print (Ptr<OutputStreamWrapper> stream) const
    { 
        *stream->GetStream ()
          << m_qkdl_id              << "\t"
          << m_qkdl_local_qkdn_id   << "\t"
          << m_qkdl_remote_qkdn_id  << "\t"
          << m_virt_next_hop        << "\t"
          << m_hops                 << "\t"
          << "apps:" << m_qkdl_applications.size() << "\t"
          << m_kmsSrcAddress        << "\t"
          << m_kmsDstAddress        << "\t"
          << m_qkdl_performance_skr << "\n"
        ;
    }

    void
    QKDKeyAssociationLinkEntry::SetUpdateStatusInterval(double statusInterval){
      m_update_status_interval = statusInterval;
    }

    double
    QKDKeyAssociationLinkEntry::GetUpdateStatusInterval(){
      return (double) m_update_status_interval;
    }

    double
    QKDKeyAssociationLinkEntry::GetSKR(){
      NS_LOG_FUNCTION(this << m_qkdl_performance_skr);
      if (std::isnan(m_qkdl_performance_skr)) return 0;
      return (double) m_qkdl_performance_skr;
    }

    void
    QKDKeyAssociationLinkEntry::SetSKR(double value){ 
      if (std::isnan(m_qkdl_performance_skr)) 
        m_qkdl_performance_skr = 0;
      else
        m_qkdl_performance_skr = value;
      NS_LOG_FUNCTION(this << m_qkdl_performance_skr);
    }

    double
    QKDKeyAssociationLinkEntry::GetExpectedConsumption(){
      NS_LOG_FUNCTION(this << m_qkdl_performance_expected_consumption);
      if (std::isnan(m_qkdl_performance_expected_consumption)) return 0;
      return (double) m_qkdl_performance_expected_consumption;
    }

    void
    QKDKeyAssociationLinkEntry::SetExpectedConsumption(double value){
      if (std::isnan(m_qkdl_performance_expected_consumption)) 
        m_qkdl_performance_expected_consumption = 0;
      else
        m_qkdl_performance_expected_consumption = value;
      NS_LOG_FUNCTION(this << m_qkdl_performance_expected_consumption);
    }

    double
    QKDKeyAssociationLinkEntry::GetEffectiveSKR(){
      NS_LOG_FUNCTION(this << m_qkdl_performance_eskr);
      if (std::isnan(m_qkdl_performance_eskr)) return 0;
      return (double) m_qkdl_performance_eskr;
    }

    void
    QKDKeyAssociationLinkEntry::SetEffectiveSKR(double value){
      if (std::isnan(m_qkdl_performance_eskr)) 
        m_qkdl_performance_eskr = 0;
      else
        m_qkdl_performance_eskr = value;
      NS_LOG_FUNCTION(this << m_qkdl_performance_eskr);
    }
 
} // namespace ns3