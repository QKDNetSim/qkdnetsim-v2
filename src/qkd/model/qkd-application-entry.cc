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
 
#include "ns3/qkd-application-entry.h"

namespace ns3 {

    NS_LOG_COMPONENT_DEFINE ("QKDApplicationEntry");

    NS_OBJECT_ENSURE_REGISTERED (QKDApplicationEntry);
          
    TypeId 
    QKDApplicationEntry::GetTypeId (void) 
    {
      static TypeId tid = TypeId ("ns3::QKDApplicationEntry")
        .SetParent<Object> () 
        .SetGroupName ("QKDApplicationEntry")
        .AddConstructor<QKDApplicationEntry> ()
        ;
      return tid;
    } 

    TypeId
    QKDApplicationEntry::GetInstanceTypeId (void) const
    {
      return GetTypeId ();
    }

    QKDApplicationEntry::QKDApplicationEntry(){
      m_valid = false;
    }
     
    QKDApplicationEntry::QKDApplicationEntry (
        UUID keyAssociationId,
        UUID srcSaeId,
        UUID dstSaeId,
        ConnectionType type,
        uint32_t priority,
        double expirationTime,
        Ipv4Address srcKMSAddress,
        Ipv4Address dstKMSAddress
    )
      : m_app_type (type), 
        m_client_app_id (srcSaeId), 
        m_server_app_id (dstSaeId), 
        m_backing_qkdl_id (keyAssociationId),
        m_app_priority (priority),
        m_expiration_time (expirationTime),
        m_kmsSrcAddress(srcKMSAddress),
        m_kmsDstAddress(dstKMSAddress)
    {
        m_app_id = UUID::Random(); 
        m_valid = true;
        NS_LOG_FUNCTION(this 
          << "CREATE NEW QKD APPLICATION ENTRY!"
          << m_valid
          << m_app_id
          << m_backing_qkdl_id 
          << m_client_app_id 
          << m_server_app_id 
          << m_app_type 
          << m_app_priority
          << m_expiration_time
          << m_kmsSrcAddress
          << m_kmsDstAddress
        );
    }

    QKDApplicationEntry::~QKDApplicationEntry ()
    {
    }
    
    void
    QKDApplicationEntry::PrintRegistryInfo ()
    {
        NS_LOG_FUNCTION(this 
          << m_valid
          << m_app_id
          << m_backing_qkdl_id 
          << m_client_app_id 
          << m_server_app_id 
          << m_app_type 
          << m_app_priority
          << m_expiration_time
          << m_kmsSrcAddress
          << m_kmsDstAddress
        );
    }

    void
    QKDApplicationEntry::Print (Ptr<OutputStreamWrapper> stream) const
    {
       *stream->GetStream ()
          << m_valid                << "\t"
          << m_app_id               << "\t"
          << m_backing_qkdl_id      << "\t"
          << m_client_app_id        << "\t"
          << m_server_app_id        << "\t"
          << m_app_type             << "\t"
          << m_app_priority         << "\t"
          << m_expiration_time      << "\t"
          << m_kmsSrcAddress        << "\t"
          << m_kmsDstAddress        << "\n"
      ;
    }
 
} // namespace ns3