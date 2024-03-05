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
#ifndef QKD_CONNECTION_REGISTER_H
#define QKD_CONNECTION_REGISTER_H
 
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
 
#include "ns3/qkd-key-association-link-entry.h"
#include "ns3/qkd-application-entry.h"

#include <map>
#include <iostream>
#include <sstream>

namespace ns3 {
    
class QKDKeyAssociationLinkEntry;
class QKDApplicationEntry;
 
/**
 * \ingroup qkd
 * \class QKDConnectionRegister
 * \brief QKDConnectionRegister is a class used to 
 * keep details about distant QKD links and applications
 *
 * \note QKDNetSim KMS implements a location register table that is used
 * to define paths to distant node. It is a early version of routing table
 * that will be updated via routing protocol.
 */
 
class QKDConnectionRegister : public Object 
{
  public:

    /**
    * \brief Get the type ID.
    * \return The object TypeId.
    */
    static TypeId GetTypeId (void);

    /**
    * \brief Get the type ID for the instance.
    * \return The instance TypeId
    */
    virtual TypeId GetInstanceTypeId (void) const;

    /**
     * \brief Constructor.
     */
    QKDConnectionRegister ();
    
    /**
     * \brief Add the QKD application entry if it doesn't yet exist in the table.
     * \param r The location table entry.
     * \return The success indicator.
     */
    bool
    AddApplicationEntry (QKDApplicationEntry & r);
    
    /**
     * \brief Add the key association entry if it doesn't yet exist in the table.
     * \param r The location table entry.
     * \return The success indicator.
     */
    bool
    AddKeyAssociationEntry (QKDKeyAssociationLinkEntry & r);
    
    /**
     * \brief Delete the application entry, if it exists.
     * \param dst The destination (receiver) application identifier (UUID).
     * \return The success indicator.
     */
    bool
    DeleteApplicationEntry (UUID dst);
    
    /**
     * \brief Delete the key association table entry with a given destination, if it exists.
     * \param dst The destination node identifier
     * \return The success indicator.
     */
    bool
    DeleteKeyAssociationLinkEntry (uint32_t dst);

    /**
     * \brief Lookup the application entry with the application identifiers and the connection type.
     * \param src The source (sender) application identifier (UUID).
     * \param dst The destination (receiver) application identifier (UUID).
     * \param type The conncetion type.
     * \param rt The entry with the destination address dst, if exists.
     * \return The lookup success indicator.
     */
    bool
    LookupApplicationBySaeIDsAndType (
      UUID srcSaeId, 
      UUID dstSaeId, 
      QKDApplicationEntry::ConnectionType type,
      QKDApplicationEntry & rt
    ); 

    /**
     * \brief Lookup the application entry with the destination (receiver) application identifier (UUID).
     * \param dst The destination (receiver) application identifier (UUID).
     * \param rt The entry with the destination address dst, if exists.
     * \return The lookup success indicator.
     */
    bool
    LookupApplication (UUID dstSaeId, QKDApplicationEntry & rt); 
    
    /**
     * \brief Lookup the key association entry with destination node identifier.
     * \param dst The destination node identifier.
     * \param rt The entry with the destination address dst, if exists.
     * \return The lookup success indicator.
     */
    bool
    LookupKeyAssociationById (UUID keyAssociationId, QKDKeyAssociationLinkEntry & rt); 

    /**
     * \brief Store the key association entry.
     * \param The key association entry.
     * \return The success indicator.
     */
    bool
    SaveKeyAssociation(QKDKeyAssociationLinkEntry& rt);

    /**
     * \brief Lookup the key association entry with the application identifier (UUID).
     * \param id The application identifier (UUID).
     * \param rt The entry with the destination identifier id, if exists.
     * \return The lookup success indicator.
     */
    bool
    LookupKeyAssociationBySaeId (UUID id, QKDKeyAssociationLinkEntry & rt);

    /**
     * \brief Lookup the key association entry with the source and destination identifiers.
     * \param srcNodeId The source node identifier.
     * \param dstNodeId The destination node identifier.
     * \param rt The entry with either the source or destination node identifier, if exists.
     * \return The lookup success indicator.
     */
    bool
    LookupKeyAssociationByDestinationNodeId ( 
      uint32_t srcNodeId, 
      uint32_t dstNodeId, 
      QKDKeyAssociationLinkEntry & rt 
    );

    /**
     * \brief Lookup the key association entry with the application identifier (UUID).
     * \param saeId The application identifier (UUID).
     * \param rt The entry with the application saeId, if exists.
     * \return The lookup success indicator.
     */
    bool
    LookupKeyAssociationByApplicationId(
      UUID saeId,
      QKDKeyAssociationLinkEntry & rt
    );

    /**
     * \brief Update the key association list of QKD applications.
     * \param keyAssociationId The key association identifier.
     * \param saeId The application identifier (UUID).
     */
    void
    UpdateQKDApplications(UUID keyAssociationId, UUID saeId);

    /**
     * \brief Print the key association list.
     */
    void
    PrintListOfAllKeyAssociations ();
    
    /**
     * \brief Print the location table.
     * \param stream The output stream.
     */
    void
    Print (Ptr<OutputStreamWrapper> stream) const;
    
    /**
     * \briet Get the number of the key associations present in the associations table.
     * \returns The number of the key associations.
     */
    uint32_t
    GetNumberOfKeyAssociations (){
      return m_keyAssociations.size();
    }

    /**
     * \brief Get the number of the applications present in the applications table.
     * \returns The number of the applications.
     */
    uint32_t
    GetNumberOfApplications (){
      return m_applications.size();
    }

    /**
     * \brief Assign the key association.
     * \param srdSaeId The soruce (sender) application identifier (UUID).
     * \param dstSaeId The destination (receiver) application identifier (UUID).
     * \param type The key association type.
     * \param priority The key association priority.
     * \param rt The entry with the application dstId, if exists.
     * \return The success indicator.
     */
    bool AssignKeyAssociation(
        UUID srcSaeId,
        UUID dstSaeId,
        std::string type,
        uint32_t priority,
        QKDKeyAssociationLinkEntry & rt
    );
    
  private: 
    std::map<uint32_t, QKDKeyAssociationLinkEntry>  m_keyAssociations;  //!< The list of key associations.
    std::map<UUID, QKDApplicationEntry>         m_applications; //!< The list of applications.

};

 

} // namespace ns3

#endif /* QKD_CONNECTION_REGISTER_H */

