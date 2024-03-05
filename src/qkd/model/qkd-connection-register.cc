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

#include "ns3/qkd-connection-register.h"
 
namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDConnectionRegister");

NS_OBJECT_ENSURE_REGISTERED (QKDConnectionRegister);

TypeId 
QKDConnectionRegister::GetTypeId (void) 
{
  static TypeId tid = TypeId ("ns3::QKDConnectionRegister")
    .SetParent<Object> () 
    .SetGroupName ("QKDConnectionRegister")
    .AddConstructor<QKDConnectionRegister> ()
    ;
  return tid;
} 

TypeId
QKDConnectionRegister::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

QKDConnectionRegister::QKDConnectionRegister(){}

bool
QKDConnectionRegister::AddApplicationEntry (QKDApplicationEntry & rt)
{
    NS_LOG_FUNCTION(this << rt.GetId () );

    std::pair<std::map<UUID, QKDApplicationEntry>::iterator, bool> result = m_applications.insert (
        std::make_pair (rt.GetId (), rt)
    );


    for (std::map<UUID, QKDApplicationEntry>::iterator i3 = m_applications.begin (); i3 != m_applications.end (); ++i3)
    {  
        NS_LOG_FUNCTION(this 
            << "aaaaaa" 
            << i3->second.GetId() 
            << i3->second.GetSrcSaeId() 
            << i3->second.GetDestinationSaeId()
            << i3->second.GetType() 
        );
    }

    return result.second;
}

bool
QKDConnectionRegister::AddKeyAssociationEntry (QKDKeyAssociationLinkEntry & rt)
{
    NS_LOG_FUNCTION(this << "saving keyAssociationId:" << rt.GetId().string());
    std::pair<std::map<uint32_t, QKDKeyAssociationLinkEntry>::iterator, bool> result = m_keyAssociations.insert (
        std::make_pair (rt.GetDestinationNodeId (),rt)
    );
    return result.second;
}

bool
QKDConnectionRegister::DeleteApplicationEntry (UUID dstSaeId)
{
    if (m_applications.erase (dstSaeId) != 0) return true;
    return false;
}

bool
QKDConnectionRegister::DeleteKeyAssociationLinkEntry (uint32_t dstSaeId)
{
    if (m_keyAssociations.erase (dstSaeId) != 0) return true;
    return false;
}

bool
QKDConnectionRegister::LookupApplication (
    UUID id,
    QKDApplicationEntry & rt
){
    NS_LOG_FUNCTION(this << id << m_applications.size() );
    if (m_applications.empty ()) return false;

    std::map<UUID, QKDApplicationEntry>::const_iterator i = m_applications.find (id);
    if (i != m_applications.end ()) { 
        rt = i->second;
        return true;
    }else{

        for (std::map<UUID, QKDApplicationEntry>::iterator i3 = m_applications.begin (); i3 != m_applications.end (); ++i3)
        { 
            if(
                i3->second.GetSrcSaeId() == id || i3->second.GetDestinationSaeId() == id
            ){ 
                rt = i3->second;
                return true;
            }

            NS_LOG_FUNCTION(this 
                << "bbbbbb" 
                << i3->second.GetId() 
                << i3->second.GetSrcSaeId() 
                << i3->second.GetDestinationSaeId()
                << i3->second.GetType() 
            );
        }
    }
    return false;

}

bool
QKDConnectionRegister::LookupApplicationBySaeIDsAndType (
    UUID srcSaeId,
    UUID dstSaeId,
    QKDApplicationEntry::ConnectionType type,
    QKDApplicationEntry & rt
){
    NS_LOG_FUNCTION(this << srcSaeId << dstSaeId << type << m_applications.size() );
    if (m_applications.empty ()) return false;

    for (std::map<UUID, QKDApplicationEntry>::iterator i3 = m_applications.begin (); i3 != m_applications.end (); ++i3)
    { 
        if(
            (
                (i3->second.GetSrcSaeId() == srcSaeId && i3->second.GetDestinationSaeId() == dstSaeId) || 
                (i3->second.GetSrcSaeId() == dstSaeId && i3->second.GetDestinationSaeId() == srcSaeId)
            ) && i3->second.GetType() == type 
        ){ 
            rt = i3->second;
            return true;
        }

        NS_LOG_FUNCTION(this 
            << "bbbbbb" 
            << i3->second.GetId() 
            << i3->second.GetSrcSaeId() 
            << i3->second.GetDestinationSaeId()
            << i3->second.GetType() 
        );
    }
    
    return false;
}



bool
QKDConnectionRegister::LookupKeyAssociationById (
    UUID keyAssociationId,
    QKDKeyAssociationLinkEntry & rt
){
    NS_LOG_FUNCTION(this << keyAssociationId );

    if (m_keyAssociations.empty ()) return false;
    for (std::map<uint32_t, QKDKeyAssociationLinkEntry>::iterator i = m_keyAssociations.begin (); i != m_keyAssociations.end (); ++i)
    {
        if(i->second.GetId() == keyAssociationId){
            rt = i->second;
            return true;
        }
    }    
    return false;
}

bool
QKDConnectionRegister::LookupKeyAssociationByDestinationNodeId(
    uint32_t srcNodeId,
    uint32_t dstNodeId,
    QKDKeyAssociationLinkEntry & rt
){
    NS_LOG_FUNCTION(this << srcNodeId << dstNodeId);

    if (m_keyAssociations.empty ()) return false; 

    for (std::map<uint32_t, QKDKeyAssociationLinkEntry>::iterator i = m_keyAssociations.begin (); i != m_keyAssociations.end (); ++i)
    { 
        if(
            (i->second.GetSourceNodeId() == srcNodeId && i->second.GetDestinationNodeId() == dstNodeId) || 
            (i->second.GetSourceNodeId() == dstNodeId && i->second.GetDestinationNodeId() == srcNodeId)
        ){
            rt = i->second;
            return true;
        }
    }
    return false;
}

bool
QKDConnectionRegister::LookupKeyAssociationByApplicationId(
    UUID appId,
    QKDKeyAssociationLinkEntry & rt
){
    NS_LOG_FUNCTION(this << appId << m_keyAssociations.size() );
    PrintListOfAllKeyAssociations();

    if (m_keyAssociations.empty ()) return false;
    std::map<double, QKDKeyAssociationLinkEntry> connectedLinks;
    for (std::map<uint32_t, QKDKeyAssociationLinkEntry>::iterator i = m_keyAssociations.begin (); i != m_keyAssociations.end (); ++i)
    { 
        if( i->second.CheckSAEApplicationExists(appId) ) {
            connectedLinks.insert(
                std::make_pair(i->second.GetEffectiveSKR(), i->second)
            );
            rt = i->second;
        }
    }

    //@toDo: one qkd application can be connected to multiple key association entries
    if(connectedLinks.size()){   
        uint32_t counter = 1;
        uint32_t random = rand() % connectedLinks.size();
        for (std::map<double, QKDKeyAssociationLinkEntry>::iterator i = connectedLinks.begin (); i != connectedLinks.end (); ++i)
        {  
            if(counter == random){
                rt = i->second;
                return true;
            }
            counter++;
        }
    }
    return false;
}

bool
QKDConnectionRegister::AssignKeyAssociation(
    UUID srcSaeId,
    UUID dstSaeId,
    std::string type,
    uint32_t priority,
    QKDKeyAssociationLinkEntry & rt
){
    NS_LOG_FUNCTION(this << srcSaeId << dstSaeId << type << priority << m_keyAssociations.size() );
    PrintListOfAllKeyAssociations();

    if (m_keyAssociations.empty ()) return false;
    std::map<double, QKDKeyAssociationLinkEntry> connectedLinks;
    for (std::map<uint32_t, QKDKeyAssociationLinkEntry>::iterator i = m_keyAssociations.begin (); i != m_keyAssociations.end (); ++i)
    { 
        NS_LOG_FUNCTION(this << "Assigned keyAssociationId:" << i->second.GetId().string());
        rt = i->second;
        return true;
    }
    return false;
}

bool
QKDConnectionRegister::SaveKeyAssociation(
    QKDKeyAssociationLinkEntry & rt
){
    NS_LOG_FUNCTION(this << rt.GetId() );
    PrintListOfAllKeyAssociations();

    if (m_keyAssociations.empty ()) return false;
    for (std::map<uint32_t, QKDKeyAssociationLinkEntry>::iterator i = m_keyAssociations.begin (); i != m_keyAssociations.end (); ++i)
    {
        if(i->second.GetId() == rt.GetId()){
            i->second = rt;
            return true;
        }
    }    
    return false;
}

void
QKDConnectionRegister::PrintListOfAllKeyAssociations ()
{
    NS_LOG_FUNCTION(this << m_keyAssociations.size() );

    for (std::map<uint32_t, QKDKeyAssociationLinkEntry>::iterator i = m_keyAssociations.begin (); i != m_keyAssociations.end (); ++i)
    {  
        i->second.PrintSAEApplications();
    }
}

void
QKDConnectionRegister::UpdateQKDApplications(UUID keyAssociationId, UUID appId){

    NS_LOG_FUNCTION(this << keyAssociationId << appId);

    bool keyAssociationFound = false;
    for (std::map<uint32_t, QKDKeyAssociationLinkEntry>::iterator i = m_keyAssociations.begin (); i != m_keyAssociations.end (); ++i)
    {
        if(i->second.GetId() == keyAssociationId){
            i->second.UpdateQKDApplications(appId);
            i->second.PrintRegistryInfo();
            i->second.PrintSAEApplications();
            keyAssociationFound = true;
        }
    }
    if(!keyAssociationFound){
        NS_LOG_FUNCTION(this << "No key association found with id " << keyAssociationId);
    }
}


/*
void
QKDConnectionRegister::GetListOfAllEntries (std::map<uint32_t, QKDConnectionRegisterEntry> & allRoutes)
{
  for (std::map<uint32_t, QKDConnectionRegisterEntry>::iterator i = m_locationEntites.begin (); i != m_locationEntites.end (); ++i)
    {
        allRoutes.insert (std::make_pair (i->first,i->second));
    }
}

void
QKDConnectionRegister::GetListOfDestinationWithNextHop (uint32_t nextHop,
                                               std::map<uint32_t, QKDConnectionRegisterEntry> & unreachable)
{
  unreachable.clear ();
  for (std::map<uint32_t, QKDConnectionRegisterEntry>::const_iterator i = m_locationEntites.begin (); i
       != m_locationEntites.end (); ++i)
    {
      if (i->second.GetNextHop () == nextHop)
        {
          unreachable.insert (std::make_pair (i->first,i->second));
        }
    }
}
*/


} // namespace ns3