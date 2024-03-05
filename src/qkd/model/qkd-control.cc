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
 * Author: Miralem Mehic <miralem.mehic@ieee.org>
 */

#include <cmath>
#include <algorithm>                                                      
#include <numeric>    
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/log.h" 
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/uinteger.h" 

#include "qkd-control.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDControl");

NS_OBJECT_ENSURE_REGISTERED (QKDControl);

TypeId 
QKDControl::GetTypeId (void) 
{
  static TypeId tid = TypeId ("ns3::QKDControl")
    .SetParent<Object> () 
    .SetGroupName ("QKDControl")
    .AddConstructor<QKDControl> ()
    .AddAttribute ("BufferList", "The list of buffers associated to this QKD Control.",
                   ObjectVectorValue (),
                   MakeObjectVectorAccessor (&QKDControl::m_qkdbuffers),
                   MakeObjectVectorChecker<QKDControl> ())
    ;
  return tid;
} 

TypeId
QKDControl::GetInstanceTypeId (void) const
{
  return GetTypeId ();
}

QKDControl::QKDControl () 
  : Object ()
{ 
  NS_LOG_FUNCTION_NOARGS ();
}
 
QKDControl::~QKDControl ()
{  
    m_destinations.clear();
}

void
QKDControl::DoDispose ()
{ 
    for (std::vector<Ptr<QKDBuffer> >::iterator i = m_qkdbuffers.begin ();
       i != m_qkdbuffers.end (); i++)
    {
        Ptr<QKDBuffer> device = *i;
        device->Dispose ();
        *i = 0;
    }
    m_qkdbuffers.clear (); 
    Object::DoDispose ();
}

void 
QKDControl::DoInitialize (void)
{
    NS_LOG_FUNCTION (this); 
    Object::DoInitialize ();
} 

struct QKDControl::QKDLink
QKDControl::AddNewLink (   
    Ptr<Node>               a, //alice
    Ptr<Node>               b, //bob 
    Ptr<Node>               aKMS, //alice KMS
    Ptr<Node>               bKMS, //bob KMS
    uint32_t                Mmin, 
    uint32_t                Mthr, 
    uint32_t                Mmax, 
    uint32_t                Mcurrent,
    bool                    isMaster,
    bool                    useRealStorages
)
{  
    NS_LOG_FUNCTION (this << GetNode()->GetId() << a->GetId() <<  b->GetId() ); 
        
    // Only one buffer can exist per connection between two nodes!
    // It is possible to implement multiple number of links,
    // but if the source and the destination of the link is the same, 
    // these links belong to the same connection and they sohuld use the same buffer.
    std::map<uint32_t, QKDControl::QKDLink >::iterator i = m_destinations.find ( b->GetId() );
    if (i != m_destinations.end ()){

        NS_LOG_FUNCTION (this << "BUFFER ALREADY EXISTS!");
        return i->second;

    }else{

        struct QKDControl::QKDLink newLink; 
        newLink.alice = a;
        newLink.bob   = b; 
        newLink.publicChannelMetric = 0;
        newLink.quantumChannelMetric = 0;

        NS_LOG_FUNCTION (this << GetNode()->GetId() << "CREATE NEW BUFFER FOR ALICE!");
        newLink.qkdBufferAlice = CreateObject<QKDBuffer> ();
        newLink.qkdBufferAlice->Init(
            a,
            b,
            Mmin,
            Mthr,
            Mmax,
            Mcurrent,
            useRealStorages
        );
        m_qkdbuffers.push_back(newLink.qkdBufferAlice); 
        newLink.qkdBufferAlice->SetIndex( m_qkdbuffers.size() - 1 );

        NS_LOG_FUNCTION (this << GetNode()->GetId() << "CREATE NEW BUFFER FOR BOB!");
        newLink.qkdBufferBob = CreateObject<QKDBuffer> ();
        newLink.qkdBufferBob->Init(
            b,
            a,
            Mmin,
            Mthr,
            Mmax,
            Mcurrent,
            useRealStorages
        );

        m_destinations.insert (std::make_pair ( b->GetId(), newLink) );
        NS_LOG_FUNCTION (this << GetNode()->GetId() << "save destination to " << b->GetId() ); 
    
        Ptr<QKDKeyManagerSystemApplication> lkmsA;
        Ptr<QKDKeyManagerSystemApplication> lkmsB;
        for (uint32_t i = 0; i < aKMS->GetNApplications (); ++i){
            lkmsA = aKMS->GetApplication (i)->GetObject <QKDKeyManagerSystemApplication> (); 
            if(lkmsA) break;
        }
        for (uint32_t i = 0; i < bKMS->GetNApplications (); ++i){
            lkmsB = bKMS->GetApplication (i)->GetObject <QKDKeyManagerSystemApplication> ();
            if(lkmsB) break;
        } 

        if(lkmsA && lkmsB){
            std::string keyAssociationId = lkmsA->AddNewLink(
                a->GetId(),
                b->GetId(), 
                lkmsB->GetAddress(),
                newLink.qkdBufferAlice
            );
            newLink.keyAssociationId = keyAssociationId;

            lkmsB->AddNewLink(
                b->GetId(),
                a->GetId(), 
                lkmsA->GetAddress(),
                newLink.qkdBufferBob,
                keyAssociationId
            );
        }else{
            NS_FATAL_ERROR ("NO QKD KEY MANAGER INSTALLED ON THE NODE!");
        }

        return newLink;
    }
}
 
void
QKDControl::AddLinkRecord (struct QKDControl::QKDLink newLink)
{
    NS_LOG_FUNCTION (this << GetNode()->GetId() <<  newLink.alice->GetId() ); 
        
    // Only one buffer can exist per connection between two nodes!
    // It is possible to implement multiple number of links,
    // but if the source and the destination of the link is the same, 
    // these links belong to the same connection and they sohuld use the same buffer.
    std::map<uint32_t, QKDControl::QKDLink >::iterator i = m_destinations.find ( newLink.alice->GetId() );
    if (i != m_destinations.end ()){
        NS_LOG_FUNCTION (this << "BUFFER ALREADY EXISTS!");
    }else{
        Ptr<Node> temp = newLink.alice;
        newLink.alice = newLink.bob;
        newLink.bob   = temp;
        m_qkdbuffers.push_back( newLink.qkdBufferBob );
        newLink.qkdBufferBob->SetIndex( m_qkdbuffers.size() - 1 );
        m_destinations.insert (std::make_pair ( newLink.bob->GetId(), newLink) );

        NS_LOG_FUNCTION (this << GetNode()->GetId() << "save destination to " <<  newLink.bob->GetId() ); 
    }
}



Ptr<QKDBuffer>
QKDControl::GetBufferByDestinationNode (Ptr<Node> dst) {

    NS_LOG_FUNCTION(this << GetNode()->GetId() << dst->GetId() << m_destinations.size() );

    std::map<uint32_t, QKDControl::QKDLink >::iterator i = m_destinations.find ( dst->GetId() );
    if (i != m_destinations.end ()){
        return i->second.qkdBufferAlice;    
    }else{
        NS_LOG_FUNCTION(this << GetNode()->GetId() << "Unable to find QKDbuffer for destination " << dst->GetId());
        return 0;
    }
}
 
uint32_t 
QKDControl::GetNQKDBuffers (void) const
{
  NS_LOG_FUNCTION (this);
  return m_qkdbuffers.size ();
} 

Ptr<Node> 
QKDControl::GetNode() {
    return m_node;
}

void 
QKDControl::SetNode (Ptr<Node> node) {
    m_node = node;
}


std::vector<std::string> 
QKDControl::RegisterQKDApplications(
    Ptr<QKDApp004> alice, 
    Ptr<QKDApp004> bob,
    Ptr<QKDKeyManagerSystemApplication> kmsA,
    Ptr<QKDKeyManagerSystemApplication> kmsB
){   
    NS_LOG_FUNCTION(this);

    std::vector<std::string> output;

    UintegerValue aliceEncryptionType;
    UintegerValue bobEncryptionType;

    UintegerValue aliceAuthenticationType;
    UintegerValue bobAuthenticationType;

    alice->GetAttribute ("EncryptionType", aliceEncryptionType);
    alice->GetAttribute ("AuthenticationType", aliceAuthenticationType);

    bob->GetAttribute ("EncryptionType", bobEncryptionType);
    bob->GetAttribute ("AuthenticationType", bobAuthenticationType);
 
    NS_ASSERT (aliceEncryptionType.Get()      == bobEncryptionType.Get());
    NS_ASSERT (aliceAuthenticationType.Get()  == bobAuthenticationType.Get());

    UintegerValue priorityAttrValue;
    alice->GetAttribute ("Priority", priorityAttrValue);
    uint32_t priority = priorityAttrValue.Get();

    UUID aliceId = alice->GetId();
    UUID bobId = bob->GetId();
  
    if(
        aliceEncryptionType.Get() == QKDEncryptor::QKDCRYPTO_OTP || 
        aliceEncryptionType.Get() == QKDEncryptor::QKDCRYPTO_AES
    ){
        QKDApplicationEntry appEntry = kmsA->RegisterApplicationEntry(
            aliceId,
            bobId,
            "etsi004_enc", 
            kmsB->GetAddress(),
            priority,
            200 //expiration time value of the application entry. @toDo: for later usage purge expired apps
        );
        std::string appId = appEntry.GetId().string();
        NS_LOG_FUNCTION(this << appId);
        output.push_back(appId);

        QKDApplicationEntry appEntry2 = kmsB->RegisterApplicationEntry(
            appEntry.GetKeyAssociationId(),
            appEntry.GetId(),
            bobId,
            aliceId,
            "etsi004_enc", 
            kmsA->GetAddress(),
            priority,
            200 //expiration time value of the application entry. @toDo: for later usage purge expired apps
        );
        NS_LOG_FUNCTION(this << "Encryption SAE connections established!");

        alice->SetKsidEncryption(appEntry.GetId());
        bob->SetKsidEncryption(appEntry.GetId());
    } 
    
    if(
        aliceAuthenticationType.Get() == QKDEncryptor::QKDCRYPTO_AUTH_VMAC 
    ){
        QKDApplicationEntry appEntry = kmsA->RegisterApplicationEntry(
            aliceId,
            bobId,
            "etsi004_auth", 
            kmsB->GetAddress(),
            priority,
            200 //expiration time value of the application entry. @toDo: for later usage purge expired apps
        );
        std::string appId = appEntry.GetId().string();
        NS_LOG_FUNCTION(this << appId);
        output.push_back(appId);

        QKDApplicationEntry appEntry2 = kmsB->RegisterApplicationEntry(
            appEntry.GetKeyAssociationId(),
            appEntry.GetId(),
            bobId,
            aliceId,
            "etsi004_auth", 
            kmsA->GetAddress(),
            priority,
            200 //expiration time value of the application entry. @toDo: for later usage purge expired apps
        );
        NS_LOG_FUNCTION(this << "Authentication SAE connections established!");

        alice->SetKsidAuthentication(appEntry.GetId());
        bob->SetKsidAuthentication(appEntry.GetId());
    } 
    
    NS_LOG_FUNCTION(this << output.size());

    return output;
}


std::vector<std::string> 
QKDControl::RegisterQKDApplications(
    Ptr<QKDApp014> alice, 
    Ptr<QKDApp014> bob,
    Ptr<QKDKeyManagerSystemApplication> kmsA,
    Ptr<QKDKeyManagerSystemApplication> kmsB
){   
    NS_LOG_FUNCTION(this);

    std::vector<std::string> output;

    UintegerValue aliceEncryptionType;
    UintegerValue bobEncryptionType;

    UintegerValue aliceAuthenticationType;
    UintegerValue bobAuthenticationType;

    alice->GetAttribute ("EncryptionType", aliceEncryptionType);
    alice->GetAttribute ("AuthenticationType", aliceAuthenticationType);

    bob->GetAttribute ("EncryptionType", bobEncryptionType);
    bob->GetAttribute ("AuthenticationType", bobAuthenticationType);
 
    NS_ASSERT (aliceEncryptionType.Get()      == bobEncryptionType.Get());
    NS_ASSERT (aliceAuthenticationType.Get()  == bobAuthenticationType.Get());

    //UintegerValue priorityAttrValue;
    //alice->GetAttribute ("Priority", priorityAttrValue);
    uint32_t priority = 0;//priorityAttrValue.Get();

    UUID aliceId = alice->GetId();
    UUID bobId = bob->GetId();
  
    if(
        aliceEncryptionType.Get() == QKDEncryptor::QKDCRYPTO_OTP || 
        aliceEncryptionType.Get() == QKDEncryptor::QKDCRYPTO_AES
    ){
        QKDApplicationEntry appEntry = kmsA->RegisterApplicationEntry(
            aliceId,
            bobId,
            "etsi014_enc", 
            kmsB->GetAddress(),
            priority,
            200 //expiration time value of the application entry. @toDo: for later usage purge expired apps
        );
        std::string appId = appEntry.GetId().string();
        NS_LOG_FUNCTION(this << appId);
        output.push_back(appId);

        QKDApplicationEntry appEntry2 = kmsB->RegisterApplicationEntry(
            appEntry.GetKeyAssociationId(),
            appEntry.GetId(),
            bobId,
            aliceId,
            "etsi014_enc", 
            kmsA->GetAddress(),
            priority,
            200 //expiration time value of the application entry. @toDo: for later usage purge expired apps
        );
        NS_LOG_FUNCTION(this << "Encryption SAE connections established!");

        alice->SetKsidEncryption(appEntry.GetId());
        bob->SetKsidEncryption(appEntry.GetId());
    } 
    
    if(
        aliceAuthenticationType.Get() == QKDEncryptor::QKDCRYPTO_AUTH_VMAC 
    ){
        QKDApplicationEntry appEntry = kmsA->RegisterApplicationEntry(
            aliceId,
            bobId,
            "etsi014_auth", 
            kmsB->GetAddress(),
            priority,
            200 //expiration time value of the application entry. @toDo: for later usage purge expired apps
        );
        std::string appId = appEntry.GetId().string();
        NS_LOG_FUNCTION(this << appId);
        output.push_back(appId);

        QKDApplicationEntry appEntry2 = kmsB->RegisterApplicationEntry(
            appEntry.GetKeyAssociationId(),
            appEntry.GetId(),
            bobId,
            aliceId,
            "etsi014_auth", 
            kmsA->GetAddress(),
            priority,
            200 //expiration time value of the application entry. @toDo: for later usage purge expired apps
        );
        NS_LOG_FUNCTION(this << "Authentication SAE connections established!");
        
        alice->SetKsidAuthentication(appEntry.GetId());
        bob->SetKsidAuthentication(appEntry.GetId());
    } 
    
    NS_LOG_FUNCTION(this << output.size());

    return output;
}
 
} // namespace ns3