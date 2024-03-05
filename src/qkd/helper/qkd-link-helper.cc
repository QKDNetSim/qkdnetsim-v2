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

#include "ns3/abort.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/queue.h"
#include "ns3/config.h"
#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/names.h"

#include "ns3/internet-module.h"
#include "ns3/random-variable-stream.h"
#include "ns3/trace-helper.h" 
#include "ns3/traffic-control-module.h" 

#include "qkd-link-helper.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDLinkHelper");

QKDLinkHelper::QKDLinkHelper ()
{  
    m_useRealStorages = false;
    m_qkdbufferFactory.SetTypeId ("ns3::QKDBuffer"); 
}  
 
/**
*   \brief ADD QKDGraph
*   @param  Ptr<Node>       src
*   @param  Ptr<Node>       dst 
*/
void 
QKDLinkHelper::AddGraph(
    Ptr<Node> src, 
    Ptr<Node> dst
) {
    AddGraph(src, dst, "", "png");
}

/**
*   \brief ADD QKDGraph
*   @param  Ptr<Node>       src
*   @param  Ptr<Node>       dst 
*   @param  std::string     graphName    
*/
void 
QKDLinkHelper::AddGraph(
    Ptr<Node> src, 
    Ptr<Node> dst, 
    std::string graphName
){
    AddGraph(src, dst, graphName, "png");
}
/**
*   \brief ADD QKDGraph
*   @param  Ptr<QKDControl> QKDControl
*   @param  Ptr<Node>       src
*   @param  Ptr<Node>       dst 
*   @param  std::string     graphName    
*   @param  std::string     graphType    
*/
void 
QKDLinkHelper::AddGraph(
    Ptr<Node> src, 
    Ptr<Node> dst, 
    std::string graphName, 
    std::string graphType
) {   

    NS_ASSERT (src);
    NS_ASSERT (dst);
 
    Ptr<QKDControl> c = src->GetObject<QKDControl> ();
    NS_ASSERT (c);

    Ptr<QKDBuffer> buffer = c->GetBufferByDestinationNode ( dst );
    NS_ASSERT (buffer);

    NS_LOG_FUNCTION(this << buffer << buffer->FetchState() << c->GetNQKDBuffers() << buffer->GetIndex() );

    QKDGraphManager *QKDGraphManager = QKDGraphManager::getInstance();
    QKDGraphManager->AddQKDBuffer(c, src, dst, buffer->GetIndex(), graphName, graphType);
}

/**
*   \brief Print QKDGraphs
*/
void 
QKDLinkHelper::PrintGraphs()
{    
    QKDGraphManager *QKDGraphManager = QKDGraphManager::getInstance();
    QKDGraphManager->PrintGraphs();
}

/**
*   \brief Install QKDControl on the node
*   @param  NodeContainer&  n
*/ 
Ptr<QKDControl>
QKDLinkHelper::InstallQKDControl (Ptr<Node> n)
{   
    Ptr<QKDControl> control = n->GetObject<QKDControl> ();
    if(!control) {
        ObjectFactory factory;     
        factory.SetTypeId ("ns3::QKDControl");
        control = factory.Create <QKDControl> ();
        control->SetNode(n);
        n->AggregateObject (control);
    }
    return control;
}

/**
*   \brief Install QKDControl on the node
*   @param  NodeContainer&  n
*/ 
QKDControlContainer
QKDLinkHelper::InstallQKDControl (NodeContainer& n)
{    
    QKDControlContainer container;
    for(uint16_t i=0; i < n.GetN(); i++)
    {
        Ptr<QKDControl> control = InstallQKDControl( n.Get(i) );
        container.Add( control, i );
    }
    return container;
}

/**
*   \brief Install QKDEncryptor on the node
*   @param  NodeContainer&  n
*/ 
Ptr<QKDEncryptor>
QKDLinkHelper::InstallQKDEncryptor (Ptr<Node> n)
{   
    ObjectFactory factory;     
    factory.SetTypeId ("ns3::QKDEncryptor");
    Ptr<QKDEncryptor> ecrypto = factory.Create <QKDEncryptor> ();
    n->AggregateObject (ecrypto);    
    return ecrypto;
}

/**
*   \brief Install QKDEncryptor on the node
*   @param  NodeContainer&  n
*/ 
QKDEncryptorContainer
QKDLinkHelper::InstallQKDEncryptor (NodeContainer& n)
{           
    QKDEncryptorContainer container;
    for(uint16_t i=0; i < n.GetN(); i++)
    {
        Ptr<QKDEncryptor> ecrypto = InstallQKDEncryptor( n.Get(i) );
        container.Add( ecrypto, i );
    }
    return container;
}

/**
*   \brief Help function used to aggregate protocols to the node such as virtual-tcp, virtual-udp, virtual-ipv4-l3
*   @param  Ptr<Node>           node
*   @param  const std::string   typeID
*/
void
QKDLinkHelper::CreateAndAggregateObjectFromTypeId (Ptr<Node> node, const std::string typeId)
{
    ObjectFactory factory;
    factory.SetTypeId (typeId);
    Ptr<Object> protocol = factory.Create <Object> ();
    node->AggregateObject (protocol);
}

/**
*   \brief Create and setup QKD link between two nodes. It notifies LKMS (Local QKD Manager about the connection).
* 
*   QKDControl passed as parameter is the central control entity which is not currently used.
*
*   @param  Ptr<QKDControl>         QKDControl
*   @param  Ptr<Node>               alice
*   @param  Ptr<Node>               alice 
*   @param  uint32_t                Mmin
*   @param  uint32_t                Mthr
*   @param  uint32_t                Mmmax
*   @param  uint32_t                Mcurrent 
*   
*   
*/
std::string
QKDLinkHelper::CreateQKDLink (
    Ptr<QKDControl>         centralControler, //not currently used
    Ptr<Node>               alice,           
    Ptr<Node>               bob,  
    Ptr<Node>               aliceKMS,           
    Ptr<Node>               bobKMS,       
    uint32_t                Mmin,           //Buffer details
    uint32_t                Mthr,           //Buffer details
    uint32_t                Mmax,           //Buffer details
    uint32_t                Mcurrent        //Buffer details
)
{
    NS_LOG_FUNCTION( this << alice->GetId() << bob->GetId() );

    /////////////////////////////////
    //          NODE A
    /////////////////////////////////
    Ptr<QKDControl> controlAlice = alice->GetObject<QKDControl> ();
    if(!controlAlice) controlAlice = InstallQKDControl(alice);
      
    /////////////////////////////////
    //          NODE B
    /////////////////////////////////
    Ptr<QKDControl> controlBob = bob->GetObject<QKDControl> ();
    if(!controlBob) controlBob = InstallQKDControl(bob);
  
    struct QKDControl::QKDLink linkDetails = controlAlice->AddNewLink (
        alice, 
        bob,
        aliceKMS,
        bobKMS,
        Mmin,
        Mthr,
        Mmax,
        Mcurrent,
        true,
        m_useRealStorages
    );

    controlBob->AddLinkRecord(linkDetails);
    return linkDetails.keyAssociationId;

}
 
} // namespace ns3