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

#ifndef QKD_HELPER_H
#define QKD_HELPER_H

#include <string>

#include "ns3/object-factory.h"
#include "ns3/net-device-container.h"
#include "ns3/node-container.h" 
#include "ns3/trace-helper.h"
#include "ns3/ipv4-interface-address.h"
#include "ns3/core-module.h"  
#include "ns3/network-module.h"
#include "ns3/internet-module.h"  

#include "ns3/qkd-encryptor.h"
#include "ns3/qkd-encryptor-container.h"

#include "ns3/qkd-control.h"
#include "ns3/qkd-control-container.h"

#include "ns3/qkd-graph-manager.h" 

namespace ns3 {
 
class NetDevice;
class Node;

/**
 * \ingroup qkd
 * \class QKDLinkHelper
 * \brief Build a set of QKDNetDevice objects such as QKD buffers
 * QKD encryptors and QKD graphs.
 *
 */
class QKDLinkHelper 
{
public:

    /**
    * \brief Constructor.
    * 
    * Create a QKDLinkHelper to make life easier when creating point to
    * point networks.
    */
    QKDLinkHelper ();

    /**
     * \brief Destructor.
     */
    virtual ~QKDLinkHelper () {}

    /**
     * \brief Add a graph.
     * \param src The source node.
     * \param dst The destination node.
     */
	void AddGraph(Ptr<Node> src, Ptr<Node> dst);

    /**
     * \brief Add a graph.
     * \param src The source node.
     * \param dst The destination node.
     * \param graphName The graph name.
     */
	void AddGraph(Ptr<Node> src, Ptr<Node> dst, std::string graphName);
    
    /**
     * \brief Add a graph.
     * \param src The source node.
     * \param dst The destination node.
     * \param graphName The graph name.
     * \param graphType The graph type.
     */
    void AddGraph(Ptr<Node> src, Ptr<Node> dst, std::string graphName, std::string graphType);

    /**
     * \brief Print graphs.
     */
    void PrintGraphs(); 
    
    /**
     * \brief Install QKD encryptor on a node.
     * \param node The node.
     * \return The QKD encryptor.
     */
    Ptr<QKDEncryptor> InstallQKDEncryptor (Ptr<Node> node);
    
    /**
     * \brief Install QKD encryptor on nodes within a given container.
     * \param n The node container.
     * \return The container of the installed QKD encryptors.
     */
    QKDEncryptorContainer InstallQKDEncryptor (NodeContainer& n);

    /**
     * \brief Install the QKD control on a node.
     * \param node The node.
     */ 
    Ptr<QKDControl> InstallQKDControl (Ptr<Node> node); 

    /**
     * \brief Install the QKD controll on nodes within a given container.
     * \param n The node container.
     * \return The container of the installed QKD controls.
     */ 
    QKDControlContainer InstallQKDControl (NodeContainer& n);  
    
    /**
     * \brief Create a QKD link.
     * \param control The QKD control.
     * \param alice The source node.
     * \param bob The destination node.
     * \param aliceKMS The source KMS node.
     * \param bobKMS The destination KMS node.
     * \param Mmin The lower threshold value.
     * \param Mthr The threshold value,
     * \param Mmax The maximum capacity.
     * \param Mcurrent The current amount of key material in bits.
     */
    std::string CreateQKDLink (
        Ptr<QKDControl>         control,
        Ptr<Node>               alice,
        Ptr<Node>               bob, 
        Ptr<Node>               aliceKMS,           
        Ptr<Node>               bobKMS,   
        uint32_t                Mmin,
        uint32_t                Mthr,
        uint32_t                Mmax,
        uint32_t                Mcurrent
    );

    bool     m_useRealStorages; //!< Wheater to use real key file storage (still in development).

    /**
    * \brief Create an object from its TypeId and aggregates it to the node.
    * \param node The node.
    * \param The object TypeId.
    */
    static void CreateAndAggregateObjectFromTypeId (Ptr<Node> node, const std::string typeId);

private:

    ObjectFactory m_qkdbufferFactory;        //!< Device Factory

}; 
} // namespace ns3

#endif /* QKD_HELPER_H */
