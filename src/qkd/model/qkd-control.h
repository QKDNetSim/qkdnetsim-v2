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

#ifndef QKDCONTROL_H
#define QKDCONTROL_H

#include <queue>
#include <vector>
#include <map>
#include <string>

#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/ipv4-header.h" 
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/event-id.h"
#include "ns3/node.h" 
#include "ns3/ptr.h"
#include "ns3/vector.h"

#include "ns3/names.h"
#include "ns3/tag.h"
#include "ns3/net-device.h"
#include "ns3/traffic-control-layer.h"

#include "ns3/qkd-encryptor.h"
#include "ns3/qkd-buffer.h"  

#include "ns3/object-factory.h"
#include "ns3/core-module.h"  
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/ipv4-interface-address.h"

#include "ns3/applications-module.h"
#include "ns3/qkd-key-manager-system-application.h"

namespace ns3 {

    class Node; 
    /**
     * \ingroup qkd
     * \class QKDControl
     *
     * \brief QKD control is a network component with the knowledge of the
     * network status. It should perform network management through distributed
     * protocols or centralized entities. 
     *
     * \note In the current version of QKDNetSim, QKDControl can be installed 
     * on an independent node without a direct QKD connection. It is in charge 
     * of establishing QKD links, and it contains a list of QKD links with
     * associated QKD buffers implemented in a QKD network.  
     */
    class QKDControl : public Object 
    {
    public:

        /**
         * Description of a QKD link.
         */
        struct QKDLink
        {
            Ptr<Node>               alice;
            Ptr<Node>               bob;
            Ptr<QKDBuffer>          qkdBufferAlice;
            Ptr<QKDBuffer>          qkdBufferBob;
            double                  publicChannelMetric;
            double                  quantumChannelMetric;
            std::string             keyAssociationId;
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
        * \brief Constructor.
        */
        QKDControl ();

        /**
        * \brief Destructor.
        */
        virtual ~QKDControl ();
            
        /**
        * \brief Destroy a QKDControl object.
        *
        * This is the pre-destructor function of the QKDControl.
        */
        void Dispose(void);

        /**
         * \brief Get the number of QKDBuffers associated to this QKDControl.
         * \returns The number of QKDBuffers.
         */
        uint32_t GetNQKDBuffers (void) const;
         
        /**
        *   \brief Establish new QKD link.
        * 
        *   This function is called from qkd/helper/qkd-helper.cc 
        *   \param     Alice The source node.
        *   \param     Bob The destination (detector) node.
        *   \param     AliceKMS The source key management node.
        *   \param     BobKMS The destination key management node.
        *   \param     Mmin The lower buffer threshold value.
        *   \param     Mthr The buffer threshold value.
        *   \param     Mmax The buffer capacity. 
        *   \param     Mcurrent The current amount of key material in the buffer.
        *   \param     isMaster Is this a master node? 
        *   \return    The QKDLink object.
        */
        struct QKDControl::QKDLink AddNewLink (  
            Ptr<Node>               Alice,
            Ptr<Node>               Bob,  
            Ptr<Node>               AliceKMS,
            Ptr<Node>               BobKMS,  
            uint32_t                Mmin, 
            uint32_t                Mthr, 
            uint32_t                Mmax, 
            uint32_t                Mcurrent,
            bool                    isMaster,
            bool                    useRealStorages
        );  

        /**
        *   \brief Record details about the new QKD link.
        *   
        *   This function is called from qkd/helper/qkd-helper.cc 
        *   
        *   \param The QKDLink details.
        */
        void AddLinkRecord (struct QKDControl::QKDLink); 

        /**
        *   \brief Get the QKDBuffer for the given destination node.
        *   \param  The destination node.
        *   \return The QKDBuffer.
        */
        Ptr<QKDBuffer> GetBufferByDestinationNode (Ptr<Node>);

        /**
         * \brief Get the QKDBuffer with given position.
         * \param bufferPosition The buffer position within m_buffers list.
         * \return The QKDBuffer.
         */
        Ptr<QKDBuffer> GetBufferByPosition (const uint32_t& bufferPosition);

        /**
         * \brief Get the controller node.
         * \return The node.
         */
        Ptr<Node> GetNode();
        
        /**
         * \brief Set the controller node.
         * \param The node.
         */
        void SetNode (Ptr<Node>);

        /**
         * \brief Register the QKD application pair (that implements ETSI QKD 004 API) on the site.
         * \param alice The sender application.
         * \param bob The receiver application.
         * \param kmsA The key manager system at the sender side.
         * \param kmsB The key manager system at the receiver side.
         */
        std::vector<std::string> RegisterQKDApplications (
            Ptr<QKDApp004> alice, 
            Ptr<QKDApp004> bob,
            Ptr<QKDKeyManagerSystemApplication> kmsA,
            Ptr<QKDKeyManagerSystemApplication> kmsB
        );
        
        /**
         * \brief Register the QKD application pair (that implements ETSI QKD 014 API) on the site.
         * \param alice The sender application.
         * \param bob The receiver application.
         * \param kmsA The key manager system at the sender side.
         * \param kmsB The key manager system at the receiver side.
         */ 
        std::vector<std::string> RegisterQKDApplications (
            Ptr<QKDApp014> alice, 
            Ptr<QKDApp014> bob,
            Ptr<QKDKeyManagerSystemApplication> kmsA,
            Ptr<QKDKeyManagerSystemApplication> kmsB
        );

    protected: 
        /**
        * The dispose method. Subclasses must override this method
        * and must chain up to it by calling Node::DoDispose at the
        * end of their own DoDispose method.
        */
        virtual void DoDispose (void);

        /**
        *   \brief Initialization function.
        */
        virtual void DoInitialize (void);

    private:  

        Ptr<Node> m_node; //!< The controller node.

        std::vector<Ptr<QKDBuffer> > m_qkdbuffers; //!< The list of associated QKDBuffers.
        
        std::map<uint32_t, QKDLink> m_destinations; //<! The map of QKD destinations including buffers.

    }; 
}  
// namespace ns3

#endif /* QKDCONTROL_H */
