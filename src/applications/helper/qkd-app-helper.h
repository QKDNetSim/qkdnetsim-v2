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

#ifndef QKD_APP_HELPER_H
#define QKD_APP_HELPER_H

#include <stdint.h>
#include <string>
#include "ns3/object-factory.h"
#include "ns3/address.h"
#include "ns3/attribute.h"
#include "ns3/net-device.h"
#include "ns3/net-device-container.h"
#include "ns3/node-container.h"
#include "ns3/application-container.h"
#include "ns3/qkd-postprocessing-application.h"

namespace ns3 {

/**
 * \ingroup qkd
 * \brief A helper to make it easier to instantiate an ns3::QKDAppApplication
 * on a set of nodes.
 */
class QKDAppHelper
{
public:
  /**
   * Create an QKDAppHelper to make it easier to work with QKD Applications (KMS, Post-processing and other)
   *
   * \param protocol the name of the protocol to use to send traffic
   *        by the applications. This string identifies the socket
   *        factory type used to create sockets for the applications.
   *        A typical value would be ns3::UdpSocketFactory.
   * \param address the address of the remote node to send traffic
   *        to.
   */

  /**
   * \brief Constructor.
   */
  QKDAppHelper ();

  /**
   * \brief Constructor.
   * \param protocol The transport layer protocol.
   * \param address The application address.
   */
  QKDAppHelper (std::string protocol, Address address);

  /**
   * \brief Constructor.
   * \param protocol The transport layer protocol.
   * \param addressSrc The source application IP address.
   * \param addressDst The destination application IP address.
   * \param keyRate The secret key rate.
   */
  QKDAppHelper (std::string protocol, Ipv4Address addressSrc, Ipv4Address addressDst, uint32_t keyRate);

  /**
   * Helper function used to set the underlying application attributes, 
   * _not_ the socket attributes.
   *
   * \param name the name of the application attribute to set
   * \param value the value of the application attribute to set
   */
  void SetAttribute (std::string mFactoryName, std::string name, const AttributeValue &value);

  /**
   * Install an ns3::QKDAppApplication on each node of the input container
   * configured with all the attributes set with SetAttribute.
   *
   * \param c NodeContainer of the set of nodes on which an QKDAppApplication
   * will be installed.
   * \returns Container of Ptr to the applications installed.
   */
  //ApplicationContainer Install (NodeContainer c) const;
  void SetSettings ( std::string protocol, Ipv4Address master, Ipv4Address slave, uint32_t keyRate);

  /**
   * Install an ns3::QKDKeyManagmentSystem on the node configured with all the
   * attributes set with SetAttribute.
   *
   * \param node The node on which an QKDAppApplication will be installed. 
   * \param node The IP address on which KMS will listen for requests
   */
  Ptr<QKDKeyManagerSystemApplication> InstallKMS (Ptr<Node> node, Ipv4Address kmsAddress) const;

  /**
   * Install an ns3::QKDKeyManagmentSystem on the node configured with all the
   * attributes set with SetAttribute.
   *
   * \param node The node on which an QKDAppApplication will be installed. 
   * \param node The IP address on which KMS will listen for requests
   * \param node The port number on which KMS will listen for requests
   */
  Ptr<QKDKeyManagerSystemApplication> InstallKMS (Ptr<Node> node, Ipv4Address kmsAddress, uint32_t port) const;

  /**
   * Install an ns3::QKDKeyManagmentSystem on the node configured with all the
   * attributes set with SetAttribute.
   *
   * \param node The node on which an QKDAppApplication will be installed. 
   * \param node The IP address on which SDN will listen for requests
   */
  void InstallSDN (Ptr<Node> node, Ipv4Address sdnAddress) const;

  /**
   * Install an ns3::QKDKeyManagmentSystem on the node configured with all the
   * attributes set with SetAttribute.
   *
   * \param node The node on which an QKDAppApplication will be installed. 
   * \param node The IP address on which SDN will listen for requests
   * \param node The port number on which SDN will listen for requests
   */
  void InstallSDN (Ptr<Node> node, Ipv4Address sdnAddress, uint32_t port) const;

  /**
   * Install an ns3::QKDApp on the node configured with all the
   * attributes set with SetAttribute.
   *
   * \param node The node on which an QKDAppApplication will be installed.
   * \returns Container of Ptr to the applications installed.
   */
  ApplicationContainer InstallQKDApp (Ptr<Node> node) const;
  /**
   * Install an ns3::QKDPostprocessingApplication on the node configured with all the
   * attributes set with SetAttribute.
   *
   * \param nodeName The nodes on which an QKDPostprocessingApplication will be installed.
   * \returns Container of Ptr to the applications installed.
   */
  ApplicationContainer InstallPostProcessing (
    Ptr<Node> node1, 
    Ptr<Node> node2,
    Address     masterAddress, 
    Address     slaveAddress, 
    Address     masterKMSAddress, 
    Address     slaveKMSAddress, 
    uint32_t    keySizeInBits, 
    DataRate    keyRate,
    uint32_t    packetSize,
    DataRate    dataRate
  );

  void ConnectKMSToSDN(Ptr<Node> kmsNode, Ipv4Address sdnAddress, uint32_t port);

private:
  /**
   * Install an ns3::QKDAppApplication on the node configured with all the
   * attributes set with SetAttribute.
   *
   * \param node The node on which an QKDAppApplication will be installed.
   * \returns Ptr to the application installed.
   */ 
  ApplicationContainer InstallPriv (Ptr<NetDevice> net1, Ptr<NetDevice> net2) const;

  ObjectFactory m_factory_sdn_app; //!< Object factory.
  ObjectFactory m_factory_kms_app; //!< Object factory.
  ObjectFactory m_factory_qkd_app; //!< Object factory.
  ObjectFactory m_factory_postprocessing_app; //!< Object factory.
  ObjectFactory m_factory_lr_app;
   
  std::string     m_protocol;

  static uint32_t appCounter;

};

} // namespace ns3
 
#endif /* QKD_APP_HELPER_H */

