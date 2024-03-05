/*
 * Copyright (c) 2005,2006,2007 INRIA
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
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */

#ifndef UDP_L4_PROTOCOL_H
#define UDP_L4_PROTOCOL_H

#include "ip-l4-protocol.h"

#include "ns3/packet.h"
#include "ns3/ptr.h"

#include <stdint.h>
#include <unordered_map>

namespace ns3
{

class Node;
class Socket;
class Ipv4EndPointDemux;
class Ipv4EndPoint;
class Ipv6EndPointDemux;
class Ipv6EndPoint;
class UdpSocketImpl;
class NetDevice;

/**
 * \ingroup internet
 * \defgroup udp UDP
 *
 * This  is  an  implementation of the User Datagram Protocol described in
 * \RFC{768}.  It implements a connectionless,  unreliable  datagram  packet
 * service.   Packets  may  be reordered or duplicated before they arrive.
 * UDP generates and checks checksums to catch transmission errors.
 *
 * The following options are not presently part of this implementation:
 * UDP_CORK, MSG_DONTROUTE, path MTU discovery control (e.g.
 * IP_MTU_DISCOVER).  MTU handling is also weak in ns-3 for the moment;
 * it is best to send datagrams that do not exceed 1500 byte MTU (e.g.
 * 1472 byte UDP datagrams)
 */

/**
 * \ingroup udp
 * \brief Implementation of the UDP protocol
 */
class UdpL4Protocol : public IpL4Protocol
{
  public:
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    static const uint8_t PROT_NUMBER; //!< protocol number (0x11)

    UdpL4Protocol();
    ~UdpL4Protocol() override;

    // Delete copy constructor and assignment operator to avoid misuse
    UdpL4Protocol(const UdpL4Protocol&) = delete;
    UdpL4Protocol& operator=(const UdpL4Protocol&) = delete;

    /**
     * Set node associated with this stack
     * \param node the node
     */
    void SetNode(Ptr<Node> node);

    int GetProtocolNumber() const override;

    /**
     * \return A smart Socket pointer to a UdpSocket, allocated by this instance
     * of the UDP protocol
     */
    Ptr<Socket> CreateSocket();

    /**
     * \brief Allocate an IPv4 Endpoint
     * \return the Endpoint
     */
    Ipv4EndPoint* Allocate();
    /**
     * \brief Allocate an IPv4 Endpoint
     * \param address address to use
     * \return the Endpoint
     */
    Ipv4EndPoint* Allocate(Ipv4Address address);
    /**
     * \brief Allocate an IPv4 Endpoint
     * \param boundNetDevice Bound NetDevice (if any)
     * \param port port to use
     * \return the Endpoint
     */
    Ipv4EndPoint* Allocate(Ptr<NetDevice> boundNetDevice, uint16_t port);
    /**
     * \brief Allocate an IPv4 Endpoint
     * \param boundNetDevice Bound NetDevice (if any)
     * \param address address to use
     * \param port port to use
     * \return the Endpoint
     */
    Ipv4EndPoint* Allocate(Ptr<NetDevice> boundNetDevice, Ipv4Address address, uint16_t port);
    /**
     * \brief Allocate an IPv4 Endpoint
     * \param boundNetDevice Bound NetDevice (if any)
     * \param localAddress local address to use
     * \param localPort local port to use
     * \param peerAddress remote address to use
     * \param peerPort remote port to use
     * \return the Endpoint
     */
    Ipv4EndPoint* Allocate(Ptr<NetDevice> boundNetDevice,
                           Ipv4Address localAddress,
                           uint16_t localPort,
                           Ipv4Address peerAddress,
                           uint16_t peerPort);

    /**
     * \brief Allocate an IPv6 Endpoint
     * \return the Endpoint
     */
    Ipv6EndPoint* Allocate6();
    /**
     * \brief Allocate an IPv6 Endpoint
     * \param address address to use
     * \return the Endpoint
     */
    Ipv6EndPoint* Allocate6(Ipv6Address address);
    /**
     * \brief Allocate an IPv6 Endpoint
     * \param boundNetDevice Bound NetDevice (if any)
     * \param port port to use
     * \return the Endpoint
     */
    Ipv6EndPoint* Allocate6(Ptr<NetDevice> boundNetDevice, uint16_t port);
    /**
     * \brief Allocate an IPv6 Endpoint
     * \param boundNetDevice Bound NetDevice (if any)
     * \param address address to use
     * \param port port to use
     * \return the Endpoint
     */
    Ipv6EndPoint* Allocate6(Ptr<NetDevice> boundNetDevice, Ipv6Address address, uint16_t port);
    /**
     * \brief Allocate an IPv6 Endpoint
     * \param boundNetDevice Bound NetDevice (if any)
     * \param localAddress local address to use
     * \param localPort local port to use
     * \param peerAddress remote address to use
     * \param peerPort remote port to use
     * \return the Endpoint
     */
    Ipv6EndPoint* Allocate6(Ptr<NetDevice> boundNetDevice,
                            Ipv6Address localAddress,
                            uint16_t localPort,
                            Ipv6Address peerAddress,
                            uint16_t peerPort);

    /**
     * \brief Remove an IPv4 Endpoint.
     * \param endPoint the end point to remove
     */
    void DeAllocate(Ipv4EndPoint* endPoint);
    /**
     * \brief Remove an IPv6 Endpoint.
     * \param endPoint the end point to remove
     */
    void DeAllocate(Ipv6EndPoint* endPoint);

    /**
     * \brief Remove a socket from the internal list
     *
     * \param socket socket to remove
     * \return true if the socket has been removed
     */
    bool RemoveSocket(Ptr<UdpSocketImpl> socket);

    // called by UdpSocket.
    /**
     * \brief Send a packet via UDP (IPv4)
     * \param packet The packet to send
     * \param saddr The source Ipv4Address
     * \param daddr The destination Ipv4Address
     * \param sport The source port number
     * \param dport The destination port number
     */
    void Send(Ptr<Packet> packet,
              Ipv4Address saddr,
              Ipv4Address daddr,
              uint16_t sport,
              uint16_t dport);
    /**
     * \brief Send a packet via UDP (IPv4)
     * \param packet The packet to send
     * \param saddr The source Ipv4Address
     * \param daddr The destination Ipv4Address
     * \param sport The source port number
     * \param dport The destination port number
     * \param route The route
     */
    void Send(Ptr<Packet> packet,
              Ipv4Address saddr,
              Ipv4Address daddr,
              uint16_t sport,
              uint16_t dport,
              Ptr<Ipv4Route> route);
    /**
     * \brief Send a packet via UDP (IPv6)
     * \param packet The packet to send
     * \param saddr The source Ipv4Address
     * \param daddr The destination Ipv4Address
     * \param sport The source port number
     * \param dport The destination port number
     */
    void Send(Ptr<Packet> packet,
              Ipv6Address saddr,
              Ipv6Address daddr,
              uint16_t sport,
              uint16_t dport);
    /**
     * \brief Send a packet via UDP (IPv6)
     * \param packet The packet to send
     * \param saddr The source Ipv4Address
     * \param daddr The destination Ipv4Address
     * \param sport The source port number
     * \param dport The destination port number
     * \param route The route
     */
    void Send(Ptr<Packet> packet,
              Ipv6Address saddr,
              Ipv6Address daddr,
              uint16_t sport,
              uint16_t dport,
              Ptr<Ipv6Route> route);

    // inherited from Ipv4L4Protocol
    IpL4Protocol::RxStatus Receive(Ptr<Packet> p,
                                   const Ipv4Header& header,
                                   Ptr<Ipv4Interface> interface) override;
    IpL4Protocol::RxStatus Receive(Ptr<Packet> p,
                                   const Ipv6Header& header,
                                   Ptr<Ipv6Interface> interface) override;

    void ReceiveIcmp(Ipv4Address icmpSource,
                     uint8_t icmpTtl,
                     uint8_t icmpType,
                     uint8_t icmpCode,
                     uint32_t icmpInfo,
                     Ipv4Address payloadSource,
                     Ipv4Address payloadDestination,
                     const uint8_t payload[8]) override;
    void ReceiveIcmp(Ipv6Address icmpSource,
                     uint8_t icmpTtl,
                     uint8_t icmpType,
                     uint8_t icmpCode,
                     uint32_t icmpInfo,
                     Ipv6Address payloadSource,
                     Ipv6Address payloadDestination,
                     const uint8_t payload[8]) override;

    // From IpL4Protocol
    void SetDownTarget(IpL4Protocol::DownTargetCallback cb) override;
    void SetDownTarget6(IpL4Protocol::DownTargetCallback6 cb) override;
    // From IpL4Protocol
    IpL4Protocol::DownTargetCallback GetDownTarget() const override;
    IpL4Protocol::DownTargetCallback6 GetDownTarget6() const override;

  protected:
    void DoDispose() override;
    /*
     * This function will notify other components connected to the node that a new stack member is
     * now connected This will be used to notify Layer 3 protocol of layer 4 protocol stack to
     * connect them together.
     */
    void NotifyNewAggregate() override;

  private:
    Ptr<Node> m_node;                //!< The node this stack is associated with
    Ipv4EndPointDemux* m_endPoints;  //!< A list of IPv4 end points.
    Ipv6EndPointDemux* m_endPoints6; //!< A list of IPv6 end points.

    std::unordered_map<uint64_t, Ptr<UdpSocketImpl>>
        m_sockets;             //!< Unordered map of socket IDs and corresponding sockets
    uint64_t m_socketIndex{0}; //!< Index of the next socket to be created
    IpL4Protocol::DownTargetCallback m_downTarget;   //!< Callback to send packets over IPv4
    IpL4Protocol::DownTargetCallback6 m_downTarget6; //!< Callback to send packets over IPv6
};

} // namespace ns3

#endif /* UDP_L4_PROTOCOL_H */
