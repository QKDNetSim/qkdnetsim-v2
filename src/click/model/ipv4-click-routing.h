/*
 * Copyright (c) 2010 Lalith Suresh
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
 * Authors: Lalith Suresh <suresh.lalith@gmail.com>
 */

#ifndef IPV4_CLICK_ROUTING_H
#define IPV4_CLICK_ROUTING_H

#include "ns3/ipv4-routing-protocol.h"
#include "ns3/ipv4.h"
#include "ns3/object.h"
#include "ns3/packet.h"
#include "ns3/test.h"

#include <map>
#include <string>
#include <sys/time.h>
#include <sys/types.h>

class ClickTrivialTest;
class ClickIfidFromNameTest;
class ClickIpMacAddressFromNameTest;
// These are in #include <click/simclick.h>,
// here we just need a forward declaration.
struct simclick_node;
typedef struct simclick_node simclick_node_t;

namespace ns3
{

/**
 * \defgroup click Click Routing
 * This section documents the API of the ns-3 click module. For a generic functional description,
 * please refer to the ns-3 manual.
 */

class UniformRandomVariable;

/**
 * \ingroup click
 * \brief Class to allow a node to use Click for external routing
 */
class Ipv4ClickRouting : public Ipv4RoutingProtocol
{
  public:
    // Allow test cases to access private members
    friend class ::ClickTrivialTest;
    friend class ::ClickIfidFromNameTest;
    friend class ::ClickIpMacAddressFromNameTest;

    /**
     * Get type ID.
     *
     * \return TypeId.
     */
    static TypeId GetTypeId();

    /** Constructor. */
    Ipv4ClickRouting();
    ~Ipv4ClickRouting() override;

    /**
     * Get the uniform random variable.
     *
     * \return Uniform random variable.
     */
    Ptr<UniformRandomVariable> GetRandomVariable();

  protected:
    void DoInitialize() override;

  public:
    void DoDispose() override;

    /**
     * \brief Click configuration file to be used by the node's Click Instance.
     * \param clickfile name of .click configuration file
     */
    void SetClickFile(std::string clickfile);

    /**
     * \brief Click defines to be used by the node's Click Instance.
     * \param defines mapping of defines for .click configuration file parsing
     */
    void SetDefines(std::map<std::string, std::string> defines);

    /**
     * \brief Name of the node as to be used by Click. Required for Click Dumps.
     * \param name Name to be assigned to the node.
     */
    void SetNodeName(std::string name);

    /**
     * \brief Name of the routing table element being used by Click. Required for RouteOutput ()
     * \param name Name of the routing table element.
     */
    void SetClickRoutingTableElement(std::string name);

    /**
     * \brief Read Handler interface for a node's Click Elements.
     *        Allows a user to read state information of a Click element.
     * \param elementName name of the Click element.
     * \param handlerName name of the handler to be read.
     * \return String read.
     */
    std::string ReadHandler(std::string elementName, std::string handlerName);

    /**
     * \brief Write Handler interface for a node's Click Elements.
     *        Allows a user to modify state information of a Click element.
     * \param elementName name of the Click element.
     * \param handlerName name of the handler to be read.
     * \param writeString string to be written using the write handler.
     * \return Write operation status.
     */
    int WriteHandler(std::string elementName, std::string handlerName, std::string writeString);

    /**
     * \brief Sets an interface to run on promiscuous mode.
     * \param ifid Interface ID.
     */
    void SetPromisc(int ifid);

  private:
    /// Pointer to the simclick node
    simclick_node_t* m_simNode;

    /**
     * \brief Provide a mapping between the node reference used by Click and the corresponding
     * Ipv4ClickRouting instance.
     */
    static std::map<simclick_node_t*, Ptr<Ipv4ClickRouting>> m_clickInstanceFromSimNode;

  public:
    /**
     * \brief Allows the Click service methods, which reside outside Ipv4ClickRouting, to get the
     * required Ipv4ClickRouting instances.
     * \param simnode The Click simclick_node_t instance for which the Ipv4ClickRouting instance is
     * required
     * \return A Ptr to the required Ipv4ClickRouting instance
     */
    static Ptr<Ipv4ClickRouting> GetClickInstanceFromSimNode(simclick_node_t* simnode);

  public:
    /**
     * \brief Provides for SIMCLICK_GET_DEFINES
     * \return The defines mapping for .click configuration file parsing
     */
    std::map<std::string, std::string> GetDefines();

    /**
     * \brief Provides for SIMCLICK_IFID_FROM_NAME
     * \param ifname The name of the interface
     * \return The interface ID which corresponds to ifname
     */
    int GetInterfaceId(const char* ifname);

    /**
     * \brief Provides for SIMCLICK_IPADDR_FROM_NAME
     * \param ifid The interface ID for which the IP Address is required
     * \return The IP Address of the interface in string format
     */
    std::string GetIpAddressFromInterfaceId(int ifid);

    /**
     * \brief Provides for SIMCLICK_IPPREFIX_FROM_NAME
     * \param ifid The interface ID for which the IP Prefix is required
     * \return The IP Prefix of the interface in string format
     */
    std::string GetIpPrefixFromInterfaceId(int ifid);

    /**
     * \brief Provides for SIMCLICK_MACADDR_FROM_NAME
     * \param ifid The interface ID for which the MAC Address is required
     * \return The MAC Address of the interface in string format
     */
    std::string GetMacAddressFromInterfaceId(int ifid);

    /**
     * \brief Provides for SIMCLICK_GET_NODE_NAME
     * \return The Node name
     */
    std::string GetNodeName();

    /**
     * \brief Provides for SIMCLICK_IF_READY
     * \param ifid Interface ID
     * \return Returns 1, if the interface is ready, -1 if ifid is invalid
     */
    bool IsInterfaceReady(int ifid);

    /**
     * \brief Set the Ipv4 instance to be used
     * \param ipv4 The Ipv4 instance
     */
    void SetIpv4(Ptr<Ipv4> ipv4) override;

  private:
    /**
     * \brief Used internally in DoInitialize () to Add a mapping to m_clickInstanceFromSimNode
     * mapping
     */
    void AddSimNodeToClickMapping();

    /**
     * \brief Get current simulation time as a timeval.
     * \return Current simulation time as a timeval.
     */
    struct timeval GetTimevalFromNow() const;

    /**
     * \brief This method has to be scheduled every time Click calls SIMCLICK_SCHEDULE
     */
    void RunClickEvent();

  public:
    /**
     * \brief Schedules simclick_click_run to run at the given time
     * \param when Time at which the simclick_click_run instance should be run
     */
    void HandleScheduleFromClick(const struct timeval* when);

    /**
     * \brief Receives a packet from Click
     * \param ifid The interface ID from which the packet is arriving
     * \param type The type of packet as defined in click/simclick.h
     * \param data The contents of the packet
     * \param len The length of the packet
     */
    void HandlePacketFromClick(int ifid, int type, const unsigned char* data, int len);

    /**
     * \brief Sends a packet to Click
     * \param ifid The interface ID from which the packet is arriving
     * \param type The type of packet as defined in click/simclick.h
     * \param data The contents of the packet
     * \param len The length of the packet
     */
    void SendPacketToClick(int ifid, int type, const unsigned char* data, int len);

    /**
     * \brief Allow a higher layer to send data through Click. (From Ipv4ExtRouting)
     * \param p The packet to be sent
     * \param src The source IP Address
     * \param dest The destination IP Address
     */
    void Send(Ptr<Packet> p, Ipv4Address src, Ipv4Address dest);

    /**
     * \brief Allow a lower layer to send data to Click. (From Ipv4ExtRouting)
     * \param p The packet to be sent
     * \param receiverAddr Receiving interface's address
     * \param dest The Destination MAC address
     */
    void Receive(Ptr<Packet> p, Mac48Address receiverAddr, Mac48Address dest);

    // From Ipv4RoutingProtocol
    Ptr<Ipv4Route> RouteOutput(Ptr<Packet> p,
                               const Ipv4Header& header,
                               Ptr<NetDevice> oif,
                               Socket::SocketErrno& sockerr) override;
    bool RouteInput(Ptr<const Packet> p,
                    const Ipv4Header& header,
                    Ptr<const NetDevice> idev,
                    const UnicastForwardCallback& ucb,
                    const MulticastForwardCallback& mcb,
                    const LocalDeliverCallback& lcb,
                    const ErrorCallback& ecb) override;
    void PrintRoutingTable(Ptr<OutputStreamWrapper> stream,
                           Time::Unit unit = Time::S) const override;
    void NotifyInterfaceUp(uint32_t interface) override;
    void NotifyInterfaceDown(uint32_t interface) override;
    void NotifyAddAddress(uint32_t interface, Ipv4InterfaceAddress address) override;
    void NotifyRemoveAddress(uint32_t interface, Ipv4InterfaceAddress address) override;

  private:
    std::string m_clickFile;                      //!< Name of .click configuration file
    std::map<std::string, std::string> m_defines; //!< Defines for .click configuration file parsing
    std::string m_nodeName;                       //!< Name of the node
    std::string m_clickRoutingTableElement;       //!< Name of the routing table element

    bool m_clickInitialised; //!< Whether click has been initialized
    bool m_nonDefaultName;   //!< Whether a non-default name has been set

    Ptr<Ipv4> m_ipv4;                    //!< Pointer to the IPv4 object
    Ptr<UniformRandomVariable> m_random; //!< Uniform random variable
};

} // namespace ns3

#endif /* IPV4_CLICK_ROUTING_H */
