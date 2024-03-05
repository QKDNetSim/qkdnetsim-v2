/*
 * Copyright (c) 2014 Universita' di Firenze, Italy
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
 * Author: Tommaso Pecorella <tommaso.pecorella@unifi.it>
 */

#include "ripng-helper.h"

#include "ns3/ipv6-list-routing.h"
#include "ns3/node-list.h"
#include "ns3/node.h"
#include "ns3/ripng.h"

#include <map>

namespace ns3
{

RipNgHelper::RipNgHelper()
{
    m_factory.SetTypeId("ns3::RipNg");
}

RipNgHelper::RipNgHelper(const RipNgHelper& o)
    : m_factory(o.m_factory)
{
    m_interfaceExclusions = o.m_interfaceExclusions;
    m_interfaceMetrics = o.m_interfaceMetrics;
}

RipNgHelper::~RipNgHelper()
{
    m_interfaceExclusions.clear();
    m_interfaceMetrics.clear();
}

RipNgHelper*
RipNgHelper::Copy() const
{
    return new RipNgHelper(*this);
}

Ptr<Ipv6RoutingProtocol>
RipNgHelper::Create(Ptr<Node> node) const
{
    Ptr<RipNg> ripng = m_factory.Create<RipNg>();

    auto it = m_interfaceExclusions.find(node);

    if (it != m_interfaceExclusions.end())
    {
        ripng->SetInterfaceExclusions(it->second);
    }

    auto iter = m_interfaceMetrics.find(node);

    if (iter != m_interfaceMetrics.end())
    {
        for (auto subiter = iter->second.begin(); subiter != iter->second.end(); subiter++)
        {
            ripng->SetInterfaceMetric(subiter->first, subiter->second);
        }
    }

    node->AggregateObject(ripng);
    return ripng;
}

void
RipNgHelper::Set(std::string name, const AttributeValue& value)
{
    m_factory.Set(name, value);
}

int64_t
RipNgHelper::AssignStreams(NodeContainer c, int64_t stream)
{
    int64_t currentStream = stream;
    Ptr<Node> node;
    for (auto i = c.Begin(); i != c.End(); ++i)
    {
        node = (*i);
        Ptr<Ipv6> ipv6 = node->GetObject<Ipv6>();
        NS_ASSERT_MSG(ipv6, "Ipv6 not installed on node");
        Ptr<Ipv6RoutingProtocol> proto = ipv6->GetRoutingProtocol();
        NS_ASSERT_MSG(proto, "Ipv6 routing not installed on node");
        Ptr<RipNg> ripng = DynamicCast<RipNg>(proto);
        if (ripng)
        {
            currentStream += ripng->AssignStreams(currentStream);
            continue;
        }
        // RIPng may also be in a list
        Ptr<Ipv6ListRouting> list = DynamicCast<Ipv6ListRouting>(proto);
        if (list)
        {
            int16_t priority;
            Ptr<Ipv6RoutingProtocol> listProto;
            Ptr<RipNg> listRipng;
            for (uint32_t i = 0; i < list->GetNRoutingProtocols(); i++)
            {
                listProto = list->GetRoutingProtocol(i, priority);
                listRipng = DynamicCast<RipNg>(listProto);
                if (listRipng)
                {
                    currentStream += listRipng->AssignStreams(currentStream);
                    break;
                }
            }
        }
    }
    return (currentStream - stream);
}

void
RipNgHelper::SetDefaultRouter(Ptr<Node> node, Ipv6Address nextHop, uint32_t interface)
{
    Ptr<Ipv6> ipv6 = node->GetObject<Ipv6>();
    NS_ASSERT_MSG(ipv6, "Ipv6 not installed on node");
    Ptr<Ipv6RoutingProtocol> proto = ipv6->GetRoutingProtocol();
    NS_ASSERT_MSG(proto, "Ipv6 routing not installed on node");
    Ptr<RipNg> ripng = DynamicCast<RipNg>(proto);
    if (ripng)
    {
        ripng->AddDefaultRouteTo(nextHop, interface);
    }
    // RIPng may also be in a list
    Ptr<Ipv6ListRouting> list = DynamicCast<Ipv6ListRouting>(proto);
    if (list)
    {
        int16_t priority;
        Ptr<Ipv6RoutingProtocol> listProto;
        Ptr<RipNg> listRipng;
        for (uint32_t i = 0; i < list->GetNRoutingProtocols(); i++)
        {
            listProto = list->GetRoutingProtocol(i, priority);
            listRipng = DynamicCast<RipNg>(listProto);
            if (listRipng)
            {
                listRipng->AddDefaultRouteTo(nextHop, interface);
                break;
            }
        }
    }
}

void
RipNgHelper::ExcludeInterface(Ptr<Node> node, uint32_t interface)
{
    auto it = m_interfaceExclusions.find(node);

    if (it == m_interfaceExclusions.end())
    {
        std::set<uint32_t> interfaces;
        interfaces.insert(interface);

        m_interfaceExclusions.insert(std::make_pair(node, interfaces));
    }
    else
    {
        it->second.insert(interface);
    }
}

void
RipNgHelper::SetInterfaceMetric(Ptr<Node> node, uint32_t interface, uint8_t metric)
{
    m_interfaceMetrics[node][interface] = metric;
}

} // namespace ns3
