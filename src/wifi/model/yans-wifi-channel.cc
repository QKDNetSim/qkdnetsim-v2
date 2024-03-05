/*
 * Copyright (c) 2006,2007 INRIA
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
 * Author: Mathieu Lacage, <mathieu.lacage@sophia.inria.fr>
 */

#include "yans-wifi-channel.h"

#include "wifi-net-device.h"
#include "wifi-ppdu.h"
#include "wifi-psdu.h"
#include "wifi-utils.h"
#include "yans-wifi-phy.h"

#include "ns3/log.h"
#include "ns3/mobility-model.h"
#include "ns3/node.h"
#include "ns3/pointer.h"
#include "ns3/propagation-delay-model.h"
#include "ns3/propagation-loss-model.h"
#include "ns3/simulator.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("YansWifiChannel");

NS_OBJECT_ENSURE_REGISTERED(YansWifiChannel);

TypeId
YansWifiChannel::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::YansWifiChannel")
            .SetParent<Channel>()
            .SetGroupName("Wifi")
            .AddConstructor<YansWifiChannel>()
            .AddAttribute("PropagationLossModel",
                          "A pointer to the propagation loss model attached to this channel.",
                          PointerValue(),
                          MakePointerAccessor(&YansWifiChannel::m_loss),
                          MakePointerChecker<PropagationLossModel>())
            .AddAttribute("PropagationDelayModel",
                          "A pointer to the propagation delay model attached to this channel.",
                          PointerValue(),
                          MakePointerAccessor(&YansWifiChannel::m_delay),
                          MakePointerChecker<PropagationDelayModel>());
    return tid;
}

YansWifiChannel::YansWifiChannel()
{
    NS_LOG_FUNCTION(this);
}

YansWifiChannel::~YansWifiChannel()
{
    NS_LOG_FUNCTION(this);
    m_phyList.clear();
}

void
YansWifiChannel::SetPropagationLossModel(const Ptr<PropagationLossModel> loss)
{
    NS_LOG_FUNCTION(this << loss);
    m_loss = loss;
}

void
YansWifiChannel::SetPropagationDelayModel(const Ptr<PropagationDelayModel> delay)
{
    NS_LOG_FUNCTION(this << delay);
    m_delay = delay;
}

void
YansWifiChannel::Send(Ptr<YansWifiPhy> sender, Ptr<const WifiPpdu> ppdu, double txPowerDbm) const
{
    NS_LOG_FUNCTION(this << sender << ppdu << txPowerDbm);
    Ptr<MobilityModel> senderMobility = sender->GetMobility();
    NS_ASSERT(senderMobility);
    for (auto i = m_phyList.begin(); i != m_phyList.end(); i++)
    {
        if (sender != (*i))
        {
            // For now don't account for inter channel interference nor channel bonding
            if ((*i)->GetChannelNumber() != sender->GetChannelNumber())
            {
                continue;
            }

            Ptr<MobilityModel> receiverMobility = (*i)->GetMobility()->GetObject<MobilityModel>();
            Time delay = m_delay->GetDelay(senderMobility, receiverMobility);
            double rxPowerDbm = m_loss->CalcRxPower(txPowerDbm, senderMobility, receiverMobility);
            NS_LOG_DEBUG("propagation: txPower="
                         << txPowerDbm << "dbm, rxPower=" << rxPowerDbm << "dbm, "
                         << "distance=" << senderMobility->GetDistanceFrom(receiverMobility)
                         << "m, delay=" << delay);
            Ptr<NetDevice> dstNetDevice = (*i)->GetDevice();
            uint32_t dstNode;
            if (!dstNetDevice)
            {
                dstNode = 0xffffffff;
            }
            else
            {
                dstNode = dstNetDevice->GetNode()->GetId();
            }

            Simulator::ScheduleWithContext(dstNode,
                                           delay,
                                           &YansWifiChannel::Receive,
                                           (*i),
                                           ppdu,
                                           rxPowerDbm);
        }
    }
}

void
YansWifiChannel::Receive(Ptr<YansWifiPhy> phy, Ptr<const WifiPpdu> ppdu, double rxPowerDbm)
{
    NS_LOG_FUNCTION(phy << ppdu << rxPowerDbm);
    // Do no further processing if signal is too weak
    // Current implementation assumes constant RX power over the PPDU duration
    // Compare received TX power per MHz to normalized RX sensitivity
    uint16_t txWidth = ppdu->GetTxChannelWidth();
    if ((rxPowerDbm + phy->GetRxGain()) < phy->GetRxSensitivity() + RatioToDb(txWidth / 20.0))
    {
        NS_LOG_INFO("Received signal too weak to process: " << rxPowerDbm << " dBm");
        return;
    }
    RxPowerWattPerChannelBand rxPowerW;
    rxPowerW.insert(
        {{{0, 0}, {0, 0}}, (DbmToW(rxPowerDbm + phy->GetRxGain()))}); // dummy band for YANS
    phy->StartReceivePreamble(ppdu, rxPowerW, ppdu->GetTxDuration());
}

std::size_t
YansWifiChannel::GetNDevices() const
{
    return m_phyList.size();
}

Ptr<NetDevice>
YansWifiChannel::GetDevice(std::size_t i) const
{
    return m_phyList[i]->GetDevice();
}

void
YansWifiChannel::Add(Ptr<YansWifiPhy> phy)
{
    NS_LOG_FUNCTION(this << phy);
    m_phyList.push_back(phy);
}

int64_t
YansWifiChannel::AssignStreams(int64_t stream)
{
    NS_LOG_FUNCTION(this << stream);
    int64_t currentStream = stream;
    currentStream += m_loss->AssignStreams(stream);
    return (currentStream - stream);
}

} // namespace ns3
