/*
 * Copyright (c) 2009 IITP RAS
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
 * Author: Pavel Boyko <boyko@iitp.ru>
 */

#include "mesh-wifi-beacon.h"

#include "ns3/nstime.h"
#include "ns3/wifi-mac-header.h"

namespace ns3
{

MeshWifiBeacon::MeshWifiBeacon(Ssid ssid, AllSupportedRates rates, uint64_t us)
{
    m_header.Get<Ssid>() = ssid;
    m_header.Get<SupportedRates>() = rates.rates;
    m_header.Get<ExtendedSupportedRatesIE>() = rates.extendedRates;
    m_header.SetBeaconIntervalUs(us);
}

void
MeshWifiBeacon::AddInformationElement(Ptr<WifiInformationElement> ie)
{
    m_elements.AddInformationElement(ie);
}

Time
MeshWifiBeacon::GetBeaconInterval() const
{
    return MicroSeconds(m_header.GetBeaconIntervalUs());
}

Ptr<Packet>
MeshWifiBeacon::CreatePacket()
{
    Ptr<Packet> packet = Create<Packet>();
    packet->AddHeader(m_elements);
    packet->AddHeader(BeaconHeader());
    return packet;
}

WifiMacHeader
MeshWifiBeacon::CreateHeader(Mac48Address address, Mac48Address mpAddress)
{
    WifiMacHeader hdr;
    hdr.SetType(WIFI_MAC_MGT_BEACON);
    hdr.SetAddr1(Mac48Address::GetBroadcast());
    hdr.SetAddr2(address);
    hdr.SetAddr3(mpAddress);
    hdr.SetDsNotFrom();
    hdr.SetDsNotTo();
    return hdr;
}

} // namespace ns3
