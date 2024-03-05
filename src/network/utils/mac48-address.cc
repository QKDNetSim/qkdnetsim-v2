/*
 * Copyright (c) 2007 INRIA
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
#include "mac48-address.h"

#include "ns3/address.h"
#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

#include <cstring>
#include <iomanip>
#include <iostream>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("Mac48Address");

ATTRIBUTE_HELPER_CPP(Mac48Address);

uint64_t Mac48Address::m_allocationIndex = 0;

Mac48Address::Mac48Address(const char* str)
{
    NS_LOG_FUNCTION(this << str);
    NS_ASSERT_MSG(strlen(str) <= 17, "Mac48Address: illegal string (too long) " << str);

    unsigned int bytes[6];
    int charsRead = 0;

    int i = sscanf(str,
                   "%02x:%02x:%02x:%02x:%02x:%02x%n",
                   bytes,
                   bytes + 1,
                   bytes + 2,
                   bytes + 3,
                   bytes + 4,
                   bytes + 5,
                   &charsRead);
    NS_ASSERT_MSG(i == 6 && !str[charsRead], "Mac48Address: illegal string " << str);

    std::copy(std::begin(bytes), std::end(bytes), std::begin(m_address));
}

void
Mac48Address::CopyFrom(const uint8_t buffer[6])
{
    NS_LOG_FUNCTION(this << &buffer);
    std::memcpy(m_address, buffer, 6);
}

void
Mac48Address::CopyTo(uint8_t buffer[6]) const
{
    NS_LOG_FUNCTION(this << &buffer);
    std::memcpy(buffer, m_address, 6);
}

bool
Mac48Address::IsMatchingType(const Address& address)
{
    NS_LOG_FUNCTION(&address);
    return address.CheckCompatible(GetType(), 6);
}

Mac48Address::operator Address() const
{
    return ConvertTo();
}

Address
Mac48Address::ConvertTo() const
{
    NS_LOG_FUNCTION(this);
    return Address(GetType(), m_address, 6);
}

Mac48Address
Mac48Address::ConvertFrom(const Address& address)
{
    NS_LOG_FUNCTION(&address);
    NS_ASSERT(address.CheckCompatible(GetType(), 6));
    Mac48Address retval;
    address.CopyTo(retval.m_address);
    return retval;
}

Mac48Address
Mac48Address::Allocate()
{
    NS_LOG_FUNCTION_NOARGS();

    if (m_allocationIndex == 0)
    {
        Simulator::ScheduleDestroy(Mac48Address::ResetAllocationIndex);
    }

    m_allocationIndex++;
    Mac48Address address;
    address.m_address[0] = (m_allocationIndex >> 40) & 0xff;
    address.m_address[1] = (m_allocationIndex >> 32) & 0xff;
    address.m_address[2] = (m_allocationIndex >> 24) & 0xff;
    address.m_address[3] = (m_allocationIndex >> 16) & 0xff;
    address.m_address[4] = (m_allocationIndex >> 8) & 0xff;
    address.m_address[5] = m_allocationIndex & 0xff;
    return address;
}

void
Mac48Address::ResetAllocationIndex()
{
    NS_LOG_FUNCTION_NOARGS();
    m_allocationIndex = 0;
}

uint8_t
Mac48Address::GetType()
{
    NS_LOG_FUNCTION_NOARGS();
    static uint8_t type = Address::Register();
    return type;
}

bool
Mac48Address::IsBroadcast() const
{
    NS_LOG_FUNCTION(this);
    return *this == GetBroadcast();
}

bool
Mac48Address::IsGroup() const
{
    NS_LOG_FUNCTION(this);
    return (m_address[0] & 0x01) == 0x01;
}

Mac48Address
Mac48Address::GetBroadcast()
{
    NS_LOG_FUNCTION_NOARGS();
    static Mac48Address broadcast("ff:ff:ff:ff:ff:ff");
    return broadcast;
}

Mac48Address
Mac48Address::GetMulticastPrefix()
{
    NS_LOG_FUNCTION_NOARGS();
    static Mac48Address multicast("01:00:5e:00:00:00");
    return multicast;
}

Mac48Address
Mac48Address::GetMulticast6Prefix()
{
    NS_LOG_FUNCTION_NOARGS();
    static Mac48Address multicast("33:33:00:00:00:00");
    return multicast;
}

Mac48Address
Mac48Address::GetMulticast(Ipv4Address multicastGroup)
{
    NS_LOG_FUNCTION(multicastGroup);
    Mac48Address etherAddr = Mac48Address::GetMulticastPrefix();
    //
    // We now have the multicast address in an abstract 48-bit container.  We
    // need to pull it out so we can play with it.  When we're done, we have the
    // high order bits in etherBuffer[0], etc.
    //
    uint8_t etherBuffer[6];
    etherAddr.CopyTo(etherBuffer);

    //
    // Now we need to pull the raw bits out of the Ipv4 destination address.
    //
    uint8_t ipBuffer[4];
    multicastGroup.Serialize(ipBuffer);

    //
    // RFC 1112 says that an Ipv4 host group address is mapped to an EUI-48
    // multicast address by placing the low-order 23-bits of the IP address into
    // the low-order 23 bits of the Ethernet multicast address
    // 01-00-5E-00-00-00 (hex).
    //
    etherBuffer[3] |= ipBuffer[1] & 0x7f;
    etherBuffer[4] = ipBuffer[2];
    etherBuffer[5] = ipBuffer[3];

    //
    // Now, etherBuffer has the desired ethernet multicast address.  We have to
    // suck these bits back into the Mac48Address,
    //
    Mac48Address result;
    result.CopyFrom(etherBuffer);
    return result;
}

Mac48Address
Mac48Address::GetMulticast(Ipv6Address addr)
{
    NS_LOG_FUNCTION(addr);
    Mac48Address etherAddr = Mac48Address::GetMulticast6Prefix();
    uint8_t etherBuffer[6];
    uint8_t ipBuffer[16];

    /* a MAC multicast IPv6 address is like 33:33 and the four low bytes */
    /* for 2001:db8::2fff:fe11:ac10 => 33:33:FE:11:AC:10 */
    etherAddr.CopyTo(etherBuffer);
    addr.Serialize(ipBuffer);

    etherBuffer[2] = ipBuffer[12];
    etherBuffer[3] = ipBuffer[13];
    etherBuffer[4] = ipBuffer[14];
    etherBuffer[5] = ipBuffer[15];

    etherAddr.CopyFrom(etherBuffer);

    return etherAddr;
}

std::ostream&
operator<<(std::ostream& os, const Mac48Address& address)
{
    uint8_t ad[6];
    address.CopyTo(ad);

    os.setf(std::ios::hex, std::ios::basefield);
    os.fill('0');
    for (uint8_t i = 0; i < 5; i++)
    {
        os << std::setw(2) << (uint32_t)ad[i] << ":";
    }
    // Final byte not suffixed by ":"
    os << std::setw(2) << (uint32_t)ad[5];
    os.setf(std::ios::dec, std::ios::basefield);
    os.fill(' ');
    return os;
}

std::istream&
operator>>(std::istream& is, Mac48Address& address)
{
    std::string v;
    is >> v;

    std::string::size_type col = 0;
    for (uint8_t i = 0; i < 6; ++i)
    {
        std::string tmp;
        std::string::size_type next;
        next = v.find(':', col);
        if (next == std::string::npos)
        {
            tmp = v.substr(col, v.size() - col);
            address.m_address[i] = std::stoul(tmp, nullptr, 16);
            break;
        }
        else
        {
            tmp = v.substr(col, next - col);
            address.m_address[i] = std::stoul(tmp, nullptr, 16);
            col = next + 1;
        }
    }
    return is;
}

} // namespace ns3
