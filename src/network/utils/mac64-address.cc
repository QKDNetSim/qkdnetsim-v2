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
#include "mac64-address.h"

#include "ns3/address.h"
#include "ns3/assert.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

#include <cstring>
#include <iomanip>
#include <iostream>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("Mac64Address");

ATTRIBUTE_HELPER_CPP(Mac64Address);

uint64_t Mac64Address::m_allocationIndex = 0;

Mac64Address::Mac64Address(const char* str)
{
    NS_LOG_FUNCTION(this << str);
    NS_ASSERT_MSG(strlen(str) <= 23, "Mac64Address: illegal string (too long) " << str);

    unsigned int bytes[8];
    int charsRead = 0;

    int i = sscanf(str,
                   "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x%n",
                   bytes,
                   bytes + 1,
                   bytes + 2,
                   bytes + 3,
                   bytes + 4,
                   bytes + 5,
                   bytes + 6,
                   bytes + 7,
                   &charsRead);
    NS_ASSERT_MSG(i == 8 && !str[charsRead], "Mac64Address: illegal string " << str);

    std::copy(std::begin(bytes), std::end(bytes), std::begin(m_address));
}

Mac64Address::Mac64Address(uint64_t addr)
{
    NS_LOG_FUNCTION(this);
    m_address[7] = addr & 0xFF;
    m_address[6] = (addr >> 8) & 0xFF;
    m_address[5] = (addr >> 16) & 0xFF;
    m_address[4] = (addr >> 24) & 0xFF;
    m_address[3] = (addr >> 32) & 0xFF;
    m_address[2] = (addr >> 40) & 0xFF;
    m_address[1] = (addr >> 48) & 0xFF;
    m_address[0] = (addr >> 56) & 0xFF;
}

void
Mac64Address::CopyFrom(const uint8_t buffer[8])
{
    NS_LOG_FUNCTION(this << &buffer);
    std::memcpy(m_address, buffer, 8);
}

void
Mac64Address::CopyTo(uint8_t buffer[8]) const
{
    NS_LOG_FUNCTION(this << &buffer);
    std::memcpy(buffer, m_address, 8);
}

bool
Mac64Address::IsMatchingType(const Address& address)
{
    NS_LOG_FUNCTION(&address);
    return address.CheckCompatible(GetType(), 8);
}

Mac64Address::operator Address() const
{
    return ConvertTo();
}

Mac64Address
Mac64Address::ConvertFrom(const Address& address)
{
    NS_LOG_FUNCTION(address);
    NS_ASSERT(address.CheckCompatible(GetType(), 8));
    Mac64Address retval;
    address.CopyTo(retval.m_address);
    return retval;
}

Address
Mac64Address::ConvertTo() const
{
    NS_LOG_FUNCTION(this);
    return Address(GetType(), m_address, 8);
}

uint64_t
Mac64Address::ConvertToInt() const
{
    uint64_t shift = 0xFF;
    uint64_t addr = static_cast<uint64_t>(m_address[7]) & (shift);
    addr |= (static_cast<uint64_t>(m_address[6]) << 8) & (shift << 8);
    addr |= (static_cast<uint64_t>(m_address[5]) << 16) & (shift << 16);
    addr |= (static_cast<uint64_t>(m_address[4]) << 24) & (shift << 24);

    addr |= (static_cast<uint64_t>(m_address[3]) << 32) & (shift << 32);
    addr |= (static_cast<uint64_t>(m_address[2]) << 40) & (shift << 40);
    addr |= (static_cast<uint64_t>(m_address[1]) << 48) & (shift << 48);
    addr |= (static_cast<uint64_t>(m_address[0]) << 56) & (shift << 56);

    return addr;
}

Mac64Address
Mac64Address::Allocate()
{
    NS_LOG_FUNCTION_NOARGS();

    if (m_allocationIndex == 0)
    {
        Simulator::ScheduleDestroy(Mac64Address::ResetAllocationIndex);
    }

    m_allocationIndex++;
    Mac64Address address;
    address.m_address[0] = (m_allocationIndex >> 56) & 0xff;
    address.m_address[1] = (m_allocationIndex >> 48) & 0xff;
    address.m_address[2] = (m_allocationIndex >> 40) & 0xff;
    address.m_address[3] = (m_allocationIndex >> 32) & 0xff;
    address.m_address[4] = (m_allocationIndex >> 24) & 0xff;
    address.m_address[5] = (m_allocationIndex >> 16) & 0xff;
    address.m_address[6] = (m_allocationIndex >> 8) & 0xff;
    address.m_address[7] = m_allocationIndex & 0xff;
    return address;
}

void
Mac64Address::ResetAllocationIndex()
{
    NS_LOG_FUNCTION_NOARGS();
    m_allocationIndex = 0;
}

uint8_t
Mac64Address::GetType()
{
    NS_LOG_FUNCTION_NOARGS();
    static uint8_t type = Address::Register();
    return type;
}

std::ostream&
operator<<(std::ostream& os, const Mac64Address& address)
{
    uint8_t ad[8];
    address.CopyTo(ad);

    os.setf(std::ios::hex, std::ios::basefield);
    os.fill('0');
    for (uint8_t i = 0; i < 7; i++)
    {
        os << std::setw(2) << (uint32_t)ad[i] << ":";
    }
    // Final byte not suffixed by ":"
    os << std::setw(2) << (uint32_t)ad[7];
    os.setf(std::ios::dec, std::ios::basefield);
    os.fill(' ');
    return os;
}

std::istream&
operator>>(std::istream& is, Mac64Address& address)
{
    std::string v;
    is >> v;

    std::string::size_type col = 0;
    for (uint8_t i = 0; i < 8; ++i)
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
