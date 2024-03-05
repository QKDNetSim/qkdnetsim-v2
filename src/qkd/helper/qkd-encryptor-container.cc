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

#include "qkd-encryptor-container.h"
#include "ns3/node-list.h"
#include "ns3/names.h"

namespace ns3 {

QKDEncryptorContainer::QKDEncryptorContainer ()
{
}

void
QKDEncryptorContainer::Add (const QKDEncryptorContainer& other)
{
  for (InterfaceVector::const_iterator i = other.m_list.begin (); i != other.m_list.end (); i++)
    {
      m_list.push_back (*i);
    }
}

QKDEncryptorContainer::Iterator
QKDEncryptorContainer::Begin (void) const
{
  return m_list.begin ();
}

QKDEncryptorContainer::Iterator
QKDEncryptorContainer::End (void) const
{
  return m_list.end ();
}

uint32_t
QKDEncryptorContainer::GetN (void) const
{
  return m_list.size ();
}

void 
QKDEncryptorContainer::Add (Ptr<QKDEncryptor> qkde, uint32_t interface)
{
  m_list.push_back (std::make_pair (qkde, interface));
}
void QKDEncryptorContainer::Add (std::pair<Ptr<QKDEncryptor>, uint32_t> a)
{
  Add (a.first, a.second);
} 

std::pair<Ptr<QKDEncryptor>, uint32_t>
QKDEncryptorContainer::Get (uint32_t i) const
{
  return m_list[i];
}


} // namespace ns3
