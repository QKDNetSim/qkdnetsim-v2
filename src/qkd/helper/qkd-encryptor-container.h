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

#ifndef QKD_ENCRYPTOR_CONTAINER_H
#define QKD_ENCRYPTOR_CONTAINER_H

#include <stdint.h>
#include <vector>
#include "ns3/qkd-encryptor.h" 
#include "ns3/node.h" 

namespace ns3 {

/**
 * \ingroup QKD
 *
 * \brief holds a vector of std::pair of Ptr<QKDEncryptor> and interface index.
 *
 * Typically ns-3 QKDEncryptors are installed on nodes using an QKD
 * helper.  
 *
 * @see QKDEncryptor 
 */
class QKDEncryptorContainer
{
public:
  /**
   * \brief Container Const Iterator for pairs of QKDEncryptor smart pointer / Interface Index.
   */
  typedef std::vector<std::pair<Ptr<QKDEncryptor>, uint32_t> >::const_iterator Iterator;

  /**
   * \brief Constructor.
   */
  QKDEncryptorContainer ();

  /**
   * \brief Concatenate the entries in the other container with ours.
   * \param other The other container.
   */
  void Add (const QKDEncryptorContainer& other);

  /**
   * \brief Get an iterator which refers to the first pair in the 
   * container.
   *
   * Pairs can be retrieved from the container in two ways.  First,
   * directly by an index into the container, and second, using an iterator.
   * This method is used in the iterator method and is typically used in a 
   * for-loop to run through the pairs
   *
   * \code
   *   QKDEncryptorContainer::Iterator i;
   *   for (i = container.Begin (); i != container.End (); ++i)
   *     {
   *       std::pair<Ptr<QKDEncryptor>, uint32_t> pair = *i;
   *       method (pair.first, pair.second);  // use the pair
   *     }
   * \endcode
   *
   * \return The iterator which refers to the first pair in the container.
   */
  Iterator Begin (void) const;

  /**
   * \brief Get an iterator which indicates past-the-last Node in the 
   * container.
   *
   * Nodes can be retrieved from the container in two ways.  First,
   * directly by an index into the container, and second, using an iterator.
   * This method is used in the iterator method and is typically used in a 
   * for-loop to run through the Nodes
   *
   * \code
   *   NodeContainer::Iterator i;
   *   for (i = container.Begin (); i != container.End (); ++i)
   *     {
   *       std::pair<Ptr<QKDEncryptor>, uint32_t> pair = *i;
   *       method (pair.first, pair.second);  // use the pair
   *     }
   * \endcode
   *
   * \return The iterator which indicates an ending condition for a loop.
   */
  Iterator End (void) const;

  /**
   * \brief Get number of nodes withing the container.
   * \return The number of nodes.
   */
  uint32_t GetN (void) const;

  /**
   * \brief Add an entry to the container.
   * \param The QKD encryptor object.
   * \param ipInterfacePair The pair of a pointer to Ipv4 object and interface index of the Ipv4Interface to add to the container.
   */
  void Add (Ptr<QKDEncryptor>, uint32_t ipInterfacePair);

  /**
   * \brief Add and entry to the container.
   * \param The pair of QKD encryptors.
   * \param ipInterfacePair The pair of a pointer to Ipv4 object and interface index of the Ipv4Interface to add to the container.
   */
  void Add (std::pair<Ptr<QKDEncryptor>, uint32_t> ipInterfacePair);

  /**
   * \brief Get the pair of the QKD encryptor and interface stored at the location
   * specified by the index.
   *
   * \param i the index of the container entry to retrieve.
   * \return The std::pair of a Ptr<QKDEncryptor> and an interface index.
   *   
   */
  std::pair<Ptr<QKDEncryptor>, uint32_t> Get (uint32_t i) const;

private:
  typedef std::vector<std::pair<Ptr<QKDEncryptor>,uint32_t> > InterfaceVector; //!< Container for pairs of QKDEncryptor smart pointer / Interface Index.
  InterfaceVector m_list; //!< List of QKD Encryptors and interfaces index.
};

} // namespace ns3

#endif /* QKD_ENCRYPTOR_CONTAINER_H */
