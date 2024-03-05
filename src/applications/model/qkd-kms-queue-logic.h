/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2022 DOTFEESA www.tk.etf.unsa.ba
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
 * Author:  Miralem Mehic <miralem.mehic@ieee.org>
 *          Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 */

#ifndef QKD_KMS_QUEUE_LOGIC_H
#define QKD_KMS_QUEUE_LOGIC_H
 
#include <queue>
#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/http.h"
#include "ns3/socket.h"
#include "ns3/json.h"

namespace ns3 {
 

/**
 * \ingroup traffic-control
 *
 * Linux pfifo_fast is the default priority queue enabled on Linux
 * systems. Packets are enqueued in three FIFO droptail queues according
 * to three priority bands based on the packet priority.
 *
 * The system behaves similar to three ns3::DropTail queues operating
 * together, in which packets from higher priority bands are always
 * dequeued before a packet from a lower priority band is dequeued.
 *
 * The queue disc capacity, i.e., the maximum number of packets that can
 * be enqueued in the queue disc, is set through the limit attribute, which
 * plays the same role as txqueuelen in Linux. If no internal queue is
 * provided, three DropTail queues having each a capacity equal to limit are
 * created by default. User is allowed to provide queues, but they must be
 * three, operate in packet mode and each have a capacity not less
 * than limit. 
 *
 * \note Additional waiting queues are installed between the L3
 * and  ISO/OSI layer to avoid conflicts in decision making
 * which could lead to inaccurate routing. Experimental testing and usage!
 */
class QKDKMSQueueLogic: public Object {
public:
  
  /**
   * The KMS Queue elements.
   */
  struct QKDKMSQueueEntry
  {
      std::string ksid;
      Ptr<Socket> socket;
      HTTPMessage httpMessage; 
      Ptr<Packet> packet;
  };

  /**
   * \brief Get the type ID.
   * \return The object TypeId.
   */
  static TypeId GetTypeId (void);
  
  /**
   * \brief Constructor.
   *
   * Creates a queue with a depth of 1000 packets per band by default.
   */
  QKDKMSQueueLogic ();

  /**
   * \brief Destructor.
   */
  ~QKDKMSQueueLogic(); 

  /**
   * \brief Add the element to the queue.
   * \param item The element.
   * \return The success indicator.
   */
  bool Enqueue (QKDKMSQueueEntry item);

  /**
   * \brief Pop the element from the queue.
   * \return The queue element.
   */
  QKDKMSQueueLogic::QKDKMSQueueEntry Dequeue (void);

private:

  TracedCallback<const HTTPMessage > m_traceEnqueue;  //!< A trace for the enqueued packet.
  TracedCallback<const HTTPMessage > m_traceDequeue; //!< A trace for the dequeue packet.
  TracedCallback<const HTTPMessage > m_traceDroped; //!< A trace for the dropped packet.

  TracedValue<uint32_t> m_nPackets; //!< The number of packets in the queue.

  uint32_t m_maxSize; //!< The queue size.
  uint32_t m_numberOfQueues; //!< The number of queues.

  std::vector<std::vector<QKDKMSQueueEntry> > m_queues; //!< A list of queues.
 
};

} // namespace ns3

#endif /* QKD_KMS_QUEUE_LOGIC_H */
