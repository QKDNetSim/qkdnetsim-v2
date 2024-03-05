/*
 * Copyright (c) 2006 INRIA
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

#ifndef PRIORITY_QUEUE_SCHEDULER_H
#define PRIORITY_QUEUE_SCHEDULER_H

#include "scheduler.h"

#include <algorithm>
#include <functional>
#include <queue>
#include <stdint.h>
#include <utility>

/**
 * \file
 * \ingroup scheduler
 * Declaration of ns3::PriorityQueueScheduler class.
 */

namespace ns3
{

/**
 * \ingroup scheduler
 * \brief a std::priority_queue event scheduler
 *
 * This class implements an event scheduler using
 * `std::priority_queue` on a `std::vector`.
 *
 * \par Time Complexity
 *
 * Operation    | Amortized %Time  | Reason
 * :----------- | :--------------- | :-----
 * Insert()     | Logarithmic      | `std::push_heap()`
 * IsEmpty()    | Constant         | `std::vector::empty()`
 * PeekNext()   | Constant         | `std::vector::front()`
 * Remove()     | Linear           | `std::find()` and `std::make_heap()`
 * RemoveNext() | Logarithmic      | `std::pop_heap()`
 *
 * \par Memory Complexity
 *
 * Category  | Memory                           | Reason
 * :-------- | :------------------------------- | :-----
 * Overhead  | 3 x `sizeof (*)`<br/>(24 bytes)  | `std::vector`
 * Per Event | 0                                | Events stored in `std::vector` directly
 *
 */
class PriorityQueueScheduler : public Scheduler
{
  public:
    /**
     *  Register this type.
     *  \return The object TypeId.
     */
    static TypeId GetTypeId();

    /** Constructor. */
    PriorityQueueScheduler();
    /** Destructor. */
    ~PriorityQueueScheduler() override;

    // Inherited
    void Insert(const Scheduler::Event& ev) override;
    bool IsEmpty() const override;
    Scheduler::Event PeekNext() const override;
    Scheduler::Event RemoveNext() override;
    void Remove(const Scheduler::Event& ev) override;

  private:
    /**
     * Custom priority_queue which supports remove,
     * and returns entries in _increasing_ time order.
     */
    class EventPriorityQueue : public std::priority_queue<Scheduler::Event,
                                                          std::vector<Scheduler::Event>,
                                                          std::greater<>>
    {
      public:
        /**
         * \copydoc PriorityQueueScheduler::Remove()
         * \returns \c true if the event was found, false otherwise.
         */
        bool remove(const Scheduler::Event& ev);

    }; // class EventPriorityQueue

    /** The event queue. */
    EventPriorityQueue m_queue;

}; // class PriorityQueueScheduler

} // namespace ns3

#endif /* PRIORITY_QUEUE_SCHEDULER_H */
