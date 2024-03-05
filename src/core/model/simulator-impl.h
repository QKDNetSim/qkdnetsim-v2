/*
 * Copyright (c) 2005,2006 INRIA
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

#ifndef SIMULATOR_IMPL_H
#define SIMULATOR_IMPL_H

#include "event-id.h"
#include "event-impl.h"
#include "nstime.h"
#include "object-factory.h"
#include "object.h"
#include "ptr.h"

/**
 * \file
 * \ingroup simulator
 * ns3::SimulatorImpl declaration.
 */

namespace ns3
{

class Scheduler;

/**
 * \ingroup simulator
 *
 * The SimulatorImpl base class.
 *
 * \todo Define what the simulation or event context means.
 */
class SimulatorImpl : public Object
{
  public:
    /**
     * Get the registered TypeId for this class.
     * \return The object TypeId.
     */
    static TypeId GetTypeId();

    /**  \copydoc Simulator::Destroy   */
    virtual void Destroy() = 0;
    /** \copydoc Simulator::IsFinished */
    virtual bool IsFinished() const = 0;
    /** \copydoc Simulator::Stop() */
    virtual void Stop() = 0;
    /** \copydoc Simulator::Stop(const Time&) */
    virtual EventId Stop(const Time& delay) = 0;
    /** \copydoc Simulator::Schedule(const Time&,const Ptr<EventImpl>&) */
    virtual EventId Schedule(const Time& delay, EventImpl* event) = 0;
    /** \copydoc Simulator::ScheduleWithContext(uint32_t,const Time&,EventImpl*) */
    virtual void ScheduleWithContext(uint32_t context, const Time& delay, EventImpl* event) = 0;
    /** \copydoc Simulator::ScheduleNow(const Ptr<EventImpl>&) */
    virtual EventId ScheduleNow(EventImpl* event) = 0;
    /** \copydoc Simulator::ScheduleDestroy(const Ptr<EventImpl>&) */
    virtual EventId ScheduleDestroy(EventImpl* event) = 0;
    /** \copydoc Simulator::Remove */
    virtual void Remove(const EventId& id) = 0;
    /** \copydoc Simulator::Cancel */
    virtual void Cancel(const EventId& id) = 0;
    /** \copydoc Simulator::IsExpired */
    virtual bool IsExpired(const EventId& id) const = 0;
    /** \copydoc Simulator::Run */
    virtual void Run() = 0;
    /** \copydoc Simulator::Now */
    virtual Time Now() const = 0;
    /** \copydoc Simulator::GetDelayLeft */
    virtual Time GetDelayLeft(const EventId& id) const = 0;
    /** \copydoc Simulator::GetMaximumSimulationTime */
    virtual Time GetMaximumSimulationTime() const = 0;
    /**
     * Set the Scheduler to be used to manage the event list.
     *
     * \param [in] schedulerFactory A new event scheduler factory.
     *
     * The event scheduler can be set at any time: the events scheduled
     * in the previous scheduler will be transferred to the new scheduler
     * before we start to use it.
     */
    virtual void SetScheduler(ObjectFactory schedulerFactory) = 0;
    /** \copydoc Simulator::GetSystemId */
    virtual uint32_t GetSystemId() const = 0;
    /** \copydoc Simulator::GetContext */
    virtual uint32_t GetContext() const = 0;
    /** \copydoc Simulator::GetEventCount */
    virtual uint64_t GetEventCount() const = 0;

    /**
     * Hook called before processing each event.
     *
     * \param [in] id The event about to be processed.
     */
    virtual void PreEventHook(const EventId& id){};
};

} // namespace ns3

#endif /* SIMULATOR_IMPL_H */
