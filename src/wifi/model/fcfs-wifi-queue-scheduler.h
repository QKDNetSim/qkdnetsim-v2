/*
 * Copyright (c) 2022 Universita' degli Studi di Napoli Federico II
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
 * Author: Stefano Avallone <stavallo@unina.it>
 */

#ifndef FCFS_WIFI_QUEUE_SCHEDULER_H
#define FCFS_WIFI_QUEUE_SCHEDULER_H

#include "wifi-mac-queue-scheduler-impl.h"

#include "ns3/nstime.h"

namespace ns3
{

class WifiMpdu;

/**
 * \ingroup wifi
 *
 * Definition of priority for container queues.
 */
struct FcfsPrio
{
    Time priority;               ///< time priority
    WifiContainerQueueType type; ///< type of container queue
};

/**
 * \param lhs the left hand side priority
 * \param rhs the right hand side priority
 * \return whether the left hand side priority is equal to the right hand side priority
 */
bool operator==(const FcfsPrio& lhs, const FcfsPrio& rhs);
/**
 * \param lhs the left hand side priority
 * \param rhs the right hand side priority
 * \return whether the left hand side priority is less than the right hand side priority
 */
bool operator<(const FcfsPrio& lhs, const FcfsPrio& rhs);

/**
 * \ingroup wifi
 *
 * FcfsWifiQueueScheduler is a wifi queue scheduler that serves data frames in a
 * first come first serve fashion. Control frames have the highest priority.
 * Management frames have the second highest priority. Hence, data frames are
 * served after control and management frames.
 */
class FcfsWifiQueueScheduler : public WifiMacQueueSchedulerImpl<FcfsPrio>
{
  public:
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();

    FcfsWifiQueueScheduler();

    /// drop policy
    enum DropPolicy
    {
        DROP_NEWEST,
        DROP_OLDEST
    };

  private:
    Ptr<WifiMpdu> HasToDropBeforeEnqueuePriv(AcIndex ac, Ptr<WifiMpdu> mpdu) override;
    void DoNotifyEnqueue(AcIndex ac, Ptr<WifiMpdu> mpdu) override;
    void DoNotifyDequeue(AcIndex ac, const std::list<Ptr<WifiMpdu>>& mpdus) override;
    void DoNotifyRemove(AcIndex ac, const std::list<Ptr<WifiMpdu>>& mpdus) override;

    DropPolicy m_dropPolicy; //!< Drop behavior of queue
    NS_LOG_TEMPLATE_DECLARE; //!< redefinition of the log component
};

} // namespace ns3

#endif /* FCFS_WIFI_QUEUE_SCHEDULER_H */
