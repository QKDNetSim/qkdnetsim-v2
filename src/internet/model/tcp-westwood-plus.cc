/*
 * Copyright (c) 2013 ResiliNets, ITTC, University of Kansas
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
 * Authors: Siddharth Gangadhar <siddharth@ittc.ku.edu>,
 *          Truc Anh N. Nguyen <annguyen@ittc.ku.edu>,
 *          Greeshma Umapathi
 *
 * James P.G. Sterbenz <jpgs@ittc.ku.edu>, director
 * ResiliNets Research Group  https://resilinets.org/
 * Information and Telecommunication Technology Center (ITTC)
 * and Department of Electrical Engineering and Computer Science
 * The University of Kansas Lawrence, KS USA.
 *
 * Work supported in part by NSF FIND (Future Internet Design) Program
 * under grant CNS-0626918 (Postmodern Internet Architecture),
 * NSF grant CNS-1050226 (Multilayer Network Resilience Analysis and Experimentation on GENI),
 * US Department of Defense (DoD), and ITTC at The University of Kansas.
 */

#include "tcp-westwood-plus.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

NS_LOG_COMPONENT_DEFINE("TcpWestwoodPlus");

namespace ns3
{

NS_OBJECT_ENSURE_REGISTERED(TcpWestwoodPlus);

TypeId
TcpWestwoodPlus::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::TcpWestwoodPlus")
            .SetParent<TcpNewReno>()
            .SetGroupName("Internet")
            .AddConstructor<TcpWestwoodPlus>()
            .AddAttribute(
                "FilterType",
                "Use this to choose no filter or Tustin's approximation filter",
                EnumValue(TcpWestwoodPlus::TUSTIN),
                MakeEnumAccessor<FilterType>(&TcpWestwoodPlus::m_fType),
                MakeEnumChecker(TcpWestwoodPlus::NONE, "None", TcpWestwoodPlus::TUSTIN, "Tustin"))
            .AddTraceSource("EstimatedBW",
                            "The estimated bandwidth",
                            MakeTraceSourceAccessor(&TcpWestwoodPlus::m_currentBW),
                            "ns3::TracedValueCallback::DataRate");
    return tid;
}

TcpWestwoodPlus::TcpWestwoodPlus()
    : TcpNewReno(),
      m_currentBW(0),
      m_lastSampleBW(0),
      m_lastBW(0),
      m_ackedSegments(0),
      m_IsCount(false),
      m_lastAck(0)
{
    NS_LOG_FUNCTION(this);
}

TcpWestwoodPlus::TcpWestwoodPlus(const TcpWestwoodPlus& sock)
    : TcpNewReno(sock),
      m_currentBW(sock.m_currentBW),
      m_lastSampleBW(sock.m_lastSampleBW),
      m_lastBW(sock.m_lastBW),
      m_fType(sock.m_fType),
      m_IsCount(sock.m_IsCount)
{
    NS_LOG_FUNCTION(this);
    NS_LOG_LOGIC("Invoked the copy constructor");
}

TcpWestwoodPlus::~TcpWestwoodPlus()
{
}

void
TcpWestwoodPlus::PktsAcked(Ptr<TcpSocketState> tcb, uint32_t packetsAcked, const Time& rtt)
{
    NS_LOG_FUNCTION(this << tcb << packetsAcked << rtt);

    if (rtt.IsZero())
    {
        NS_LOG_WARN("RTT measured is zero!");
        return;
    }

    m_ackedSegments += packetsAcked;

    if (!(rtt.IsZero() || m_IsCount))
    {
        m_IsCount = true;
        m_bwEstimateEvent.Cancel();
        m_bwEstimateEvent = Simulator::Schedule(rtt, &TcpWestwoodPlus::EstimateBW, this, rtt, tcb);
    }
}

void
TcpWestwoodPlus::EstimateBW(const Time& rtt, Ptr<TcpSocketState> tcb)
{
    NS_LOG_FUNCTION(this);

    NS_ASSERT(!rtt.IsZero());

    m_currentBW = DataRate(m_ackedSegments * tcb->m_segmentSize * 8.0 / rtt.GetSeconds());
    m_IsCount = false;

    m_ackedSegments = 0;

    NS_LOG_LOGIC("Estimated BW: " << m_currentBW);

    // Filter the BW sample

    constexpr double ALPHA = 0.9;

    if (m_fType == TcpWestwoodPlus::TUSTIN)
    {
        DataRate sample_bwe = m_currentBW;
        m_currentBW = (m_lastBW * ALPHA) + (((sample_bwe + m_lastSampleBW) * 0.5) * (1 - ALPHA));
        m_lastSampleBW = sample_bwe;
        m_lastBW = m_currentBW;
    }

    NS_LOG_LOGIC("Estimated BW after filtering: " << m_currentBW);
}

uint32_t
TcpWestwoodPlus::GetSsThresh(Ptr<const TcpSocketState> tcb, uint32_t bytesInFlight [[maybe_unused]])
{
    uint32_t ssThresh = static_cast<uint32_t>((m_currentBW * tcb->m_minRtt) / 8.0);

    NS_LOG_LOGIC("CurrentBW: " << m_currentBW << " minRtt: " << tcb->m_minRtt
                               << " ssThresh: " << ssThresh);

    return std::max(2 * tcb->m_segmentSize, ssThresh);
}

Ptr<TcpCongestionOps>
TcpWestwoodPlus::Fork()
{
    return CreateObject<TcpWestwoodPlus>(*this);
}

} // namespace ns3
