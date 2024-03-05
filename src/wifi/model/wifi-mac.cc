/*
 * Copyright (c) 2008 INRIA
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

#include "wifi-mac.h"

#include "channel-access-manager.h"
#include "extended-capabilities.h"
#include "mac-rx-middle.h"
#include "mac-tx-middle.h"
#include "mgt-action-headers.h"
#include "qos-txop.h"
#include "ssid.h"
#include "wifi-mac-queue.h"
#include "wifi-net-device.h"

#include "ns3/eht-configuration.h"
#include "ns3/eht-frame-exchange-manager.h"
#include "ns3/he-configuration.h"
#include "ns3/ht-configuration.h"
#include "ns3/log.h"
#include "ns3/packet.h"
#include "ns3/pointer.h"
#include "ns3/vht-configuration.h"

#include <algorithm>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("WifiMac");

NS_OBJECT_ENSURE_REGISTERED(WifiMac);

WifiMac::WifiMac()
    : m_qosSupported(false)
{
    NS_LOG_FUNCTION(this);

    m_rxMiddle = Create<MacRxMiddle>();
    m_rxMiddle->SetForwardCallback(MakeCallback(&WifiMac::Receive, this));

    m_txMiddle = Create<MacTxMiddle>();
}

WifiMac::~WifiMac()
{
    NS_LOG_FUNCTION(this);
}

TypeId
WifiMac::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::WifiMac")
            .SetParent<Object>()
            .SetGroupName("Wifi")
            .AddAttribute("Ssid",
                          "The ssid we want to belong to.",
                          SsidValue(Ssid("default")),
                          MakeSsidAccessor(&WifiMac::GetSsid, &WifiMac::SetSsid),
                          MakeSsidChecker())
            .AddAttribute("QosSupported",
                          "This Boolean attribute is set to enable 802.11e/WMM-style QoS support "
                          "at this STA.",
                          TypeId::ATTR_GET |
                              TypeId::ATTR_CONSTRUCT, // prevent setting after construction
                          BooleanValue(false),
                          MakeBooleanAccessor(&WifiMac::SetQosSupported, &WifiMac::GetQosSupported),
                          MakeBooleanChecker())
            .AddAttribute("CtsToSelfSupported",
                          "Use CTS to Self when using a rate that is not in the basic rate set.",
                          BooleanValue(false),
                          MakeBooleanAccessor(&WifiMac::SetCtsToSelfSupported),
                          MakeBooleanChecker())
            .AddAttribute(
                "ShortSlotTimeSupported",
                "Whether or not short slot time is supported (only used by ERP APs or STAs).",
                BooleanValue(true),
                MakeBooleanAccessor(&WifiMac::SetShortSlotTimeSupported,
                                    &WifiMac::GetShortSlotTimeSupported),
                MakeBooleanChecker())
            .AddAttribute("Txop",
                          "The Txop object.",
                          PointerValue(),
                          MakePointerAccessor(&WifiMac::GetTxop),
                          MakePointerChecker<Txop>())
            .AddAttribute("VO_Txop",
                          "Queue that manages packets belonging to AC_VO access class.",
                          PointerValue(),
                          MakePointerAccessor(&WifiMac::GetVOQueue),
                          MakePointerChecker<QosTxop>())
            .AddAttribute("VI_Txop",
                          "Queue that manages packets belonging to AC_VI access class.",
                          PointerValue(),
                          MakePointerAccessor(&WifiMac::GetVIQueue),
                          MakePointerChecker<QosTxop>())
            .AddAttribute("BE_Txop",
                          "Queue that manages packets belonging to AC_BE access class.",
                          PointerValue(),
                          MakePointerAccessor(&WifiMac::GetBEQueue),
                          MakePointerChecker<QosTxop>())
            .AddAttribute("BK_Txop",
                          "Queue that manages packets belonging to AC_BK access class.",
                          PointerValue(),
                          MakePointerAccessor(&WifiMac::GetBKQueue),
                          MakePointerChecker<QosTxop>())
            .AddAttribute(
                "MpduBufferSize",
                "The size (in number of MPDUs) of the buffer used for each BlockAck "
                "agreement in which this node is a recipient. The provided value is "
                "capped to the maximum allowed value based on the supported standard.",
                UintegerValue(1024),
                MakeUintegerAccessor(&WifiMac::GetMpduBufferSize, &WifiMac::SetMpduBufferSize),
                MakeUintegerChecker<uint16_t>(1, 1024))
            .AddAttribute("VO_MaxAmsduSize",
                          "Maximum length in bytes of an A-MSDU for AC_VO access class "
                          "(capped to 7935 for HT PPDUs and 11398 for VHT/HE/EHT PPDUs). "
                          "Value 0 means A-MSDU aggregation is disabled for that AC.",
                          UintegerValue(0),
                          MakeUintegerAccessor(&WifiMac::m_voMaxAmsduSize),
                          MakeUintegerChecker<uint16_t>(0, 11398))
            .AddAttribute("VI_MaxAmsduSize",
                          "Maximum length in bytes of an A-MSDU for AC_VI access class "
                          "(capped to 7935 for HT PPDUs and 11398 for VHT/HE/EHT PPDUs). "
                          "Value 0 means A-MSDU aggregation is disabled for that AC.",
                          UintegerValue(0),
                          MakeUintegerAccessor(&WifiMac::m_viMaxAmsduSize),
                          MakeUintegerChecker<uint16_t>(0, 11398))
            .AddAttribute("BE_MaxAmsduSize",
                          "Maximum length in bytes of an A-MSDU for AC_BE access class "
                          "(capped to 7935 for HT PPDUs and 11398 for VHT/HE/EHT PPDUs). "
                          "Value 0 means A-MSDU aggregation is disabled for that AC.",
                          UintegerValue(0),
                          MakeUintegerAccessor(&WifiMac::m_beMaxAmsduSize),
                          MakeUintegerChecker<uint16_t>(0, 11398))
            .AddAttribute("BK_MaxAmsduSize",
                          "Maximum length in bytes of an A-MSDU for AC_BK access class "
                          "(capped to 7935 for HT PPDUs and 11398 for VHT/HE/EHT PPDUs). "
                          "Value 0 means A-MSDU aggregation is disabled for that AC.",
                          UintegerValue(0),
                          MakeUintegerAccessor(&WifiMac::m_bkMaxAmsduSize),
                          MakeUintegerChecker<uint16_t>(0, 11398))
            .AddAttribute(
                "VO_MaxAmpduSize",
                "Maximum length in bytes of an A-MPDU for AC_VO access class "
                "(capped to 65535 for HT PPDUs, 1048575 for VHT PPDUs, 6500631 for HE PPDUs "
                "and 15523200 for EHT PPDUs). "
                "Value 0 means A-MPDU aggregation is disabled for that AC.",
                UintegerValue(0),
                MakeUintegerAccessor(&WifiMac::m_voMaxAmpduSize),
                MakeUintegerChecker<uint32_t>(0, 15523200))
            .AddAttribute(
                "VI_MaxAmpduSize",
                "Maximum length in bytes of an A-MPDU for AC_VI access class "
                "(capped to 65535 for HT PPDUs, 1048575 for VHT PPDUs, 6500631 for HE PPDUs "
                "and 15523200 for EHT PPDUs). "
                "Value 0 means A-MPDU aggregation is disabled for that AC.",
                UintegerValue(65535),
                MakeUintegerAccessor(&WifiMac::m_viMaxAmpduSize),
                MakeUintegerChecker<uint32_t>(0, 15523200))
            .AddAttribute(
                "BE_MaxAmpduSize",
                "Maximum length in bytes of an A-MPDU for AC_BE access class "
                "(capped to 65535 for HT PPDUs, 1048575 for VHT PPDUs, 6500631 for HE PPDUs "
                "and 15523200 for EHT PPDUs). "
                "Value 0 means A-MPDU aggregation is disabled for that AC.",
                UintegerValue(65535),
                MakeUintegerAccessor(&WifiMac::m_beMaxAmpduSize),
                MakeUintegerChecker<uint32_t>(0, 15523200))
            .AddAttribute(
                "BK_MaxAmpduSize",
                "Maximum length in bytes of an A-MPDU for AC_BK access class "
                "(capped to 65535 for HT PPDUs, 1048575 for VHT PPDUs, 6500631 for HE PPDUs "
                "and 15523200 for EHT PPDUs). "
                "Value 0 means A-MPDU aggregation is disabled for that AC.",
                UintegerValue(0),
                MakeUintegerAccessor(&WifiMac::m_bkMaxAmpduSize),
                MakeUintegerChecker<uint32_t>(0, 15523200))
            .AddAttribute(
                "VO_BlockAckThreshold",
                "If number of packets in VO queue reaches this value, "
                "block ack mechanism is used. If this value is 0, block ack is never used."
                "When A-MPDU is enabled, block ack mechanism is used regardless of this value.",
                UintegerValue(0),
                MakeUintegerAccessor(&WifiMac::SetVoBlockAckThreshold),
                MakeUintegerChecker<uint8_t>(0, 64))
            .AddAttribute(
                "VI_BlockAckThreshold",
                "If number of packets in VI queue reaches this value, "
                "block ack mechanism is used. If this value is 0, block ack is never used."
                "When A-MPDU is enabled, block ack mechanism is used regardless of this value.",
                UintegerValue(0),
                MakeUintegerAccessor(&WifiMac::SetViBlockAckThreshold),
                MakeUintegerChecker<uint8_t>(0, 64))
            .AddAttribute(
                "BE_BlockAckThreshold",
                "If number of packets in BE queue reaches this value, "
                "block ack mechanism is used. If this value is 0, block ack is never used."
                "When A-MPDU is enabled, block ack mechanism is used regardless of this value.",
                UintegerValue(0),
                MakeUintegerAccessor(&WifiMac::SetBeBlockAckThreshold),
                MakeUintegerChecker<uint8_t>(0, 64))
            .AddAttribute(
                "BK_BlockAckThreshold",
                "If number of packets in BK queue reaches this value, "
                "block ack mechanism is used. If this value is 0, block ack is never used."
                "When A-MPDU is enabled, block ack mechanism is used regardless of this value.",
                UintegerValue(0),
                MakeUintegerAccessor(&WifiMac::SetBkBlockAckThreshold),
                MakeUintegerChecker<uint8_t>(0, 64))
            .AddAttribute(
                "VO_BlockAckInactivityTimeout",
                "Represents max time (blocks of 1024 microseconds) allowed for block ack"
                "inactivity for AC_VO. If this value isn't equal to 0 a timer start after that a"
                "block ack setup is completed and will be reset every time that a block ack"
                "frame is received. If this value is 0, block ack inactivity timeout won't be "
                "used.",
                UintegerValue(0),
                MakeUintegerAccessor(&WifiMac::SetVoBlockAckInactivityTimeout),
                MakeUintegerChecker<uint16_t>())
            .AddAttribute(
                "VI_BlockAckInactivityTimeout",
                "Represents max time (blocks of 1024 microseconds) allowed for block ack"
                "inactivity for AC_VI. If this value isn't equal to 0 a timer start after that a"
                "block ack setup is completed and will be reset every time that a block ack"
                "frame is received. If this value is 0, block ack inactivity timeout won't be "
                "used.",
                UintegerValue(0),
                MakeUintegerAccessor(&WifiMac::SetViBlockAckInactivityTimeout),
                MakeUintegerChecker<uint16_t>())
            .AddAttribute(
                "BE_BlockAckInactivityTimeout",
                "Represents max time (blocks of 1024 microseconds) allowed for block ack"
                "inactivity for AC_BE. If this value isn't equal to 0 a timer start after that a"
                "block ack setup is completed and will be reset every time that a block ack"
                "frame is received. If this value is 0, block ack inactivity timeout won't be "
                "used.",
                UintegerValue(0),
                MakeUintegerAccessor(&WifiMac::SetBeBlockAckInactivityTimeout),
                MakeUintegerChecker<uint16_t>())
            .AddAttribute(
                "BK_BlockAckInactivityTimeout",
                "Represents max time (blocks of 1024 microseconds) allowed for block ack"
                "inactivity for AC_BK. If this value isn't equal to 0 a timer start after that a"
                "block ack setup is completed and will be reset every time that a block ack"
                "frame is received. If this value is 0, block ack inactivity timeout won't be "
                "used.",
                UintegerValue(0),
                MakeUintegerAccessor(&WifiMac::SetBkBlockAckInactivityTimeout),
                MakeUintegerChecker<uint16_t>())
            .AddTraceSource("MacTx",
                            "A packet has been received from higher layers and is being processed "
                            "in preparation for "
                            "queueing for transmission.",
                            MakeTraceSourceAccessor(&WifiMac::m_macTxTrace),
                            "ns3::Packet::TracedCallback")
            .AddTraceSource(
                "MacTxDrop",
                "A packet has been dropped in the MAC layer before being queued for transmission. "
                "This trace source is fired, e.g., when an AP's MAC receives from the upper layer "
                "a packet destined to a station that is not associated with the AP or a STA's MAC "
                "receives a packet from the upper layer while it is not associated with any AP.",
                MakeTraceSourceAccessor(&WifiMac::m_macTxDropTrace),
                "ns3::Packet::TracedCallback")
            .AddTraceSource(
                "MacPromiscRx",
                "A packet has been received by this device, has been passed up from the physical "
                "layer "
                "and is being forwarded up the local protocol stack.  This is a promiscuous trace.",
                MakeTraceSourceAccessor(&WifiMac::m_macPromiscRxTrace),
                "ns3::Packet::TracedCallback")
            .AddTraceSource("MacRx",
                            "A packet has been received by this device, has been passed up from "
                            "the physical layer "
                            "and is being forwarded up the local protocol stack. This is a "
                            "non-promiscuous trace.",
                            MakeTraceSourceAccessor(&WifiMac::m_macRxTrace),
                            "ns3::Packet::TracedCallback")
            .AddTraceSource("MacRxDrop",
                            "A packet has been dropped in the MAC layer after it has been passed "
                            "up from the physical layer.",
                            MakeTraceSourceAccessor(&WifiMac::m_macRxDropTrace),
                            "ns3::Packet::TracedCallback")
            .AddTraceSource("AckedMpdu",
                            "An MPDU that was successfully acknowledged, via either a "
                            "Normal Ack or a Block Ack.",
                            MakeTraceSourceAccessor(&WifiMac::m_ackedMpduCallback),
                            "ns3::WifiMpdu::TracedCallback")
            .AddTraceSource("NAckedMpdu",
                            "An MPDU that was negatively acknowledged via a Block Ack.",
                            MakeTraceSourceAccessor(&WifiMac::m_nackedMpduCallback),
                            "ns3::WifiMpdu::TracedCallback")
            .AddTraceSource(
                "DroppedMpdu",
                "An MPDU that was dropped for the given reason (see WifiMacDropReason).",
                MakeTraceSourceAccessor(&WifiMac::m_droppedMpduCallback),
                "ns3::WifiMac::DroppedMpduCallback")
            .AddTraceSource(
                "MpduResponseTimeout",
                "An MPDU whose response was not received before the timeout, along with "
                "an identifier of the type of timeout (see WifiTxTimer::Reason) and the "
                "TXVECTOR used to transmit the MPDU. This trace source is fired when a "
                "CTS is missing after an RTS, when all CTS frames are missing after an MU-RTS, "
                "or when a Normal Ack is missing after an MPDU or after a DL MU PPDU "
                "acknowledged in SU format.",
                MakeTraceSourceAccessor(&WifiMac::m_mpduResponseTimeoutCallback),
                "ns3::WifiMac::MpduResponseTimeoutCallback")
            .AddTraceSource(
                "PsduResponseTimeout",
                "A PSDU whose response was not received before the timeout, along with "
                "an identifier of the type of timeout (see WifiTxTimer::Reason) and the "
                "TXVECTOR used to transmit the PSDU. This trace source is fired when a "
                "BlockAck is missing after an A-MPDU, a BlockAckReq (possibly in the "
                "context of the acknowledgment of a DL MU PPDU in SU format) or a TB PPDU "
                "(in the latter case the missing BlockAck is a Multi-STA BlockAck).",
                MakeTraceSourceAccessor(&WifiMac::m_psduResponseTimeoutCallback),
                "ns3::WifiMac::PsduResponseTimeoutCallback")
            .AddTraceSource(
                "PsduMapResponseTimeout",
                "A PSDU map for which not all the responses were received before the timeout, "
                "along with an identifier of the type of timeout (see WifiTxTimer::Reason), "
                "the set of MAC addresses of the stations that did not respond and the total "
                "number of stations that had to respond. This trace source is fired when not "
                "all the addressed stations responded to an MU-BAR Trigger frame (either sent as "
                "a SU frame or aggregated to PSDUs in the DL MU PPDU), a Basic Trigger Frame or "
                "a BSRP Trigger Frame.",
                MakeTraceSourceAccessor(&WifiMac::m_psduMapResponseTimeoutCallback),
                "ns3::WifiMac::PsduMapResponseTimeoutCallback");
    return tid;
}

void
WifiMac::DoInitialize()
{
    NS_LOG_FUNCTION(this);

    if (m_txop)
    {
        m_txop->Initialize();
    }

    for (auto it = m_edca.begin(); it != m_edca.end(); ++it)
    {
        it->second->Initialize();
    }

    for (const auto& [id, link] : m_links)
    {
        if (auto cam = link->channelAccessManager)
        {
            cam->Initialize();
        }
    }
}

void
WifiMac::DoDispose()
{
    NS_LOG_FUNCTION(this);

    m_rxMiddle = nullptr;
    m_txMiddle = nullptr;
    m_links.clear();

    if (m_txop)
    {
        m_txop->Dispose();
    }
    m_txop = nullptr;

    for (auto it = m_edca.begin(); it != m_edca.end(); ++it)
    {
        it->second->Dispose();
        it->second = nullptr;
    }

    m_device = nullptr;
    if (m_scheduler != nullptr)
    {
        m_scheduler->Dispose();
    }
    m_scheduler = nullptr;
}

WifiMac::LinkEntity::~LinkEntity()
{
    // WifiMac owns pointers to ChannelAccessManager and FrameExchangeManager
    if (channelAccessManager)
    {
        channelAccessManager->Dispose();
    }
    if (feManager)
    {
        feManager->Dispose();
    }
}

void
WifiMac::SetTypeOfStation(TypeOfStation type)
{
    NS_LOG_FUNCTION(this << type);
    m_typeOfStation = type;
}

TypeOfStation
WifiMac::GetTypeOfStation() const
{
    return m_typeOfStation;
}

void
WifiMac::SetDevice(const Ptr<WifiNetDevice> device)
{
    m_device = device;
    if (GetHtSupported())
    {
        // the configured BlockAck buffer size can now be capped
        m_mpduBufferSize = std::min(m_mpduBufferSize, GetMaxBaBufferSize());
    }
}

Ptr<WifiNetDevice>
WifiMac::GetDevice() const
{
    return m_device;
}

void
WifiMac::SetAddress(Mac48Address address)
{
    NS_LOG_FUNCTION(this << address);
    m_address = address;
}

Mac48Address
WifiMac::GetAddress() const
{
    return m_address;
}

void
WifiMac::SetSsid(Ssid ssid)
{
    NS_LOG_FUNCTION(this << ssid);
    m_ssid = ssid;
}

Ssid
WifiMac::GetSsid() const
{
    return m_ssid;
}

void
WifiMac::SetBssid(Mac48Address bssid, uint8_t linkId)
{
    NS_LOG_FUNCTION(this << bssid << +linkId);
    GetLink(linkId).feManager->SetBssid(bssid);
}

Mac48Address
WifiMac::GetBssid(uint8_t linkId) const
{
    return GetLink(linkId).feManager->GetBssid();
}

void
WifiMac::SetPromisc()
{
    for (auto& [id, link] : m_links)
    {
        link->feManager->SetPromisc();
    }
}

Ptr<Txop>
WifiMac::GetTxop() const
{
    return m_txop;
}

Ptr<QosTxop>
WifiMac::GetQosTxop(AcIndex ac) const
{
    // Use std::find_if() instead of std::map::find() because the latter compares
    // the given AC index with the AC index of an element in the map by using the
    // operator< defined for AcIndex, which aborts if an operand is not a QoS AC
    // (the AC index passed to this method may not be a QoS AC).
    // The performance penalty is limited because std::map::find() performs 3
    // comparisons in the worst case, while std::find_if() performs 4 comparisons
    // in the worst case.
    const auto it = std::find_if(m_edca.cbegin(), m_edca.cend(), [ac](const auto& pair) {
        return pair.first == ac;
    });
    return (it == m_edca.cend() ? nullptr : it->second);
}

Ptr<QosTxop>
WifiMac::GetQosTxop(uint8_t tid) const
{
    return GetQosTxop(QosUtilsMapTidToAc(tid));
}

Ptr<QosTxop>
WifiMac::GetVOQueue() const
{
    return (m_qosSupported ? GetQosTxop(AC_VO) : nullptr);
}

Ptr<QosTxop>
WifiMac::GetVIQueue() const
{
    return (m_qosSupported ? GetQosTxop(AC_VI) : nullptr);
}

Ptr<QosTxop>
WifiMac::GetBEQueue() const
{
    return (m_qosSupported ? GetQosTxop(AC_BE) : nullptr);
}

Ptr<QosTxop>
WifiMac::GetBKQueue() const
{
    return (m_qosSupported ? GetQosTxop(AC_BK) : nullptr);
}

Ptr<WifiMacQueue>
WifiMac::GetTxopQueue(AcIndex ac) const
{
    Ptr<Txop> txop = (ac == AC_BE_NQOS ? m_txop : StaticCast<Txop>(GetQosTxop(ac)));
    return (txop ? txop->GetWifiMacQueue() : nullptr);
}

bool
WifiMac::HasFramesToTransmit(uint8_t linkId)
{
    if (m_txop && m_txop->HasFramesToTransmit(linkId))
    {
        return true;
    }
    for (const auto& [aci, qosTxop] : m_edca)
    {
        if (qosTxop->HasFramesToTransmit(linkId))
        {
            return true;
        }
    }
    return false;
}

void
WifiMac::SetMacQueueScheduler(Ptr<WifiMacQueueScheduler> scheduler)
{
    m_scheduler = scheduler;
    m_scheduler->SetWifiMac(this);
}

Ptr<WifiMacQueueScheduler>
WifiMac::GetMacQueueScheduler() const
{
    return m_scheduler;
}

void
WifiMac::NotifyChannelSwitching(uint8_t linkId)
{
    NS_LOG_FUNCTION(this << +linkId);

    // we may have changed PHY band, in which case it is necessary to re-configure
    // the PHY dependent parameters. In any case, this makes no harm
    ConfigurePhyDependentParameters(linkId);

    // Reset remote station manager
    GetLink(linkId).stationManager->Reset();
}

void
WifiMac::NotifyTx(Ptr<const Packet> packet)
{
    m_macTxTrace(packet);
}

void
WifiMac::NotifyTxDrop(Ptr<const Packet> packet)
{
    m_macTxDropTrace(packet);
}

void
WifiMac::NotifyRx(Ptr<const Packet> packet)
{
    m_macRxTrace(packet);
}

void
WifiMac::NotifyPromiscRx(Ptr<const Packet> packet)
{
    m_macPromiscRxTrace(packet);
}

void
WifiMac::NotifyRxDrop(Ptr<const Packet> packet)
{
    m_macRxDropTrace(packet);
}

void
WifiMac::SetupEdcaQueue(AcIndex ac)
{
    NS_LOG_FUNCTION(this << ac);

    // Our caller shouldn't be attempting to setup a queue that is
    // already configured.
    NS_ASSERT(m_edca.find(ac) == m_edca.end());

    Ptr<QosTxop> edca = CreateObject<QosTxop>(ac);
    edca->SetTxMiddle(m_txMiddle);
    edca->GetBaManager()->SetTxOkCallback(
        MakeCallback(&MpduTracedCallback::operator(), &m_ackedMpduCallback));
    edca->GetBaManager()->SetTxFailedCallback(
        MakeCallback(&MpduTracedCallback::operator(), &m_nackedMpduCallback));
    edca->SetDroppedMpduCallback(
        MakeCallback(&DroppedMpduTracedCallback::operator(), &m_droppedMpduCallback));

    m_edca.insert(std::make_pair(ac, edca));
}

void
WifiMac::ConfigureContentionWindow(uint32_t cwMin, uint32_t cwMax)
{
    std::list<bool> isDsssOnly;
    for (const auto& [id, link] : m_links)
    {
        isDsssOnly.push_back(link->dsssSupported && !link->erpSupported);
    }

    if (m_txop)
    {
        // The special value of AC_BE_NQOS which exists in the Access
        // Category enumeration allows us to configure plain old DCF.
        ConfigureDcf(m_txop, cwMin, cwMax, isDsssOnly, AC_BE_NQOS);
    }

    // Now we configure the EDCA functions
    for (auto it = m_edca.begin(); it != m_edca.end(); ++it)
    {
        ConfigureDcf(it->second, cwMin, cwMax, isDsssOnly, it->first);
    }
}

void
WifiMac::ConfigureDcf(Ptr<Txop> dcf,
                      uint32_t cwmin,
                      uint32_t cwmax,
                      std::list<bool> isDsss,
                      AcIndex ac)
{
    NS_LOG_FUNCTION(this << dcf << cwmin << cwmax << +ac);

    uint32_t cwMinValue = 0;
    uint32_t cwMaxValue = 0;
    uint8_t aifsnValue = 0;
    Time txopLimitDsss(0);
    Time txopLimitNoDsss(0);

    /* see IEEE 802.11-2020 Table 9-155 "Default EDCA Parameter Set element parameter values" */
    switch (ac)
    {
    case AC_VO:
        cwMinValue = (cwmin + 1) / 4 - 1;
        cwMaxValue = (cwmin + 1) / 2 - 1;
        aifsnValue = 2;
        txopLimitDsss = MicroSeconds(3264);
        txopLimitNoDsss = MicroSeconds(2080);
        break;
    case AC_VI:
        cwMinValue = (cwmin + 1) / 2 - 1;
        cwMaxValue = cwmin;
        aifsnValue = 2;
        txopLimitDsss = MicroSeconds(6016);
        txopLimitNoDsss = MicroSeconds(4096);
        break;
    case AC_BE:
        cwMinValue = cwmin;
        cwMaxValue = cwmax;
        aifsnValue = 3;
        txopLimitDsss = MicroSeconds(0);   // TODO should be MicroSeconds (3264)
        txopLimitNoDsss = MicroSeconds(0); // TODO should be MicroSeconds (2528)
        break;
    case AC_BK:
        cwMinValue = cwmin;
        cwMaxValue = cwmax;
        aifsnValue = 7;
        txopLimitDsss = MicroSeconds(0);   // TODO should be MicroSeconds (3264)
        txopLimitNoDsss = MicroSeconds(0); // TODO should be MicroSeconds (2528)
        break;
    case AC_BE_NQOS:
        cwMinValue = cwmin;
        cwMaxValue = cwmax;
        aifsnValue = 2;
        txopLimitDsss = txopLimitNoDsss = MicroSeconds(0);
        break;
    case AC_BEACON:
        // done by ApWifiMac
        break;
    case AC_UNDEF:
        NS_FATAL_ERROR("I don't know what to do with this");
        break;
    }

    std::vector<uint32_t> cwValues(m_links.size());
    std::vector<uint8_t> aifsnValues(m_links.size());
    std::vector<Time> txopLimitValues(m_links.size());

    std::fill(cwValues.begin(), cwValues.end(), cwMinValue);
    dcf->SetMinCws(cwValues);
    std::fill(cwValues.begin(), cwValues.end(), cwMaxValue);
    dcf->SetMaxCws(cwValues);
    std::fill(aifsnValues.begin(), aifsnValues.end(), aifsnValue);
    dcf->SetAifsns(aifsnValues);
    std::transform(isDsss.begin(),
                   isDsss.end(),
                   txopLimitValues.begin(),
                   [&txopLimitDsss, &txopLimitNoDsss](bool dsss) {
                       return (dsss ? txopLimitDsss : txopLimitNoDsss);
                   });
    dcf->SetTxopLimits(txopLimitValues);
}

void
WifiMac::ConfigureStandard(WifiStandard standard)
{
    NS_LOG_FUNCTION(this << standard);
    NS_ABORT_IF(standard >= WIFI_STANDARD_80211n && !m_qosSupported);
    NS_ABORT_MSG_IF(m_links.empty(), "No PHY configured yet");

    for (auto& [id, link] : m_links)
    {
        NS_ABORT_MSG_IF(
            !link->phy || !link->phy->GetOperatingChannel().IsSet(),
            "[LinkID " << +id
                       << "] PHY must have been set and an operating channel must have been set");

        // do not create a ChannelAccessManager and a FrameExchangeManager if they
        // already exist (this function may be called after ResetWifiPhys)
        if (!link->channelAccessManager)
        {
            link->channelAccessManager = CreateObject<ChannelAccessManager>();
        }
        link->channelAccessManager->SetupPhyListener(link->phy);

        if (!link->feManager)
        {
            link->feManager = SetupFrameExchangeManager(standard);
        }
        link->feManager->SetWifiPhy(link->phy);
        link->feManager->SetWifiMac(this);
        link->feManager->SetLinkId(id);
        link->channelAccessManager->SetLinkId(id);
        link->channelAccessManager->SetupFrameExchangeManager(link->feManager);

        if (m_txop)
        {
            m_txop->SetWifiMac(this);
            link->channelAccessManager->Add(m_txop);
        }
        for (auto it = m_edca.begin(); it != m_edca.end(); ++it)
        {
            it->second->SetWifiMac(this);
            link->channelAccessManager->Add(it->second);
        }

        ConfigurePhyDependentParameters(id);
    }
}

void
WifiMac::ConfigurePhyDependentParameters(uint8_t linkId)
{
    NS_LOG_FUNCTION(this << +linkId);

    WifiStandard standard = GetLink(linkId).phy->GetStandard();

    uint32_t cwmin = (standard == WIFI_STANDARD_80211b ? 31 : 15);
    uint32_t cwmax = 1023;

    SetDsssSupported(standard == WIFI_STANDARD_80211b, linkId);
    SetErpSupported(standard >= WIFI_STANDARD_80211g &&
                        m_links[linkId]->phy->GetPhyBand() == WIFI_PHY_BAND_2_4GHZ,
                    linkId);

    ConfigureContentionWindow(cwmin, cwmax);
}

Ptr<FrameExchangeManager>
WifiMac::SetupFrameExchangeManager(WifiStandard standard)
{
    NS_LOG_FUNCTION(this << standard);
    NS_ABORT_MSG_IF(standard == WIFI_STANDARD_UNSPECIFIED, "Wifi standard not set");
    Ptr<FrameExchangeManager> feManager;

    if (standard >= WIFI_STANDARD_80211be)
    {
        feManager = CreateObject<EhtFrameExchangeManager>();
    }
    else if (standard >= WIFI_STANDARD_80211ax)
    {
        feManager = CreateObject<HeFrameExchangeManager>();
    }
    else if (standard >= WIFI_STANDARD_80211ac)
    {
        feManager = CreateObject<VhtFrameExchangeManager>();
    }
    else if (standard >= WIFI_STANDARD_80211n)
    {
        feManager = CreateObject<HtFrameExchangeManager>();
    }
    else if (m_qosSupported)
    {
        feManager = CreateObject<QosFrameExchangeManager>();
    }
    else
    {
        feManager = CreateObject<FrameExchangeManager>();
    }

    feManager->SetMacTxMiddle(m_txMiddle);
    feManager->SetMacRxMiddle(m_rxMiddle);
    feManager->SetAddress(GetAddress());
    feManager->GetWifiTxTimer().SetMpduResponseTimeoutCallback(
        MakeCallback(&MpduResponseTimeoutTracedCallback::operator(),
                     &m_mpduResponseTimeoutCallback));
    feManager->GetWifiTxTimer().SetPsduResponseTimeoutCallback(
        MakeCallback(&PsduResponseTimeoutTracedCallback::operator(),
                     &m_psduResponseTimeoutCallback));
    feManager->GetWifiTxTimer().SetPsduMapResponseTimeoutCallback(
        MakeCallback(&PsduMapResponseTimeoutTracedCallback::operator(),
                     &m_psduMapResponseTimeoutCallback));
    feManager->SetDroppedMpduCallback(
        MakeCallback(&DroppedMpduTracedCallback::operator(), &m_droppedMpduCallback));
    feManager->SetAckedMpduCallback(
        MakeCallback(&MpduTracedCallback::operator(), &m_ackedMpduCallback));
    return feManager;
}

Ptr<FrameExchangeManager>
WifiMac::GetFrameExchangeManager(uint8_t linkId) const
{
    return GetLink(linkId).feManager;
}

Ptr<ChannelAccessManager>
WifiMac::GetChannelAccessManager(uint8_t linkId) const
{
    return GetLink(linkId).channelAccessManager;
}

void
WifiMac::SetWifiRemoteStationManager(const Ptr<WifiRemoteStationManager> stationManager)
{
    NS_LOG_FUNCTION(this << stationManager);
    SetWifiRemoteStationManagers({stationManager});
}

void
WifiMac::SetWifiRemoteStationManagers(
    const std::vector<Ptr<WifiRemoteStationManager>>& stationManagers)
{
    NS_LOG_FUNCTION(this);

    NS_ABORT_MSG_UNLESS(m_links.empty() || m_links.size() == stationManagers.size(),
                        "If links have been already created, the number of provided "
                        "Remote Manager objects ("
                            << stationManagers.size()
                            << ") must "
                               "match the number of links ("
                            << m_links.size() << ")");

    for (std::size_t i = 0; i < stationManagers.size(); i++)
    {
        // the link may already exist in case PHY objects were configured first
        auto [it, inserted] = m_links.emplace(i, CreateLinkEntity());
        m_linkIds.insert(i);
        it->second->stationManager = stationManagers[i];
    }
}

Ptr<WifiRemoteStationManager>
WifiMac::GetWifiRemoteStationManager(uint8_t linkId) const
{
    return GetLink(linkId).stationManager;
}

std::unique_ptr<WifiMac::LinkEntity>
WifiMac::CreateLinkEntity() const
{
    return std::make_unique<LinkEntity>();
}

const std::map<uint8_t, std::unique_ptr<WifiMac::LinkEntity>>&
WifiMac::GetLinks() const
{
    return m_links;
}

WifiMac::LinkEntity&
WifiMac::GetLink(uint8_t linkId) const
{
    auto it = m_links.find(linkId);
    NS_ASSERT(it != m_links.cend());
    NS_ASSERT(it->second); // check that the pointer owns an object
    return *it->second;
}

uint8_t
WifiMac::GetNLinks() const
{
    return m_links.size();
}

const std::set<uint8_t>&
WifiMac::GetLinkIds() const
{
    return m_linkIds;
}

void
WifiMac::UpdateLinkId(uint8_t id)
{
    NS_LOG_FUNCTION(this << id);

    auto& link = GetLink(id);
    if (link.feManager)
    {
        link.feManager->SetLinkId(id);
    }
    if (link.channelAccessManager)
    {
        link.channelAccessManager->SetLinkId(id);
    }
}

std::optional<uint8_t>
WifiMac::GetLinkIdByAddress(const Mac48Address& address) const
{
    for (const auto& [id, link] : m_links)
    {
        if (link->feManager->GetAddress() == address)
        {
            return id;
        }
    }
    return std::nullopt;
}

std::optional<uint8_t>
WifiMac::GetLinkForPhy(Ptr<const WifiPhy> phy) const
{
    for (const auto& [id, link] : m_links)
    {
        if (link->phy == phy)
        {
            return id;
        }
    }
    return std::nullopt;
}

std::optional<uint8_t>
WifiMac::GetLinkForPhy(std::size_t phyId) const
{
    NS_ABORT_UNLESS(phyId < m_device->GetNPhys());
    auto phy = m_device->GetPhy(phyId);
    return GetLinkForPhy(phy);
}

void
WifiMac::SwapLinks(std::map<uint8_t, uint8_t> links)
{
    NS_LOG_FUNCTION(this);

    std::map<uint8_t, uint8_t> actualPairs;

    while (!links.empty())
    {
        auto from = links.cbegin()->first;
        auto to = links.cbegin()->second;

        if (from == to)
        {
            // nothing to do
            links.erase(links.cbegin());
            continue;
        }

        std::unique_ptr<LinkEntity> linkToMove;
        NS_ASSERT(m_links.find(from) != m_links.cend());
        linkToMove.swap(m_links.at(from)); // from is now out of m_links
        auto empty = from;                 // track empty cell in m_links

        do
        {
            auto [it, inserted] =
                m_links.emplace(to, nullptr); // insert an element with key to if not present
            m_links[to].swap(linkToMove);     // to is the link to move now
            actualPairs.emplace(from, to);
            UpdateLinkId(to);
            links.erase(from);
            if (!linkToMove)
            {
                if (inserted)
                {
                    m_links.erase(empty);
                }
                break;
            }

            auto nextTo = links.find(to);
            if (nextTo == links.cend())
            {
                // no new position specified for 'to', use the current empty cell
                m_links[empty].swap(linkToMove);
                actualPairs.emplace(to, empty);
                break;
            }

            from = to;
            to = nextTo->second;
        } while (true);
    }

    m_linkIds.clear();
    for (const auto& [id, link] : m_links)
    {
        m_linkIds.insert(id);
    }

    if (m_txop)
    {
        m_txop->SwapLinks(actualPairs);
    }
    for (auto& [ac, edca] : m_edca)
    {
        edca->SwapLinks(actualPairs);
    }
}

void
WifiMac::UpdateTidToLinkMapping(const Mac48Address& mldAddr,
                                WifiDirection dir,
                                const WifiTidLinkMapping& mapping)
{
    NS_LOG_FUNCTION(this << mldAddr);

    NS_ABORT_MSG_IF(dir == WifiDirection::BOTH_DIRECTIONS,
                    "DL and UL directions for TID-to-Link mapping must be set separately");

    auto& mappings = (dir == WifiDirection::DOWNLINK ? m_dlTidLinkMappings : m_ulTidLinkMappings);

    auto [it, inserted] = mappings.emplace(mldAddr, mapping);

    if (inserted)
    {
        // we are done
        return;
    }

    // a previous mapping is stored for this MLD
    if (mapping.empty())
    {
        // the default mapping has been now negotiated
        it->second.clear();
        return;
    }

    for (const auto& [tid, linkSet] : mapping)
    {
        it->second[tid] = linkSet;
    }
}

std::optional<std::reference_wrapper<const WifiTidLinkMapping>>
WifiMac::GetTidToLinkMapping(Mac48Address mldAddr, WifiDirection dir) const
{
    NS_ABORT_MSG_IF(dir == WifiDirection::BOTH_DIRECTIONS,
                    "Cannot request TID-to-Link mapping for both directions");

    const auto& mappings =
        (dir == WifiDirection::DOWNLINK ? m_dlTidLinkMappings : m_ulTidLinkMappings);

    if (const auto it = mappings.find(mldAddr); it != mappings.cend())
    {
        return it->second;
    }
    return std::nullopt;
}

bool
WifiMac::TidMappedOnLink(Mac48Address mldAddr, WifiDirection dir, uint8_t tid, uint8_t linkId) const
{
    NS_ABORT_MSG_IF(dir == WifiDirection::BOTH_DIRECTIONS,
                    "Cannot request TID-to-Link mapping for both directions");

    const auto& mappings =
        (dir == WifiDirection::DOWNLINK ? m_dlTidLinkMappings : m_ulTidLinkMappings);

    const auto it = mappings.find(mldAddr);

    if (it == mappings.cend())
    {
        // TID-to-link mapping was not negotiated, TIDs are mapped to all setup links
        return GetWifiRemoteStationManager(linkId)->GetMldAddress(mldAddr).has_value();
    }

    auto linkSetIt = it->second.find(tid);

    if (linkSetIt == it->second.cend())
    {
        // If there is no successfully negotiated TID-to-link mapping for a TID, then the TID
        // is mapped to all setup links for DL and UL (Sec. 35.3.7.1.3 of 802.11be D3.1)
        return GetWifiRemoteStationManager(linkId)->GetMldAddress(mldAddr).has_value();
    }

    return std::find(linkSetIt->second.cbegin(), linkSetIt->second.cend(), linkId) !=
           linkSetIt->second.cend();
}

void
WifiMac::SetWifiPhys(const std::vector<Ptr<WifiPhy>>& phys)
{
    NS_LOG_FUNCTION(this);
    ResetWifiPhys();

    NS_ABORT_MSG_UNLESS(m_links.empty() || m_links.size() == phys.size(),
                        "If links have been already created, the number of provided "
                        "PHY objects ("
                            << phys.size()
                            << ") must match the number "
                               "of links ("
                            << m_links.size() << ")");

    for (std::size_t i = 0; i < phys.size(); i++)
    {
        // the link may already exist in case we are setting new PHY objects
        // (ResetWifiPhys just nullified the PHY(s) but left the links)
        // or the remote station managers were configured first
        auto [it, inserted] = m_links.emplace(i, CreateLinkEntity());
        m_linkIds.insert(i);
        it->second->phy = phys[i];
    }
}

Ptr<WifiPhy>
WifiMac::GetWifiPhy(uint8_t linkId) const
{
    return GetLink(linkId).phy;
}

void
WifiMac::ResetWifiPhys()
{
    NS_LOG_FUNCTION(this);
    for (auto& [id, link] : m_links)
    {
        if (link->feManager)
        {
            link->feManager->ResetPhy();
        }
        if (link->channelAccessManager)
        {
            link->channelAccessManager->RemovePhyListener(link->phy);
        }
        link->phy = nullptr;
    }
}

void
WifiMac::SetQosSupported(bool enable)
{
    NS_LOG_FUNCTION(this << enable);
    NS_ABORT_IF(IsInitialized());
    m_qosSupported = enable;

    if (!m_qosSupported)
    {
        // create a non-QoS TXOP
        m_txop = CreateObject<Txop>();
        m_txop->SetTxMiddle(m_txMiddle);
        m_txop->SetDroppedMpduCallback(
            MakeCallback(&DroppedMpduTracedCallback::operator(), &m_droppedMpduCallback));
    }
    else
    {
        // Construct the EDCAFs. The ordering is important - highest
        // priority (Table 9-1 UP-to-AC mapping; IEEE 802.11-2012) must be created
        // first.
        SetupEdcaQueue(AC_VO);
        SetupEdcaQueue(AC_VI);
        SetupEdcaQueue(AC_BE);
        SetupEdcaQueue(AC_BK);
    }
}

bool
WifiMac::GetQosSupported() const
{
    return m_qosSupported;
}

bool
WifiMac::GetErpSupported(uint8_t linkId) const
{
    return GetLink(linkId).erpSupported;
}

void
WifiMac::SetErpSupported(bool enable, uint8_t linkId)
{
    NS_LOG_FUNCTION(this << enable << +linkId);
    if (enable)
    {
        SetDsssSupported(true, linkId);
    }
    GetLink(linkId).erpSupported = enable;
}

void
WifiMac::SetDsssSupported(bool enable, uint8_t linkId)
{
    NS_LOG_FUNCTION(this << enable << +linkId);
    GetLink(linkId).dsssSupported = enable;
}

bool
WifiMac::GetDsssSupported(uint8_t linkId) const
{
    return GetLink(linkId).dsssSupported;
}

void
WifiMac::SetCtsToSelfSupported(bool enable)
{
    NS_LOG_FUNCTION(this);
    m_ctsToSelfSupported = enable;
}

void
WifiMac::SetShortSlotTimeSupported(bool enable)
{
    NS_LOG_FUNCTION(this << enable);
    m_shortSlotTimeSupported = enable;
}

bool
WifiMac::GetShortSlotTimeSupported() const
{
    return m_shortSlotTimeSupported;
}

bool
WifiMac::SupportsSendFrom() const
{
    return false;
}

void
WifiMac::SetForwardUpCallback(ForwardUpCallback upCallback)
{
    NS_LOG_FUNCTION(this);
    m_forwardUp = upCallback;
}

void
WifiMac::SetLinkUpCallback(Callback<void> linkUp)
{
    NS_LOG_FUNCTION(this);
    m_linkUp = linkUp;
}

void
WifiMac::SetLinkDownCallback(Callback<void> linkDown)
{
    NS_LOG_FUNCTION(this);
    m_linkDown = linkDown;
}

void
WifiMac::ApplyTidLinkMapping(const Mac48Address& mldAddr, WifiDirection dir)
{
    NS_LOG_FUNCTION(this << mldAddr);

    NS_ABORT_MSG_IF(
        dir == WifiDirection::BOTH_DIRECTIONS,
        "This method can be used to enforce TID-to-Link mapping for one direction at a time");

    const auto& mappings =
        (dir == WifiDirection::DOWNLINK ? m_dlTidLinkMappings : m_ulTidLinkMappings);

    auto it = mappings.find(mldAddr);

    if (it == mappings.cend())
    {
        // no mapping has been ever negotiated with the given MLD, the default mapping is used
        return;
    }

    std::set<uint8_t> setupLinks;

    // find the IDs of the links setup with the given MLD
    for (const auto& [id, link] : m_links)
    {
        if (link->stationManager->GetMldAddress(mldAddr))
        {
            setupLinks.insert(id);
        }
    }

    auto linkMapping = it->second;

    if (linkMapping.empty())
    {
        // default link mapping, each TID mapped on all setup links
        for (uint8_t tid = 0; tid < 8; tid++)
        {
            linkMapping.emplace(tid, setupLinks);
        }
    }

    for (const auto& [tid, linkSet] : linkMapping)
    {
        decltype(setupLinks) mappedLinks; // empty
        auto notMappedLinks = setupLinks; // all setup links

        for (const auto id : linkSet)
        {
            if (setupLinks.find(id) != setupLinks.cend())
            {
                // link is mapped
                mappedLinks.insert(id);
                notMappedLinks.erase(id);
            }
        }

        // unblock mapped links
        NS_ABORT_MSG_IF(mappedLinks.empty(), "Every TID must be mapped to at least a link");

        m_scheduler->UnblockQueues(WifiQueueBlockedReason::TID_NOT_MAPPED,
                                   QosUtilsMapTidToAc(tid),
                                   {WIFI_QOSDATA_QUEUE},
                                   mldAddr,
                                   GetAddress(),
                                   {tid},
                                   mappedLinks);

        // block unmapped links
        if (!notMappedLinks.empty())
        {
            m_scheduler->BlockQueues(WifiQueueBlockedReason::TID_NOT_MAPPED,
                                     QosUtilsMapTidToAc(tid),
                                     {WIFI_QOSDATA_QUEUE},
                                     mldAddr,
                                     GetAddress(),
                                     {tid},
                                     notMappedLinks);
        }
    }
}

void
WifiMac::BlockUnicastTxOnLinks(WifiQueueBlockedReason reason,
                               const Mac48Address& address,
                               const std::set<uint8_t>& linkIds)
{
    NS_LOG_FUNCTION(this << reason << address);
    NS_ASSERT(m_scheduler);

    for (const auto linkId : linkIds)
    {
        auto& link = GetLink(linkId);
        auto linkAddr = link.stationManager->GetAffiliatedStaAddress(address).value_or(address);

        if (link.stationManager->GetMldAddress(address) == address && linkAddr == address)
        {
            NS_LOG_DEBUG("Link " << +linkId << " has not been setup with the MLD, skip");
            continue;
        }

        for (const auto& [acIndex, ac] : wifiAcList)
        {
            // block queues storing QoS data frames and control frames that use MLD addresses
            m_scheduler->BlockQueues(reason,
                                     acIndex,
                                     {WIFI_QOSDATA_QUEUE, WIFI_CTL_QUEUE},
                                     address,
                                     GetAddress(),
                                     {ac.GetLowTid(), ac.GetHighTid()},
                                     {linkId});
            // block queues storing management and control frames that use link addresses
            m_scheduler->BlockQueues(reason,
                                     acIndex,
                                     {WIFI_MGT_QUEUE, WIFI_CTL_QUEUE},
                                     linkAddr,
                                     link.feManager->GetAddress(),
                                     {},
                                     {linkId});
        }
    }
}

void
WifiMac::UnblockUnicastTxOnLinks(WifiQueueBlockedReason reason,
                                 const Mac48Address& address,
                                 const std::set<uint8_t>& linkIds)
{
    NS_LOG_FUNCTION(this << reason << address);
    NS_ASSERT(m_scheduler);

    for (const auto linkId : linkIds)
    {
        auto& link = GetLink(linkId);
        auto linkAddr = link.stationManager->GetAffiliatedStaAddress(address).value_or(address);

        if (link.stationManager->GetMldAddress(address) == address && linkAddr == address)
        {
            NS_LOG_DEBUG("Link " << +linkId << " has not been setup with the MLD, skip");
            continue;
        }

        for (const auto& [acIndex, ac] : wifiAcList)
        {
            // save the status of the AC queues before unblocking the requested queues
            auto hasFramesToTransmit = GetQosTxop(acIndex)->HasFramesToTransmit(linkId);

            // unblock queues storing QoS data frames and control frames that use MLD addresses
            m_scheduler->UnblockQueues(reason,
                                       acIndex,
                                       {WIFI_QOSDATA_QUEUE, WIFI_CTL_QUEUE},
                                       address,
                                       GetAddress(),
                                       {ac.GetLowTid(), ac.GetHighTid()},
                                       {linkId});
            // unblock queues storing management and control frames that use link addresses
            m_scheduler->UnblockQueues(reason,
                                       acIndex,
                                       {WIFI_MGT_QUEUE, WIFI_CTL_QUEUE},
                                       linkAddr,
                                       link.feManager->GetAddress(),
                                       {},
                                       {linkId});
            // request channel access if needed (schedule now because multiple invocations
            // of this method may be done in a loop at the caller)
            Simulator::ScheduleNow(&Txop::StartAccessAfterEvent,
                                   GetQosTxop(acIndex),
                                   linkId,
                                   hasFramesToTransmit,
                                   Txop::CHECK_MEDIUM_BUSY); // generate backoff if medium busy
        }
    }
}

void
WifiMac::Enqueue(Ptr<Packet> packet, Mac48Address to, Mac48Address from)
{
    // We expect WifiMac subclasses which do support forwarding (e.g.,
    // AP) to override this method. Therefore, we throw a fatal error if
    // someone tries to invoke this method on a class which has not done
    // this.
    NS_FATAL_ERROR("This MAC entity (" << this << ", " << GetAddress()
                                       << ") does not support Enqueue() with from address");
}

void
WifiMac::ForwardUp(Ptr<const Packet> packet, Mac48Address from, Mac48Address to)
{
    NS_LOG_FUNCTION(this << packet << from << to);
    m_forwardUp(packet, from, to);
}

void
WifiMac::Receive(Ptr<const WifiMpdu> mpdu, uint8_t linkId)
{
    NS_LOG_FUNCTION(this << *mpdu << linkId);

    const WifiMacHeader* hdr = &mpdu->GetOriginal()->GetHeader();
    Mac48Address to = hdr->GetAddr1();
    Mac48Address from = hdr->GetAddr2();
    auto myAddr = hdr->IsData() ? Mac48Address::ConvertFrom(GetDevice()->GetAddress())
                                : GetFrameExchangeManager(linkId)->GetAddress();

    // We don't know how to deal with any frame that is not addressed to
    // us (and odds are there is nothing sensible we could do anyway),
    // so we ignore such frames.
    //
    // The derived class may also do some such filtering, but it doesn't
    // hurt to have it here too as a backstop.
    if (to != myAddr)
    {
        return;
    }

    // Nothing to do with (QoS) Null Data frames
    if (hdr->IsData() && !hdr->HasData())
    {
        return;
    }

    if (hdr->IsMgt() && hdr->IsAction())
    {
        // There is currently only any reason for Management Action
        // frames to be flying about if we are a QoS STA.
        NS_ASSERT(GetQosSupported());

        auto& link = GetLink(linkId);
        WifiActionHeader actionHdr;
        Ptr<Packet> packet = mpdu->GetPacket()->Copy();
        packet->RemoveHeader(actionHdr);

        switch (actionHdr.GetCategory())
        {
        case WifiActionHeader::BLOCK_ACK:

            switch (actionHdr.GetAction().blockAck)
            {
            case WifiActionHeader::BLOCK_ACK_ADDBA_REQUEST: {
                MgtAddBaRequestHeader reqHdr;
                packet->RemoveHeader(reqHdr);

                // We've received an ADDBA Request. Our policy here is
                // to automatically accept it, so we get the ADDBA
                // Response on it's way immediately.
                NS_ASSERT(link.feManager);
                auto htFem = DynamicCast<HtFrameExchangeManager>(link.feManager);
                if (htFem)
                {
                    htFem->SendAddBaResponse(&reqHdr, from);
                }
                // This frame is now completely dealt with, so we're done.
                return;
            }
            case WifiActionHeader::BLOCK_ACK_ADDBA_RESPONSE: {
                MgtAddBaResponseHeader respHdr;
                packet->RemoveHeader(respHdr);

                // We've received an ADDBA Response. We assume that it
                // indicates success after an ADDBA Request we have
                // sent (we could, in principle, check this, but it
                // seems a waste given the level of the current model)
                // and act by locally establishing the agreement on
                // the appropriate queue.
                auto recipientMld = link.stationManager->GetMldAddress(from);
                auto recipient = (recipientMld ? *recipientMld : from);
                GetQosTxop(respHdr.GetTid())->GotAddBaResponse(respHdr, recipient);
                auto htFem = DynamicCast<HtFrameExchangeManager>(link.feManager);
                if (htFem)
                {
                    GetQosTxop(respHdr.GetTid())
                        ->GetBaManager()
                        ->SetBlockAckInactivityCallback(
                            MakeCallback(&HtFrameExchangeManager::SendDelbaFrame, htFem));
                }
                // This frame is now completely dealt with, so we're done.
                return;
            }
            case WifiActionHeader::BLOCK_ACK_DELBA: {
                MgtDelBaHeader delBaHdr;
                packet->RemoveHeader(delBaHdr);
                auto recipientMld = link.stationManager->GetMldAddress(from);
                auto recipient = (recipientMld ? *recipientMld : from);

                if (delBaHdr.IsByOriginator())
                {
                    // This DELBA frame was sent by the originator, so
                    // this means that an ingoing established
                    // agreement exists in BlockAckManager and we need to
                    // destroy it.
                    GetQosTxop(delBaHdr.GetTid())
                        ->GetBaManager()
                        ->DestroyRecipientAgreement(recipient, delBaHdr.GetTid());
                }
                else
                {
                    // We must have been the originator. We need to
                    // tell the correct queue that the agreement has
                    // been torn down
                    GetQosTxop(delBaHdr.GetTid())->GotDelBaFrame(&delBaHdr, recipient);
                }
                // This frame is now completely dealt with, so we're done.
                return;
            }
            default:
                NS_FATAL_ERROR("Unsupported Action field in Block Ack Action frame");
                return;
            }
        default:
            NS_FATAL_ERROR("Unsupported Action frame received");
            return;
        }
    }
    NS_FATAL_ERROR("Don't know how to handle frame (type=" << hdr->GetType());
}

void
WifiMac::DeaggregateAmsduAndForward(Ptr<const WifiMpdu> mpdu)
{
    NS_LOG_FUNCTION(this << *mpdu);
    for (auto& msduPair : *PeekPointer(mpdu))
    {
        ForwardUp(msduPair.first,
                  msduPair.second.GetSourceAddr(),
                  msduPair.second.GetDestinationAddr());
    }
}

std::optional<Mac48Address>
WifiMac::GetMldAddress(const Mac48Address& remoteAddr) const
{
    for (const auto& [id, link] : m_links)
    {
        if (auto mldAddress = link->stationManager->GetMldAddress(remoteAddr))
        {
            return *mldAddress;
        }
    }
    return std::nullopt;
}

Mac48Address
WifiMac::GetLocalAddress(const Mac48Address& remoteAddr) const
{
    for (const auto& [id, link] : m_links)
    {
        if (auto mldAddress = link->stationManager->GetMldAddress(remoteAddr))
        {
            // this is a link setup with remote MLD
            if (mldAddress != remoteAddr)
            {
                // the remote address is the address of a STA affiliated with the remote MLD
                return link->feManager->GetAddress();
            }
            // we have to return our MLD address
            return m_address;
        }
    }
    // we get here if no ML setup was established between this device and the remote device,
    // i.e., they are not both multi-link devices
    if (GetNLinks() == 1)
    {
        // this is a single link device
        return m_address;
    }
    // this is an MLD (hence the remote device is single link)
    return DoGetLocalAddress(remoteAddr);
}

Mac48Address
WifiMac::DoGetLocalAddress(const Mac48Address& remoteAddr [[maybe_unused]]) const
{
    return m_address;
}

WifiMac::OriginatorAgreementOptConstRef
WifiMac::GetBaAgreementEstablishedAsOriginator(Mac48Address recipient, uint8_t tid) const
{
    // BA agreements are indexed by the MLD address if ML setup was performed
    recipient = GetMldAddress(recipient).value_or(recipient);

    auto agreement = GetQosTxop(tid)->GetBaManager()->GetAgreementAsOriginator(recipient, tid);
    if (!agreement || !agreement->get().IsEstablished())
    {
        return std::nullopt;
    }
    return agreement;
}

WifiMac::RecipientAgreementOptConstRef
WifiMac::GetBaAgreementEstablishedAsRecipient(Mac48Address originator, uint8_t tid) const
{
    // BA agreements are indexed by the MLD address if ML setup was performed
    originator = GetMldAddress(originator).value_or(originator);
    return GetQosTxop(tid)->GetBaManager()->GetAgreementAsRecipient(originator, tid);
}

BlockAckType
WifiMac::GetBaTypeAsOriginator(const Mac48Address& recipient, uint8_t tid) const
{
    auto agreement = GetBaAgreementEstablishedAsOriginator(recipient, tid);
    NS_ABORT_MSG_IF(!agreement,
                    "No existing Block Ack agreement with " << recipient << " TID: " << +tid);
    return agreement->get().GetBlockAckType();
}

BlockAckReqType
WifiMac::GetBarTypeAsOriginator(const Mac48Address& recipient, uint8_t tid) const
{
    auto agreement = GetBaAgreementEstablishedAsOriginator(recipient, tid);
    NS_ABORT_MSG_IF(!agreement,
                    "No existing Block Ack agreement with " << recipient << " TID: " << +tid);
    return agreement->get().GetBlockAckReqType();
}

BlockAckType
WifiMac::GetBaTypeAsRecipient(Mac48Address originator, uint8_t tid) const
{
    auto agreement = GetBaAgreementEstablishedAsRecipient(originator, tid);
    NS_ABORT_MSG_IF(!agreement,
                    "No existing Block Ack agreement with " << originator << " TID: " << +tid);
    return agreement->get().GetBlockAckType();
}

BlockAckReqType
WifiMac::GetBarTypeAsRecipient(Mac48Address originator, uint8_t tid) const
{
    auto agreement = GetBaAgreementEstablishedAsRecipient(originator, tid);
    NS_ABORT_MSG_IF(!agreement,
                    "No existing Block Ack agreement with " << originator << " TID: " << +tid);
    return agreement->get().GetBlockAckReqType();
}

Ptr<HtConfiguration>
WifiMac::GetHtConfiguration() const
{
    return GetDevice()->GetHtConfiguration();
}

Ptr<VhtConfiguration>
WifiMac::GetVhtConfiguration() const
{
    return GetDevice()->GetVhtConfiguration();
}

Ptr<HeConfiguration>
WifiMac::GetHeConfiguration() const
{
    return GetDevice()->GetHeConfiguration();
}

Ptr<EhtConfiguration>
WifiMac::GetEhtConfiguration() const
{
    return GetDevice()->GetEhtConfiguration();
}

bool
WifiMac::GetHtSupported() const
{
    return bool(GetDevice()->GetHtConfiguration());
}

bool
WifiMac::GetVhtSupported(uint8_t linkId) const
{
    return (GetDevice()->GetVhtConfiguration() &&
            GetWifiPhy(linkId)->GetPhyBand() != WIFI_PHY_BAND_2_4GHZ);
}

bool
WifiMac::GetHeSupported() const
{
    return bool(GetDevice()->GetHeConfiguration());
}

bool
WifiMac::GetEhtSupported() const
{
    return bool(GetDevice()->GetEhtConfiguration());
}

bool
WifiMac::GetHtSupported(const Mac48Address& address) const
{
    for (const auto& [id, link] : m_links)
    {
        if (link->stationManager->GetHtSupported(address))
        {
            return true;
        }
    }
    return false;
}

bool
WifiMac::GetVhtSupported(const Mac48Address& address) const
{
    for (const auto& [id, link] : m_links)
    {
        if (link->stationManager->GetVhtSupported(address))
        {
            return true;
        }
    }
    return false;
}

bool
WifiMac::GetHeSupported(const Mac48Address& address) const
{
    for (const auto& [id, link] : m_links)
    {
        if (link->stationManager->GetHeSupported(address))
        {
            return true;
        }
    }
    return false;
}

bool
WifiMac::GetEhtSupported(const Mac48Address& address) const
{
    for (const auto& [id, link] : m_links)
    {
        if (link->stationManager->GetEhtSupported(address))
        {
            return true;
        }
    }
    return false;
}

uint16_t
WifiMac::GetMaxBaBufferSize(std::optional<Mac48Address> address) const
{
    if (address ? GetEhtSupported(*address) : GetEhtSupported())
    {
        return 1024;
    }
    if (address ? GetHeSupported(*address) : GetHeSupported())
    {
        return 256;
    }
    NS_ASSERT(address ? GetHtSupported(*address) : GetHtSupported());
    return 64;
}

void
WifiMac::SetMpduBufferSize(uint16_t size)
{
    NS_LOG_FUNCTION(this << size);

    // the cap can be computed if the device has been configured
    m_mpduBufferSize = m_device ? std::min(size, GetMaxBaBufferSize()) : size;
}

uint16_t
WifiMac::GetMpduBufferSize() const
{
    return m_mpduBufferSize;
}

void
WifiMac::SetVoBlockAckThreshold(uint8_t threshold)
{
    NS_LOG_FUNCTION(this << +threshold);
    if (m_qosSupported)
    {
        GetVOQueue()->SetBlockAckThreshold(threshold);
    }
}

void
WifiMac::SetViBlockAckThreshold(uint8_t threshold)
{
    NS_LOG_FUNCTION(this << +threshold);
    if (m_qosSupported)
    {
        GetVIQueue()->SetBlockAckThreshold(threshold);
    }
}

void
WifiMac::SetBeBlockAckThreshold(uint8_t threshold)
{
    NS_LOG_FUNCTION(this << +threshold);
    if (m_qosSupported)
    {
        GetBEQueue()->SetBlockAckThreshold(threshold);
    }
}

void
WifiMac::SetBkBlockAckThreshold(uint8_t threshold)
{
    NS_LOG_FUNCTION(this << +threshold);
    if (m_qosSupported)
    {
        GetBKQueue()->SetBlockAckThreshold(threshold);
    }
}

void
WifiMac::SetVoBlockAckInactivityTimeout(uint16_t timeout)
{
    NS_LOG_FUNCTION(this << timeout);
    if (m_qosSupported)
    {
        GetVOQueue()->SetBlockAckInactivityTimeout(timeout);
    }
}

void
WifiMac::SetViBlockAckInactivityTimeout(uint16_t timeout)
{
    NS_LOG_FUNCTION(this << timeout);
    if (m_qosSupported)
    {
        GetVIQueue()->SetBlockAckInactivityTimeout(timeout);
    }
}

void
WifiMac::SetBeBlockAckInactivityTimeout(uint16_t timeout)
{
    NS_LOG_FUNCTION(this << timeout);
    if (m_qosSupported)
    {
        GetBEQueue()->SetBlockAckInactivityTimeout(timeout);
    }
}

void
WifiMac::SetBkBlockAckInactivityTimeout(uint16_t timeout)
{
    NS_LOG_FUNCTION(this << timeout);
    if (m_qosSupported)
    {
        GetBKQueue()->SetBlockAckInactivityTimeout(timeout);
    }
}

ExtendedCapabilities
WifiMac::GetExtendedCapabilities() const
{
    NS_LOG_FUNCTION(this);
    ExtendedCapabilities capabilities;
    capabilities.SetHtSupported(GetHtSupported());
    capabilities.SetVhtSupported(GetVhtSupported(SINGLE_LINK_OP_ID));
    // TODO: to be completed
    return capabilities;
}

HtCapabilities
WifiMac::GetHtCapabilities(uint8_t linkId) const
{
    NS_LOG_FUNCTION(this << +linkId);
    NS_ASSERT(GetHtSupported());
    HtCapabilities capabilities;

    auto phy = GetWifiPhy(linkId);
    Ptr<HtConfiguration> htConfiguration = GetHtConfiguration();
    bool sgiSupported = htConfiguration->GetShortGuardIntervalSupported();
    capabilities.SetLdpc(htConfiguration->GetLdpcSupported());
    capabilities.SetSupportedChannelWidth(htConfiguration->Get40MHzOperationSupported() ? 1 : 0);
    capabilities.SetShortGuardInterval20(sgiSupported);
    capabilities.SetShortGuardInterval40(sgiSupported);
    // Set Maximum A-MSDU Length subfield
    uint16_t maxAmsduSize =
        std::max({m_voMaxAmsduSize, m_viMaxAmsduSize, m_beMaxAmsduSize, m_bkMaxAmsduSize});
    if (maxAmsduSize <= 3839)
    {
        capabilities.SetMaxAmsduLength(3839);
    }
    else
    {
        capabilities.SetMaxAmsduLength(7935);
    }
    uint32_t maxAmpduLength =
        std::max({m_voMaxAmpduSize, m_viMaxAmpduSize, m_beMaxAmpduSize, m_bkMaxAmpduSize});
    // round to the next power of two minus one
    maxAmpduLength = (1UL << static_cast<uint32_t>(std::ceil(std::log2(maxAmpduLength + 1)))) - 1;
    // The maximum A-MPDU length in HT capabilities elements ranges from 2^13-1 to 2^16-1
    capabilities.SetMaxAmpduLength(std::min(std::max(maxAmpduLength, 8191U), 65535U));

    capabilities.SetLSigProtectionSupport(true);
    uint64_t maxSupportedRate = 0; // in bit/s
    for (const auto& mcs : phy->GetMcsList(WIFI_MOD_CLASS_HT))
    {
        capabilities.SetRxMcsBitmask(mcs.GetMcsValue());
        uint8_t nss = (mcs.GetMcsValue() / 8) + 1;
        NS_ASSERT(nss > 0 && nss < 5);
        uint64_t dataRate = mcs.GetDataRate(htConfiguration->Get40MHzOperationSupported() ? 40 : 20,
                                            sgiSupported ? 400 : 800,
                                            nss);
        if (dataRate > maxSupportedRate)
        {
            maxSupportedRate = dataRate;
            NS_LOG_DEBUG("Updating maxSupportedRate to " << maxSupportedRate);
        }
    }
    capabilities.SetRxHighestSupportedDataRate(
        static_cast<uint16_t>(maxSupportedRate / 1e6)); // in Mbit/s
    capabilities.SetTxMcsSetDefined(phy->GetNMcs() > 0);
    capabilities.SetTxMaxNSpatialStreams(phy->GetMaxSupportedTxSpatialStreams());
    // we do not support unequal modulations
    capabilities.SetTxRxMcsSetUnequal(0);
    capabilities.SetTxUnequalModulation(0);

    return capabilities;
}

VhtCapabilities
WifiMac::GetVhtCapabilities(uint8_t linkId) const
{
    NS_LOG_FUNCTION(this << +linkId);
    NS_ASSERT(GetVhtSupported(linkId));
    VhtCapabilities capabilities;

    auto phy = GetWifiPhy(linkId);
    Ptr<HtConfiguration> htConfiguration = GetHtConfiguration();
    NS_ABORT_MSG_IF(!htConfiguration->Get40MHzOperationSupported(),
                    "VHT stations have to support 40 MHz operation");
    Ptr<VhtConfiguration> vhtConfiguration = GetVhtConfiguration();
    bool sgiSupported = htConfiguration->GetShortGuardIntervalSupported();
    capabilities.SetSupportedChannelWidthSet(vhtConfiguration->Get160MHzOperationSupported() ? 1
                                                                                             : 0);
    // Set Maximum MPDU Length subfield
    uint16_t maxAmsduSize =
        std::max({m_voMaxAmsduSize, m_viMaxAmsduSize, m_beMaxAmsduSize, m_bkMaxAmsduSize});
    if (maxAmsduSize <= 3839)
    {
        capabilities.SetMaxMpduLength(3895);
    }
    else if (maxAmsduSize <= 7935)
    {
        capabilities.SetMaxMpduLength(7991);
    }
    else
    {
        capabilities.SetMaxMpduLength(11454);
    }
    uint32_t maxAmpduLength =
        std::max({m_voMaxAmpduSize, m_viMaxAmpduSize, m_beMaxAmpduSize, m_bkMaxAmpduSize});
    // round to the next power of two minus one
    maxAmpduLength = (1UL << static_cast<uint32_t>(std::ceil(std::log2(maxAmpduLength + 1)))) - 1;
    // The maximum A-MPDU length in VHT capabilities elements ranges from 2^13-1 to 2^20-1
    capabilities.SetMaxAmpduLength(std::min(std::max(maxAmpduLength, 8191U), 1048575U));

    capabilities.SetRxLdpc(htConfiguration->GetLdpcSupported());
    capabilities.SetShortGuardIntervalFor80Mhz(sgiSupported);
    capabilities.SetShortGuardIntervalFor160Mhz(sgiSupported);
    uint8_t maxMcs = 0;
    for (const auto& mcs : phy->GetMcsList(WIFI_MOD_CLASS_VHT))
    {
        if (mcs.GetMcsValue() > maxMcs)
        {
            maxMcs = mcs.GetMcsValue();
        }
    }
    // Support same MaxMCS for each spatial stream
    for (uint8_t nss = 1; nss <= phy->GetMaxSupportedRxSpatialStreams(); nss++)
    {
        capabilities.SetRxMcsMap(maxMcs, nss);
    }
    for (uint8_t nss = 1; nss <= phy->GetMaxSupportedTxSpatialStreams(); nss++)
    {
        capabilities.SetTxMcsMap(maxMcs, nss);
    }
    uint64_t maxSupportedRateLGI = 0; // in bit/s
    uint16_t maxWidth = vhtConfiguration->Get160MHzOperationSupported() ? 160 : 80;
    for (const auto& mcs : phy->GetMcsList(WIFI_MOD_CLASS_VHT))
    {
        if (!mcs.IsAllowed(maxWidth, 1))
        {
            continue;
        }
        if (mcs.GetDataRate(maxWidth) > maxSupportedRateLGI)
        {
            maxSupportedRateLGI = mcs.GetDataRate(maxWidth);
            NS_LOG_DEBUG("Updating maxSupportedRateLGI to " << maxSupportedRateLGI);
        }
    }
    capabilities.SetRxHighestSupportedLgiDataRate(
        static_cast<uint16_t>(maxSupportedRateLGI / 1e6)); // in Mbit/s
    capabilities.SetTxHighestSupportedLgiDataRate(
        static_cast<uint16_t>(maxSupportedRateLGI / 1e6)); // in Mbit/s
    // To be filled in once supported
    capabilities.SetRxStbc(0);
    capabilities.SetTxStbc(0);

    return capabilities;
}

HeCapabilities
WifiMac::GetHeCapabilities(uint8_t linkId) const
{
    NS_LOG_FUNCTION(this << +linkId);
    NS_ASSERT(GetHeSupported());
    HeCapabilities capabilities;

    Ptr<WifiPhy> phy = GetLink(linkId).phy;
    Ptr<HtConfiguration> htConfiguration = GetHtConfiguration();
    Ptr<VhtConfiguration> vhtConfiguration = GetVhtConfiguration();
    Ptr<HeConfiguration> heConfiguration = GetHeConfiguration();
    uint8_t channelWidthSet = 0;
    if ((htConfiguration->Get40MHzOperationSupported()) &&
        (phy->GetPhyBand() == WIFI_PHY_BAND_2_4GHZ))
    {
        channelWidthSet |= 0x01;
    }
    // we assume that HE stations support 80 MHz operations
    if ((phy->GetPhyBand() == WIFI_PHY_BAND_5GHZ) || (phy->GetPhyBand() == WIFI_PHY_BAND_6GHZ))
    {
        channelWidthSet |= 0x02;
    }
    if ((vhtConfiguration->Get160MHzOperationSupported()) &&
        ((phy->GetPhyBand() == WIFI_PHY_BAND_5GHZ) || (phy->GetPhyBand() == WIFI_PHY_BAND_6GHZ)))
    {
        channelWidthSet |= 0x04;
    }
    capabilities.SetChannelWidthSet(channelWidthSet);
    capabilities.SetLdpcCodingInPayload(htConfiguration->GetLdpcSupported());
    if (heConfiguration->GetGuardInterval() == NanoSeconds(800))
    {
        // todo: We assume for now that if we support 800ns GI then 1600ns GI is supported as well
        // todo: Assuming reception support for both 1x HE LTF and 4x HE LTF 800 ns
        capabilities.SetHeSuPpdu1xHeLtf800nsGi(true);
        capabilities.SetHePpdu4xHeLtf800nsGi(true);
    }

    uint32_t maxAmpduLength =
        std::max({m_voMaxAmpduSize, m_viMaxAmpduSize, m_beMaxAmpduSize, m_bkMaxAmpduSize});
    // round to the next power of two minus one
    maxAmpduLength = (1UL << static_cast<uint32_t>(std::ceil(std::log2(maxAmpduLength + 1)))) - 1;
    // The maximum A-MPDU length in HE capabilities elements ranges from 2^20-1 to 2^23-1
    capabilities.SetMaxAmpduLength(std::min(std::max(maxAmpduLength, 1048575U), 8388607U));

    uint8_t maxMcs = 0;
    for (const auto& mcs : phy->GetMcsList(WIFI_MOD_CLASS_HE))
    {
        if (mcs.GetMcsValue() > maxMcs)
        {
            maxMcs = mcs.GetMcsValue();
        }
    }
    capabilities.SetHighestMcsSupported(maxMcs);
    capabilities.SetHighestNssSupported(phy->GetMaxSupportedTxSpatialStreams());

    return capabilities;
}

EhtCapabilities
WifiMac::GetEhtCapabilities(uint8_t linkId) const
{
    NS_LOG_FUNCTION(this << +linkId);
    NS_ASSERT(GetEhtSupported());
    EhtCapabilities capabilities;

    Ptr<WifiPhy> phy = GetLink(linkId).phy;

    // Set Maximum MPDU Length subfield (Reserved when transmitted in 5 GHz or 6 GHz band)
    if (phy->GetPhyBand() == WIFI_PHY_BAND_2_4GHZ)
    {
        uint16_t maxAmsduSize =
            std::max({m_voMaxAmsduSize, m_viMaxAmsduSize, m_beMaxAmsduSize, m_bkMaxAmsduSize});
        // Table 9-34—Maximum data unit sizes (in octets) and durations (in microseconds)
        if (maxAmsduSize <= 3839)
        {
            capabilities.SetMaxMpduLength(3895);
        }
        else if (maxAmsduSize <= 7935)
        {
            capabilities.SetMaxMpduLength(7991);
        }
        else
        {
            capabilities.SetMaxMpduLength(11454);
        }
    }

    // Set Maximum A-MPDU Length Exponent Extension subfield
    uint32_t maxAmpduLength =
        std::max({m_voMaxAmpduSize, m_viMaxAmpduSize, m_beMaxAmpduSize, m_bkMaxAmpduSize});
    // round to the next power of two minus one
    maxAmpduLength = (1UL << static_cast<uint32_t>(std::ceil(std::log2(maxAmpduLength + 1)))) - 1;
    // The maximum A-MPDU length in EHT capabilities elements ranges from 2^23-1 to 2^24-1
    capabilities.SetMaxAmpduLength(std::min(std::max(maxAmpduLength, 8388607U), 16777215U));

    // Set the PHY capabilities
    const bool support4096Qam = phy->IsMcsSupported(WIFI_MOD_CLASS_EHT, 12);
    capabilities.m_phyCapabilities.supportTx1024And4096QamForRuSmallerThan242Tones =
        support4096Qam ? 1 : 0;
    capabilities.m_phyCapabilities.supportRx1024And4096QamForRuSmallerThan242Tones =
        support4096Qam ? 1 : 0;

    const uint8_t maxTxNss = phy->GetMaxSupportedTxSpatialStreams();
    const uint8_t maxRxNss = phy->GetMaxSupportedRxSpatialStreams();
    if (auto htConfig = GetHtConfiguration(); !htConfig->Get40MHzOperationSupported())
    {
        for (auto maxMcs : {7, 9, 11, 13})
        {
            capabilities.SetSupportedRxEhtMcsAndNss(
                EhtMcsAndNssSet::EHT_MCS_MAP_TYPE_20_MHZ_ONLY,
                maxMcs,
                phy->IsMcsSupported(WIFI_MOD_CLASS_EHT, maxMcs) ? maxRxNss : 0);
            capabilities.SetSupportedTxEhtMcsAndNss(
                EhtMcsAndNssSet::EHT_MCS_MAP_TYPE_20_MHZ_ONLY,
                maxMcs,
                phy->IsMcsSupported(WIFI_MOD_CLASS_EHT, maxMcs) ? maxTxNss : 0);
        }
    }
    else
    {
        for (auto maxMcs : {9, 11, 13})
        {
            capabilities.SetSupportedRxEhtMcsAndNss(
                EhtMcsAndNssSet::EHT_MCS_MAP_TYPE_NOT_LARGER_THAN_80_MHZ,
                maxMcs,
                phy->IsMcsSupported(WIFI_MOD_CLASS_EHT, maxMcs) ? maxRxNss : 0);
            capabilities.SetSupportedTxEhtMcsAndNss(
                EhtMcsAndNssSet::EHT_MCS_MAP_TYPE_NOT_LARGER_THAN_80_MHZ,
                maxMcs,
                phy->IsMcsSupported(WIFI_MOD_CLASS_EHT, maxMcs) ? maxTxNss : 0);
        }
    }
    if (auto vhtConfig = GetVhtConfiguration(); vhtConfig->Get160MHzOperationSupported())
    {
        for (auto maxMcs : {9, 11, 13})
        {
            capabilities.SetSupportedRxEhtMcsAndNss(
                EhtMcsAndNssSet::EHT_MCS_MAP_TYPE_160_MHZ,
                maxMcs,
                phy->IsMcsSupported(WIFI_MOD_CLASS_EHT, maxMcs) ? maxRxNss : 0);
            capabilities.SetSupportedTxEhtMcsAndNss(
                EhtMcsAndNssSet::EHT_MCS_MAP_TYPE_160_MHZ,
                maxMcs,
                phy->IsMcsSupported(WIFI_MOD_CLASS_EHT, maxMcs) ? maxTxNss : 0);
        }
    }
    // 320 MHz not supported yet

    return capabilities;
}

uint32_t
WifiMac::GetMaxAmpduSize(AcIndex ac) const
{
    uint32_t maxSize = 0;
    switch (ac)
    {
    case AC_BE:
        maxSize = m_beMaxAmpduSize;
        break;
    case AC_BK:
        maxSize = m_bkMaxAmpduSize;
        break;
    case AC_VI:
        maxSize = m_viMaxAmpduSize;
        break;
    case AC_VO:
        maxSize = m_voMaxAmpduSize;
        break;
    default:
        NS_ABORT_MSG("Unknown AC " << ac);
        return 0;
    }
    return maxSize;
}

uint16_t
WifiMac::GetMaxAmsduSize(AcIndex ac) const
{
    uint16_t maxSize = 0;
    switch (ac)
    {
    case AC_BE:
        maxSize = m_beMaxAmsduSize;
        break;
    case AC_BK:
        maxSize = m_bkMaxAmsduSize;
        break;
    case AC_VI:
        maxSize = m_viMaxAmsduSize;
        break;
    case AC_VO:
        maxSize = m_voMaxAmsduSize;
        break;
    default:
        NS_ABORT_MSG("Unknown AC " << ac);
        return 0;
    }
    return maxSize;
}

} // namespace ns3
