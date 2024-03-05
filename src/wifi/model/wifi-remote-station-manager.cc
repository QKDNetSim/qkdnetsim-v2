/*
 * Copyright (c) 2005,2006,2007 INRIA
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

#include "wifi-remote-station-manager.h"

#include "ap-wifi-mac.h"
#include "sta-wifi-mac.h"
#include "wifi-mac-header.h"
#include "wifi-mac-trailer.h"
#include "wifi-mpdu.h"
#include "wifi-net-device.h"
#include "wifi-phy.h"

#include "ns3/boolean.h"
#include "ns3/eht-configuration.h"
#include "ns3/enum.h"
#include "ns3/erp-ofdm-phy.h"
#include "ns3/he-configuration.h"
#include "ns3/ht-configuration.h"
#include "ns3/ht-phy.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/uinteger.h"
#include "ns3/vht-configuration.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("WifiRemoteStationManager");

NS_OBJECT_ENSURE_REGISTERED(WifiRemoteStationManager);

TypeId
WifiRemoteStationManager::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::WifiRemoteStationManager")
            .SetParent<Object>()
            .SetGroupName("Wifi")
            .AddAttribute("MaxSsrc",
                          "The maximum number of retransmission attempts for any packet with size "
                          "<= RtsCtsThreshold. "
                          "This value will not have any effect on some rate control algorithms.",
                          UintegerValue(7),
                          MakeUintegerAccessor(&WifiRemoteStationManager::SetMaxSsrc),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("MaxSlrc",
                          "The maximum number of retransmission attempts for any packet with size "
                          "> RtsCtsThreshold. "
                          "This value will not have any effect on some rate control algorithms.",
                          UintegerValue(4),
                          MakeUintegerAccessor(&WifiRemoteStationManager::SetMaxSlrc),
                          MakeUintegerChecker<uint32_t>())
            .AddAttribute("RtsCtsThreshold",
                          "If the size of the PSDU is bigger than this value, we use an RTS/CTS "
                          "handshake before sending the data frame."
                          "This value will not have any effect on some rate control algorithms.",
                          UintegerValue(4692480),
                          MakeUintegerAccessor(&WifiRemoteStationManager::SetRtsCtsThreshold),
                          MakeUintegerChecker<uint32_t>(0, 4692480))
            .AddAttribute(
                "FragmentationThreshold",
                "If the size of the PSDU is bigger than this value, we fragment it such that the "
                "size of the fragments are equal or smaller. "
                "This value does not apply when it is carried in an A-MPDU. "
                "This value will not have any effect on some rate control algorithms.",
                UintegerValue(65535),
                MakeUintegerAccessor(&WifiRemoteStationManager::DoSetFragmentationThreshold,
                                     &WifiRemoteStationManager::DoGetFragmentationThreshold),
                MakeUintegerChecker<uint32_t>())
            .AddAttribute("NonUnicastMode",
                          "Wifi mode used for non-unicast transmissions.",
                          WifiModeValue(),
                          MakeWifiModeAccessor(&WifiRemoteStationManager::m_nonUnicastMode),
                          MakeWifiModeChecker())
            .AddAttribute("DefaultTxPowerLevel",
                          "Default power level to be used for transmissions. "
                          "This is the power level that is used by all those WifiManagers that do "
                          "not implement TX power control.",
                          UintegerValue(0),
                          MakeUintegerAccessor(&WifiRemoteStationManager::m_defaultTxPowerLevel),
                          MakeUintegerChecker<uint8_t>())
            .AddAttribute("ErpProtectionMode",
                          "Protection mode used when non-ERP STAs are connected to an ERP AP: "
                          "Rts-Cts or Cts-To-Self",
                          EnumValue(WifiRemoteStationManager::CTS_TO_SELF),
                          MakeEnumAccessor<WifiRemoteStationManager::ProtectionMode>(
                              &WifiRemoteStationManager::m_erpProtectionMode),
                          MakeEnumChecker(WifiRemoteStationManager::RTS_CTS,
                                          "Rts-Cts",
                                          WifiRemoteStationManager::CTS_TO_SELF,
                                          "Cts-To-Self"))
            .AddAttribute("HtProtectionMode",
                          "Protection mode used when non-HT STAs are connected to a HT AP: Rts-Cts "
                          "or Cts-To-Self",
                          EnumValue(WifiRemoteStationManager::CTS_TO_SELF),
                          MakeEnumAccessor<WifiRemoteStationManager::ProtectionMode>(
                              &WifiRemoteStationManager::m_htProtectionMode),
                          MakeEnumChecker(WifiRemoteStationManager::RTS_CTS,
                                          "Rts-Cts",
                                          WifiRemoteStationManager::CTS_TO_SELF,
                                          "Cts-To-Self"))
            .AddTraceSource("MacTxRtsFailed",
                            "The transmission of a RTS by the MAC layer has failed",
                            MakeTraceSourceAccessor(&WifiRemoteStationManager::m_macTxRtsFailed),
                            "ns3::Mac48Address::TracedCallback")
            .AddTraceSource("MacTxDataFailed",
                            "The transmission of a data packet by the MAC layer has failed",
                            MakeTraceSourceAccessor(&WifiRemoteStationManager::m_macTxDataFailed),
                            "ns3::Mac48Address::TracedCallback")
            .AddTraceSource(
                "MacTxFinalRtsFailed",
                "The transmission of a RTS has exceeded the maximum number of attempts",
                MakeTraceSourceAccessor(&WifiRemoteStationManager::m_macTxFinalRtsFailed),
                "ns3::Mac48Address::TracedCallback")
            .AddTraceSource(
                "MacTxFinalDataFailed",
                "The transmission of a data packet has exceeded the maximum number of attempts",
                MakeTraceSourceAccessor(&WifiRemoteStationManager::m_macTxFinalDataFailed),
                "ns3::Mac48Address::TracedCallback");
    return tid;
}

WifiRemoteStationManager::WifiRemoteStationManager()
    : m_useNonErpProtection(false),
      m_useNonHtProtection(false),
      m_shortPreambleEnabled(false),
      m_shortSlotTimeEnabled(false)
{
    NS_LOG_FUNCTION(this);
    m_ssrc.fill(0);
    m_slrc.fill(0);
}

WifiRemoteStationManager::~WifiRemoteStationManager()
{
    NS_LOG_FUNCTION(this);
}

void
WifiRemoteStationManager::DoDispose()
{
    NS_LOG_FUNCTION(this);
    Reset();
}

void
WifiRemoteStationManager::SetupPhy(const Ptr<WifiPhy> phy)
{
    NS_LOG_FUNCTION(this << phy);
    // We need to track our PHY because it is the object that knows the
    // full set of transmit rates that are supported. We need to know
    // this in order to find the relevant mandatory rates when choosing a
    // transmit rate for automatic control responses like
    // acknowledgments.
    m_wifiPhy = phy;
}

void
WifiRemoteStationManager::SetupMac(const Ptr<WifiMac> mac)
{
    NS_LOG_FUNCTION(this << mac);
    // We need to track our MAC because it is the object that knows the
    // full set of interframe spaces.
    m_wifiMac = mac;
}

int64_t
WifiRemoteStationManager::AssignStreams(int64_t stream)
{
    NS_LOG_FUNCTION(this << stream);
    return 0;
}

void
WifiRemoteStationManager::SetMaxSsrc(uint32_t maxSsrc)
{
    NS_LOG_FUNCTION(this << maxSsrc);
    m_maxSsrc = maxSsrc;
}

void
WifiRemoteStationManager::SetMaxSlrc(uint32_t maxSlrc)
{
    NS_LOG_FUNCTION(this << maxSlrc);
    m_maxSlrc = maxSlrc;
}

void
WifiRemoteStationManager::SetRtsCtsThreshold(uint32_t threshold)
{
    NS_LOG_FUNCTION(this << threshold);
    m_rtsCtsThreshold = threshold;
}

void
WifiRemoteStationManager::SetFragmentationThreshold(uint32_t threshold)
{
    NS_LOG_FUNCTION(this << threshold);
    DoSetFragmentationThreshold(threshold);
}

void
WifiRemoteStationManager::SetShortPreambleEnabled(bool enable)
{
    NS_LOG_FUNCTION(this << enable);
    m_shortPreambleEnabled = enable;
}

void
WifiRemoteStationManager::SetShortSlotTimeEnabled(bool enable)
{
    NS_LOG_FUNCTION(this << enable);
    m_shortSlotTimeEnabled = enable;
}

bool
WifiRemoteStationManager::GetShortSlotTimeEnabled() const
{
    return m_shortSlotTimeEnabled;
}

bool
WifiRemoteStationManager::GetShortPreambleEnabled() const
{
    return m_shortPreambleEnabled;
}

bool
WifiRemoteStationManager::GetHtSupported() const
{
    return bool(m_wifiPhy->GetDevice()->GetHtConfiguration());
}

bool
WifiRemoteStationManager::GetVhtSupported() const
{
    return (m_wifiPhy->GetDevice()->GetVhtConfiguration() &&
            m_wifiPhy->GetPhyBand() != WIFI_PHY_BAND_2_4GHZ);
}

bool
WifiRemoteStationManager::GetHeSupported() const
{
    return bool(m_wifiPhy->GetDevice()->GetHeConfiguration());
}

bool
WifiRemoteStationManager::GetEhtSupported() const
{
    return bool(m_wifiPhy->GetDevice()->GetEhtConfiguration());
}

bool
WifiRemoteStationManager::GetLdpcSupported() const
{
    if (GetHtSupported())
    {
        Ptr<HtConfiguration> htConfiguration = m_wifiPhy->GetDevice()->GetHtConfiguration();
        NS_ASSERT(htConfiguration); // If HT is supported, we should have a HT configuration
                                    // attached
        return htConfiguration->GetLdpcSupported();
    }
    return false;
}

bool
WifiRemoteStationManager::GetShortGuardIntervalSupported() const
{
    if (GetHtSupported())
    {
        Ptr<HtConfiguration> htConfiguration = m_wifiPhy->GetDevice()->GetHtConfiguration();
        NS_ASSERT(htConfiguration); // If HT is supported, we should have a HT configuration
                                    // attached
        if (htConfiguration->GetShortGuardIntervalSupported())
        {
            return true;
        }
    }
    return false;
}

uint16_t
WifiRemoteStationManager::GetGuardInterval() const
{
    uint16_t gi = 0;
    if (GetHeSupported())
    {
        Ptr<HeConfiguration> heConfiguration = m_wifiPhy->GetDevice()->GetHeConfiguration();
        NS_ASSERT(heConfiguration); // If HE is supported, we should have a HE configuration
                                    // attached
        gi = static_cast<uint16_t>(heConfiguration->GetGuardInterval().GetNanoSeconds());
    }
    return gi;
}

uint32_t
WifiRemoteStationManager::GetFragmentationThreshold() const
{
    return DoGetFragmentationThreshold();
}

void
WifiRemoteStationManager::AddSupportedPhyPreamble(Mac48Address address,
                                                  bool isShortPreambleSupported)
{
    NS_LOG_FUNCTION(this << address << isShortPreambleSupported);
    NS_ASSERT(!address.IsGroup());
    LookupState(address)->m_shortPreamble = isShortPreambleSupported;
}

void
WifiRemoteStationManager::AddSupportedErpSlotTime(Mac48Address address,
                                                  bool isShortSlotTimeSupported)
{
    NS_LOG_FUNCTION(this << address << isShortSlotTimeSupported);
    NS_ASSERT(!address.IsGroup());
    LookupState(address)->m_shortSlotTime = isShortSlotTimeSupported;
}

void
WifiRemoteStationManager::AddSupportedMode(Mac48Address address, WifiMode mode)
{
    NS_LOG_FUNCTION(this << address << mode);
    NS_ASSERT(!address.IsGroup());
    auto state = LookupState(address);
    for (const auto& i : state->m_operationalRateSet)
    {
        if (i == mode)
        {
            return; // already in
        }
    }
    if ((mode.GetModulationClass() == WIFI_MOD_CLASS_DSSS) ||
        (mode.GetModulationClass() == WIFI_MOD_CLASS_HR_DSSS))
    {
        state->m_dsssSupported = true;
    }
    else if (mode.GetModulationClass() == WIFI_MOD_CLASS_ERP_OFDM)
    {
        state->m_erpOfdmSupported = true;
    }
    else if (mode.GetModulationClass() == WIFI_MOD_CLASS_OFDM)
    {
        state->m_ofdmSupported = true;
    }
    state->m_operationalRateSet.push_back(mode);
}

void
WifiRemoteStationManager::AddAllSupportedModes(Mac48Address address)
{
    NS_LOG_FUNCTION(this << address);
    NS_ASSERT(!address.IsGroup());
    auto state = LookupState(address);
    state->m_operationalRateSet.clear();
    for (const auto& mode : m_wifiPhy->GetModeList())
    {
        state->m_operationalRateSet.push_back(mode);
        if (mode.IsMandatory())
        {
            AddBasicMode(mode);
        }
    }
}

void
WifiRemoteStationManager::AddAllSupportedMcs(Mac48Address address)
{
    NS_LOG_FUNCTION(this << address);
    NS_ASSERT(!address.IsGroup());
    auto state = LookupState(address);

    const auto& mcsList = m_wifiPhy->GetMcsList();
    state->m_operationalMcsSet = WifiModeList(mcsList.begin(), mcsList.end());
}

void
WifiRemoteStationManager::RemoveAllSupportedMcs(Mac48Address address)
{
    NS_LOG_FUNCTION(this << address);
    NS_ASSERT(!address.IsGroup());
    LookupState(address)->m_operationalMcsSet.clear();
}

void
WifiRemoteStationManager::AddSupportedMcs(Mac48Address address, WifiMode mcs)
{
    NS_LOG_FUNCTION(this << address << mcs);
    NS_ASSERT(!address.IsGroup());
    auto state = LookupState(address);
    for (const auto& i : state->m_operationalMcsSet)
    {
        if (i == mcs)
        {
            return; // already in
        }
    }
    state->m_operationalMcsSet.push_back(mcs);
}

bool
WifiRemoteStationManager::GetShortPreambleSupported(Mac48Address address) const
{
    return LookupState(address)->m_shortPreamble;
}

bool
WifiRemoteStationManager::GetShortSlotTimeSupported(Mac48Address address) const
{
    return LookupState(address)->m_shortSlotTime;
}

bool
WifiRemoteStationManager::GetQosSupported(Mac48Address address) const
{
    return LookupState(address)->m_qosSupported;
}

bool
WifiRemoteStationManager::IsBrandNew(Mac48Address address) const
{
    if (address.IsGroup())
    {
        return false;
    }
    return LookupState(address)->m_state == WifiRemoteStationState::BRAND_NEW;
}

bool
WifiRemoteStationManager::IsAssociated(Mac48Address address) const
{
    if (address.IsGroup())
    {
        return true;
    }
    return LookupState(address)->m_state == WifiRemoteStationState::GOT_ASSOC_TX_OK;
}

bool
WifiRemoteStationManager::IsWaitAssocTxOk(Mac48Address address) const
{
    if (address.IsGroup())
    {
        return false;
    }
    return LookupState(address)->m_state == WifiRemoteStationState::WAIT_ASSOC_TX_OK;
}

void
WifiRemoteStationManager::RecordWaitAssocTxOk(Mac48Address address)
{
    NS_ASSERT(!address.IsGroup());
    LookupState(address)->m_state = WifiRemoteStationState::WAIT_ASSOC_TX_OK;
}

void
WifiRemoteStationManager::RecordGotAssocTxOk(Mac48Address address)
{
    NS_ASSERT(!address.IsGroup());
    LookupState(address)->m_state = WifiRemoteStationState::GOT_ASSOC_TX_OK;
}

void
WifiRemoteStationManager::RecordGotAssocTxFailed(Mac48Address address)
{
    NS_ASSERT(!address.IsGroup());
    LookupState(address)->m_state = WifiRemoteStationState::DISASSOC;
}

void
WifiRemoteStationManager::RecordDisassociated(Mac48Address address)
{
    NS_ASSERT(!address.IsGroup());
    LookupState(address)->m_state = WifiRemoteStationState::DISASSOC;
}

bool
WifiRemoteStationManager::IsAssocRefused(Mac48Address address) const
{
    if (address.IsGroup())
    {
        return false;
    }
    return LookupState(address)->m_state == WifiRemoteStationState::ASSOC_REFUSED;
}

void
WifiRemoteStationManager::RecordAssocRefused(Mac48Address address)
{
    NS_ASSERT(!address.IsGroup());
    LookupState(address)->m_state = WifiRemoteStationState::ASSOC_REFUSED;
}

uint16_t
WifiRemoteStationManager::GetAssociationId(Mac48Address remoteAddress) const
{
    std::shared_ptr<WifiRemoteStationState> state;
    if (!remoteAddress.IsGroup() &&
        (state = LookupState(remoteAddress))->m_state == WifiRemoteStationState::GOT_ASSOC_TX_OK)
    {
        return state->m_aid;
    }
    return SU_STA_ID;
}

uint16_t
WifiRemoteStationManager::GetStaId(Mac48Address address, const WifiTxVector& txVector) const
{
    NS_LOG_FUNCTION(this << address << txVector);

    uint16_t staId = SU_STA_ID;

    if (txVector.IsMu())
    {
        if (m_wifiMac->GetTypeOfStation() == AP)
        {
            staId = GetAssociationId(address);
        }
        else if (m_wifiMac->GetTypeOfStation() == STA)
        {
            Ptr<StaWifiMac> staMac = StaticCast<StaWifiMac>(m_wifiMac);
            if (staMac->IsAssociated())
            {
                staId = staMac->GetAssociationId();
            }
        }
    }

    NS_LOG_DEBUG("Returning STAID = " << staId);
    return staId;
}

bool
WifiRemoteStationManager::IsInPsMode(const Mac48Address& address) const
{
    return LookupState(address)->m_isInPsMode;
}

void
WifiRemoteStationManager::SetPsMode(const Mac48Address& address, bool isInPsMode)
{
    LookupState(address)->m_isInPsMode = isInPsMode;
}

std::optional<Mac48Address>
WifiRemoteStationManager::GetMldAddress(const Mac48Address& address) const
{
    if (auto stateIt = m_states.find(address);
        stateIt != m_states.end() && stateIt->second->m_mleCommonInfo)
    {
        return stateIt->second->m_mleCommonInfo->m_mldMacAddress;
    }

    return std::nullopt;
}

std::optional<Mac48Address>
WifiRemoteStationManager::GetAffiliatedStaAddress(const Mac48Address& mldAddress) const
{
    auto stateIt = m_states.find(mldAddress);

    if (stateIt == m_states.end() || !stateIt->second->m_mleCommonInfo)
    {
        // MLD address not found
        return std::nullopt;
    }

    NS_ASSERT(stateIt->second->m_mleCommonInfo->m_mldMacAddress == mldAddress);
    return stateIt->second->m_address;
}

WifiTxVector
WifiRemoteStationManager::GetDataTxVector(const WifiMacHeader& header, uint16_t allowedWidth)
{
    NS_LOG_FUNCTION(this << header << allowedWidth);
    Mac48Address address = header.GetAddr1();
    if (!header.IsMgt() && address.IsGroup())
    {
        WifiMode mode = GetNonUnicastMode();
        WifiTxVector v;
        v.SetMode(mode);
        v.SetPreambleType(
            GetPreambleForTransmission(mode.GetModulationClass(), GetShortPreambleEnabled()));
        v.SetTxPowerLevel(m_defaultTxPowerLevel);
        v.SetChannelWidth(m_wifiPhy->GetTxBandwidth(mode, allowedWidth));
        v.SetGuardInterval(ConvertGuardIntervalToNanoSeconds(mode, m_wifiPhy->GetDevice()));
        v.SetNTx(GetNumberOfAntennas());
        v.SetNss(1);
        v.SetNess(0);
        return v;
    }
    WifiTxVector txVector;
    if (header.IsMgt())
    {
        // Use the lowest basic rate for management frames
        WifiMode mgtMode;
        if (GetNBasicModes() > 0)
        {
            mgtMode = GetBasicMode(0);
        }
        else
        {
            mgtMode = GetDefaultMode();
        }
        txVector.SetMode(mgtMode);
        txVector.SetPreambleType(
            GetPreambleForTransmission(mgtMode.GetModulationClass(), GetShortPreambleEnabled()));
        txVector.SetTxPowerLevel(m_defaultTxPowerLevel);
        uint16_t channelWidth = allowedWidth;
        if (!header.GetAddr1().IsGroup())
        {
            if (uint16_t rxWidth = GetChannelWidthSupported(header.GetAddr1());
                rxWidth < channelWidth)
            {
                channelWidth = rxWidth;
            }
        }

        txVector.SetChannelWidth(m_wifiPhy->GetTxBandwidth(mgtMode, channelWidth));
        txVector.SetGuardInterval(
            ConvertGuardIntervalToNanoSeconds(mgtMode, m_wifiPhy->GetDevice()));
    }
    else
    {
        txVector = DoGetDataTxVector(Lookup(address), allowedWidth);
        txVector.SetLdpc(txVector.GetMode().GetModulationClass() < WIFI_MOD_CLASS_HT
                             ? false
                             : UseLdpcForDestination(address));
    }
    Ptr<HeConfiguration> heConfiguration = m_wifiPhy->GetDevice()->GetHeConfiguration();
    if (heConfiguration)
    {
        txVector.SetBssColor(heConfiguration->GetBssColor());
    }
    // If both the allowed width and the TXVECTOR channel width are integer multiple
    // of 20 MHz, then the TXVECTOR channel width must not exceed the allowed width
    NS_ASSERT_MSG((txVector.GetChannelWidth() % 20 != 0) || (allowedWidth % 20 != 0) ||
                      (txVector.GetChannelWidth() <= allowedWidth),
                  "TXVECTOR channel width (" << txVector.GetChannelWidth()
                                             << " MHz) exceeds allowed width (" << allowedWidth
                                             << " MHz)");
    return txVector;
}

WifiTxVector
WifiRemoteStationManager::GetCtsToSelfTxVector()
{
    WifiMode defaultMode = GetDefaultMode();
    WifiPreamble defaultPreamble;
    if (defaultMode.GetModulationClass() == WIFI_MOD_CLASS_EHT)
    {
        defaultPreamble = WIFI_PREAMBLE_EHT_MU;
    }
    else if (defaultMode.GetModulationClass() == WIFI_MOD_CLASS_HE)
    {
        defaultPreamble = WIFI_PREAMBLE_HE_SU;
    }
    else if (defaultMode.GetModulationClass() == WIFI_MOD_CLASS_VHT)
    {
        defaultPreamble = WIFI_PREAMBLE_VHT_SU;
    }
    else if (defaultMode.GetModulationClass() == WIFI_MOD_CLASS_HT)
    {
        defaultPreamble = WIFI_PREAMBLE_HT_MF;
    }
    else
    {
        defaultPreamble = WIFI_PREAMBLE_LONG;
    }

    return WifiTxVector(defaultMode,
                        GetDefaultTxPowerLevel(),
                        defaultPreamble,
                        ConvertGuardIntervalToNanoSeconds(defaultMode, m_wifiPhy->GetDevice()),
                        GetNumberOfAntennas(),
                        1,
                        0,
                        m_wifiPhy->GetTxBandwidth(defaultMode),
                        false);
}

WifiTxVector
WifiRemoteStationManager::GetRtsTxVector(Mac48Address address, uint16_t allowedWidth)
{
    NS_LOG_FUNCTION(this << address << allowedWidth);
    WifiTxVector v;
    if (address.IsGroup())
    {
        WifiMode mode = GetNonUnicastMode();
        v.SetMode(mode);
        v.SetPreambleType(
            GetPreambleForTransmission(mode.GetModulationClass(), GetShortPreambleEnabled()));
        v.SetTxPowerLevel(m_defaultTxPowerLevel);
        v.SetChannelWidth(m_wifiPhy->GetTxBandwidth(mode));
        v.SetGuardInterval(ConvertGuardIntervalToNanoSeconds(mode, m_wifiPhy->GetDevice()));
        v.SetNTx(GetNumberOfAntennas());
        v.SetNss(1);
        v.SetNess(0);
    }
    else
    {
        v = DoGetRtsTxVector(Lookup(address));
    }
    auto modulation = v.GetModulationClass();

    if (allowedWidth >= 40 &&
        (modulation == WIFI_MOD_CLASS_DSSS || modulation == WIFI_MOD_CLASS_HR_DSSS))
    {
        // RTS must be sent in a non-HT duplicate PPDU because it must protect a frame being
        // transmitted on at least 40 MHz. Change the modulation class to ERP-OFDM and the rate
        // to 6 Mbps
        v.SetMode(ErpOfdmPhy::GetErpOfdmRate6Mbps());
        modulation = v.GetModulationClass();
    }
    // do not set allowedWidth as the TX width if the modulation class is (HR-)DSSS (allowedWidth
    // may be >= 40 MHz) or allowedWidth is 22 MHz (the selected modulation class may be OFDM)
    if (modulation != WIFI_MOD_CLASS_DSSS && modulation != WIFI_MOD_CLASS_HR_DSSS &&
        allowedWidth != 22)
    {
        v.SetChannelWidth(allowedWidth);
    }

    return v;
}

WifiTxVector
WifiRemoteStationManager::GetCtsTxVector(Mac48Address to, WifiMode rtsTxMode) const
{
    NS_ASSERT(!to.IsGroup());
    WifiMode ctsMode = GetControlAnswerMode(rtsTxMode);
    WifiTxVector v;
    v.SetMode(ctsMode);
    v.SetPreambleType(
        GetPreambleForTransmission(ctsMode.GetModulationClass(), GetShortPreambleEnabled()));
    v.SetTxPowerLevel(GetDefaultTxPowerLevel());
    v.SetChannelWidth(m_wifiPhy->GetTxBandwidth(ctsMode));
    uint16_t ctsTxGuardInterval =
        ConvertGuardIntervalToNanoSeconds(ctsMode, m_wifiPhy->GetDevice());
    v.SetGuardInterval(ctsTxGuardInterval);
    v.SetNss(1);
    return v;
}

void
WifiRemoteStationManager::AdjustTxVectorForIcf(WifiTxVector& txVector) const
{
    NS_LOG_FUNCTION(this << txVector);

    auto txMode = txVector.GetMode();
    if (txMode.GetModulationClass() >= WIFI_MOD_CLASS_HT)
    {
        auto rate = txMode.GetDataRate(txVector);
        if (rate >= 24e6)
        {
            rate = 24e6;
        }
        else if (rate >= 12e6)
        {
            rate = 12e6;
        }
        else
        {
            rate = 6e6;
        }
        txVector.SetPreambleType(WIFI_PREAMBLE_LONG);
        if (m_wifiPhy->GetPhyBand() == WIFI_PHY_BAND_2_4GHZ)
        {
            txVector.SetMode(ErpOfdmPhy::GetErpOfdmRate(rate));
        }
        else
        {
            txVector.SetMode(OfdmPhy::GetOfdmRate(rate));
        }
    }
}

WifiTxVector
WifiRemoteStationManager::GetAckTxVector(Mac48Address to, const WifiTxVector& dataTxVector) const
{
    NS_ASSERT(!to.IsGroup());
    WifiMode ackMode = GetControlAnswerMode(dataTxVector.GetMode(GetStaId(to, dataTxVector)));
    WifiTxVector v;
    v.SetMode(ackMode);
    v.SetPreambleType(
        GetPreambleForTransmission(ackMode.GetModulationClass(), GetShortPreambleEnabled()));
    v.SetTxPowerLevel(GetDefaultTxPowerLevel());
    v.SetChannelWidth(m_wifiPhy->GetTxBandwidth(ackMode));
    uint16_t ackTxGuardInterval =
        ConvertGuardIntervalToNanoSeconds(ackMode, m_wifiPhy->GetDevice());
    v.SetGuardInterval(ackTxGuardInterval);
    v.SetNss(1);
    return v;
}

WifiTxVector
WifiRemoteStationManager::GetBlockAckTxVector(Mac48Address to,
                                              const WifiTxVector& dataTxVector) const
{
    NS_ASSERT(!to.IsGroup());
    WifiMode blockAckMode = GetControlAnswerMode(dataTxVector.GetMode(GetStaId(to, dataTxVector)));
    WifiTxVector v;
    v.SetMode(blockAckMode);
    v.SetPreambleType(
        GetPreambleForTransmission(blockAckMode.GetModulationClass(), GetShortPreambleEnabled()));
    v.SetTxPowerLevel(GetDefaultTxPowerLevel());
    v.SetChannelWidth(m_wifiPhy->GetTxBandwidth(blockAckMode));
    uint16_t blockAckTxGuardInterval =
        ConvertGuardIntervalToNanoSeconds(blockAckMode, m_wifiPhy->GetDevice());
    v.SetGuardInterval(blockAckTxGuardInterval);
    v.SetNss(1);
    return v;
}

WifiMode
WifiRemoteStationManager::GetControlAnswerMode(WifiMode reqMode) const
{
    /**
     * The standard has relatively unambiguous rules for selecting a
     * control response rate (the below is quoted from IEEE 802.11-2012,
     * Section 9.7):
     *
     * To allow the transmitting STA to calculate the contents of the
     * Duration/ID field, a STA responding to a received frame shall
     * transmit its Control Response frame (either CTS or Ack), other
     * than the BlockAck control frame, at the highest rate in the
     * BSSBasicRateSet parameter that is less than or equal to the
     * rate of the immediately previous frame in the frame exchange
     * sequence (as defined in Annex G) and that is of the same
     * modulation class (see Section 9.7.8) as the received frame...
     */
    NS_LOG_FUNCTION(this << reqMode);
    WifiMode mode = GetDefaultMode();
    bool found = false;
    // First, search the BSS Basic Rate set
    for (uint8_t i = 0; i < GetNBasicModes(); i++)
    {
        WifiMode testMode = GetBasicMode(i);
        if ((!found || testMode.IsHigherDataRate(mode)) && (!testMode.IsHigherDataRate(reqMode)) &&
            (IsAllowedControlAnswerModulationClass(reqMode.GetModulationClass(),
                                                   testMode.GetModulationClass())))
        {
            mode = testMode;
            // We've found a potentially-suitable transmit rate, but we
            // need to continue and consider all the basic rates before
            // we can be sure we've got the right one.
            found = true;
        }
    }
    if (GetHtSupported())
    {
        if (!found)
        {
            mode = GetDefaultMcs();
            for (uint8_t i = 0; i != GetNBasicMcs(); i++)
            {
                WifiMode testMode = GetBasicMcs(i);
                if ((!found || testMode.IsHigherDataRate(mode)) &&
                    (!testMode.IsHigherDataRate(reqMode)) &&
                    (testMode.GetModulationClass() == reqMode.GetModulationClass()))
                {
                    mode = testMode;
                    // We've found a potentially-suitable transmit rate, but we
                    // need to continue and consider all the basic rates before
                    // we can be sure we've got the right one.
                    found = true;
                }
            }
        }
    }
    // If we found a suitable rate in the BSSBasicRateSet, then we are
    // done and can return that mode.
    if (found)
    {
        NS_LOG_DEBUG("WifiRemoteStationManager::GetControlAnswerMode returning " << mode);
        return mode;
    }

    /**
     * If no suitable basic rate was found, we search the mandatory
     * rates. The standard (IEEE 802.11-2007, Section 9.6) says:
     *
     *   ...If no rate contained in the BSSBasicRateSet parameter meets
     *   these conditions, then the control frame sent in response to a
     *   received frame shall be transmitted at the highest mandatory
     *   rate of the PHY that is less than or equal to the rate of the
     *   received frame, and that is of the same modulation class as the
     *   received frame. In addition, the Control Response frame shall
     *   be sent using the same PHY options as the received frame,
     *   unless they conflict with the requirement to use the
     *   BSSBasicRateSet parameter.
     *
     * \todo Note that we're ignoring the last sentence for now, because
     * there is not yet any manipulation here of PHY options.
     */
    for (const auto& thismode : m_wifiPhy->GetModeList())
    {
        /* If the rate:
         *
         *  - is a mandatory rate for the PHY, and
         *  - is equal to or faster than our current best choice, and
         *  - is less than or equal to the rate of the received frame, and
         *  - is of the same modulation class as the received frame
         *
         * ...then it's our best choice so far.
         */
        if (thismode.IsMandatory() && (!found || thismode.IsHigherDataRate(mode)) &&
            (!thismode.IsHigherDataRate(reqMode)) &&
            (IsAllowedControlAnswerModulationClass(reqMode.GetModulationClass(),
                                                   thismode.GetModulationClass())))
        {
            mode = thismode;
            // As above; we've found a potentially-suitable transmit
            // rate, but we need to continue and consider all the
            // mandatory rates before we can be sure we've got the right one.
            found = true;
        }
    }
    if (GetHtSupported())
    {
        for (const auto& thismode : m_wifiPhy->GetMcsList())
        {
            if (thismode.IsMandatory() && (!found || thismode.IsHigherDataRate(mode)) &&
                (!thismode.IsHigherCodeRate(reqMode)) &&
                (thismode.GetModulationClass() == reqMode.GetModulationClass()))
            {
                mode = thismode;
                // As above; we've found a potentially-suitable transmit
                // rate, but we need to continue and consider all the
                // mandatory rates before we can be sure we've got the right one.
                found = true;
            }
        }
    }

    /**
     * If we still haven't found a suitable rate for the response then
     * someone has messed up the simulation configuration. This probably means
     * that the WifiPhyStandard is not set correctly, or that a rate that
     * is not supported by the PHY has been explicitly requested.
     *
     * Either way, it is serious - we can either disobey the standard or
     * fail, and I have chosen to do the latter...
     */
    if (!found)
    {
        NS_FATAL_ERROR("Can't find response rate for " << reqMode);
    }

    NS_LOG_DEBUG("WifiRemoteStationManager::GetControlAnswerMode returning " << mode);
    return mode;
}

void
WifiRemoteStationManager::ReportRtsFailed(const WifiMacHeader& header)
{
    NS_LOG_FUNCTION(this << header);
    NS_ASSERT(!header.GetAddr1().IsGroup());
    AcIndex ac = QosUtilsMapTidToAc((header.IsQosData()) ? header.GetQosTid() : 0);
    m_ssrc[ac]++;
    m_macTxRtsFailed(header.GetAddr1());
    DoReportRtsFailed(Lookup(header.GetAddr1()));
}

void
WifiRemoteStationManager::ReportDataFailed(Ptr<const WifiMpdu> mpdu)
{
    NS_LOG_FUNCTION(this << *mpdu);
    NS_ASSERT(!mpdu->GetHeader().GetAddr1().IsGroup());
    AcIndex ac =
        QosUtilsMapTidToAc((mpdu->GetHeader().IsQosData()) ? mpdu->GetHeader().GetQosTid() : 0);
    bool longMpdu = (mpdu->GetSize() > m_rtsCtsThreshold);
    if (longMpdu)
    {
        m_slrc[ac]++;
    }
    else
    {
        m_ssrc[ac]++;
    }
    m_macTxDataFailed(mpdu->GetHeader().GetAddr1());
    DoReportDataFailed(Lookup(mpdu->GetHeader().GetAddr1()));
}

void
WifiRemoteStationManager::ReportRtsOk(const WifiMacHeader& header,
                                      double ctsSnr,
                                      WifiMode ctsMode,
                                      double rtsSnr)
{
    NS_LOG_FUNCTION(this << header << ctsSnr << ctsMode << rtsSnr);
    NS_ASSERT(!header.GetAddr1().IsGroup());
    WifiRemoteStation* station = Lookup(header.GetAddr1());
    AcIndex ac = QosUtilsMapTidToAc((header.IsQosData()) ? header.GetQosTid() : 0);
    station->m_state->m_info.NotifyTxSuccess(m_ssrc[ac]);
    m_ssrc[ac] = 0;
    DoReportRtsOk(station, ctsSnr, ctsMode, rtsSnr);
}

void
WifiRemoteStationManager::ReportDataOk(Ptr<const WifiMpdu> mpdu,
                                       double ackSnr,
                                       WifiMode ackMode,
                                       double dataSnr,
                                       WifiTxVector dataTxVector)
{
    NS_LOG_FUNCTION(this << *mpdu << ackSnr << ackMode << dataSnr << dataTxVector);
    const WifiMacHeader& hdr = mpdu->GetHeader();
    NS_ASSERT(!hdr.GetAddr1().IsGroup());
    WifiRemoteStation* station = Lookup(hdr.GetAddr1());
    AcIndex ac = QosUtilsMapTidToAc((hdr.IsQosData()) ? hdr.GetQosTid() : 0);
    bool longMpdu = (mpdu->GetSize() > m_rtsCtsThreshold);
    if (longMpdu)
    {
        station->m_state->m_info.NotifyTxSuccess(m_slrc[ac]);
        m_slrc[ac] = 0;
    }
    else
    {
        station->m_state->m_info.NotifyTxSuccess(m_ssrc[ac]);
        m_ssrc[ac] = 0;
    }
    DoReportDataOk(station,
                   ackSnr,
                   ackMode,
                   dataSnr,
                   dataTxVector.GetChannelWidth(),
                   dataTxVector.GetNss(GetStaId(hdr.GetAddr1(), dataTxVector)));
}

void
WifiRemoteStationManager::ReportFinalRtsFailed(const WifiMacHeader& header)
{
    NS_LOG_FUNCTION(this << header);
    NS_ASSERT(!header.GetAddr1().IsGroup());
    WifiRemoteStation* station = Lookup(header.GetAddr1());
    AcIndex ac = QosUtilsMapTidToAc((header.IsQosData()) ? header.GetQosTid() : 0);
    station->m_state->m_info.NotifyTxFailed();
    m_ssrc[ac] = 0;
    m_macTxFinalRtsFailed(header.GetAddr1());
    DoReportFinalRtsFailed(station);
}

void
WifiRemoteStationManager::ReportFinalDataFailed(Ptr<const WifiMpdu> mpdu)
{
    NS_LOG_FUNCTION(this << *mpdu);
    NS_ASSERT(!mpdu->GetHeader().GetAddr1().IsGroup());
    WifiRemoteStation* station = Lookup(mpdu->GetHeader().GetAddr1());
    AcIndex ac =
        QosUtilsMapTidToAc((mpdu->GetHeader().IsQosData()) ? mpdu->GetHeader().GetQosTid() : 0);
    station->m_state->m_info.NotifyTxFailed();
    bool longMpdu = (mpdu->GetSize() > m_rtsCtsThreshold);
    if (longMpdu)
    {
        m_slrc[ac] = 0;
    }
    else
    {
        m_ssrc[ac] = 0;
    }
    m_macTxFinalDataFailed(mpdu->GetHeader().GetAddr1());
    DoReportFinalDataFailed(station);
}

void
WifiRemoteStationManager::ReportRxOk(Mac48Address address,
                                     RxSignalInfo rxSignalInfo,
                                     WifiTxVector txVector)
{
    NS_LOG_FUNCTION(this << address << rxSignalInfo << txVector);
    if (address.IsGroup())
    {
        return;
    }
    WifiRemoteStation* station = Lookup(address);
    DoReportRxOk(station, rxSignalInfo.snr, txVector.GetMode(GetStaId(address, txVector)));
    station->m_rssiAndUpdateTimePair = std::make_pair(rxSignalInfo.rssi, Simulator::Now());
}

void
WifiRemoteStationManager::ReportAmpduTxStatus(Mac48Address address,
                                              uint16_t nSuccessfulMpdus,
                                              uint16_t nFailedMpdus,
                                              double rxSnr,
                                              double dataSnr,
                                              WifiTxVector dataTxVector)
{
    NS_LOG_FUNCTION(this << address << nSuccessfulMpdus << nFailedMpdus << rxSnr << dataSnr
                         << dataTxVector);
    NS_ASSERT(!address.IsGroup());
    for (uint16_t i = 0; i < nFailedMpdus; i++)
    {
        m_macTxDataFailed(address);
    }
    DoReportAmpduTxStatus(Lookup(address),
                          nSuccessfulMpdus,
                          nFailedMpdus,
                          rxSnr,
                          dataSnr,
                          dataTxVector.GetChannelWidth(),
                          dataTxVector.GetNss(GetStaId(address, dataTxVector)));
}

bool
WifiRemoteStationManager::NeedRts(const WifiMacHeader& header, uint32_t size)
{
    NS_LOG_FUNCTION(this << header << size);
    Mac48Address address = header.GetAddr1();
    WifiTxVector txVector = GetDataTxVector(header, m_wifiPhy->GetChannelWidth());
    const auto modulationClass = txVector.GetModulationClass();
    if (address.IsGroup())
    {
        return false;
    }
    if (m_erpProtectionMode == RTS_CTS &&
        ((modulationClass == WIFI_MOD_CLASS_ERP_OFDM) || (modulationClass == WIFI_MOD_CLASS_HT) ||
         (modulationClass == WIFI_MOD_CLASS_VHT) || (modulationClass == WIFI_MOD_CLASS_HE) ||
         (modulationClass == WIFI_MOD_CLASS_EHT)) &&
        m_useNonErpProtection)
    {
        NS_LOG_DEBUG(
            "WifiRemoteStationManager::NeedRTS returning true to protect non-ERP stations");
        return true;
    }
    else if (m_htProtectionMode == RTS_CTS &&
             ((modulationClass == WIFI_MOD_CLASS_HT) || (modulationClass == WIFI_MOD_CLASS_VHT)) &&
             m_useNonHtProtection && !(m_erpProtectionMode != RTS_CTS && m_useNonErpProtection))
    {
        NS_LOG_DEBUG("WifiRemoteStationManager::NeedRTS returning true to protect non-HT stations");
        return true;
    }
    bool normally = (size > m_rtsCtsThreshold);
    return DoNeedRts(Lookup(address), size, normally);
}

bool
WifiRemoteStationManager::NeedCtsToSelf(WifiTxVector txVector)
{
    WifiMode mode = txVector.GetMode();
    NS_LOG_FUNCTION(this << mode);
    if (m_erpProtectionMode == CTS_TO_SELF &&
        ((mode.GetModulationClass() == WIFI_MOD_CLASS_ERP_OFDM) ||
         (mode.GetModulationClass() == WIFI_MOD_CLASS_HT) ||
         (mode.GetModulationClass() == WIFI_MOD_CLASS_VHT) ||
         (mode.GetModulationClass() == WIFI_MOD_CLASS_HE) ||
         (mode.GetModulationClass() == WIFI_MOD_CLASS_EHT)) &&
        m_useNonErpProtection)
    {
        NS_LOG_DEBUG(
            "WifiRemoteStationManager::NeedCtsToSelf returning true to protect non-ERP stations");
        return true;
    }
    else if (m_htProtectionMode == CTS_TO_SELF &&
             ((mode.GetModulationClass() == WIFI_MOD_CLASS_HT) ||
              (mode.GetModulationClass() == WIFI_MOD_CLASS_VHT)) &&
             m_useNonHtProtection && !(m_erpProtectionMode != CTS_TO_SELF && m_useNonErpProtection))
    {
        NS_LOG_DEBUG(
            "WifiRemoteStationManager::NeedCtsToSelf returning true to protect non-HT stations");
        return true;
    }
    else if (!m_useNonErpProtection)
    {
        // search for the BSS Basic Rate set, if the used mode is in the basic set then there is no
        // need for CTS To Self
        for (auto i = m_bssBasicRateSet.begin(); i != m_bssBasicRateSet.end(); i++)
        {
            if (mode == *i)
            {
                NS_LOG_DEBUG("WifiRemoteStationManager::NeedCtsToSelf returning false");
                return false;
            }
        }
        if (GetHtSupported())
        {
            // search for the BSS Basic MCS set, if the used mode is in the basic set then there is
            // no need for CTS To Self
            for (auto i = m_bssBasicMcsSet.begin(); i != m_bssBasicMcsSet.end(); i++)
            {
                if (mode == *i)
                {
                    NS_LOG_DEBUG("WifiRemoteStationManager::NeedCtsToSelf returning false");
                    return false;
                }
            }
        }
        NS_LOG_DEBUG("WifiRemoteStationManager::NeedCtsToSelf returning true");
        return true;
    }
    return false;
}

void
WifiRemoteStationManager::SetUseNonErpProtection(bool enable)
{
    NS_LOG_FUNCTION(this << enable);
    m_useNonErpProtection = enable;
}

bool
WifiRemoteStationManager::GetUseNonErpProtection() const
{
    return m_useNonErpProtection;
}

void
WifiRemoteStationManager::SetUseNonHtProtection(bool enable)
{
    NS_LOG_FUNCTION(this << enable);
    m_useNonHtProtection = enable;
}

bool
WifiRemoteStationManager::GetUseNonHtProtection() const
{
    return m_useNonHtProtection;
}

bool
WifiRemoteStationManager::NeedRetransmission(Ptr<const WifiMpdu> mpdu)
{
    NS_LOG_FUNCTION(this << *mpdu);
    NS_ASSERT(!mpdu->GetHeader().GetAddr1().IsGroup());
    AcIndex ac =
        QosUtilsMapTidToAc((mpdu->GetHeader().IsQosData()) ? mpdu->GetHeader().GetQosTid() : 0);
    bool longMpdu = (mpdu->GetSize() > m_rtsCtsThreshold);
    uint32_t retryCount;
    uint32_t maxRetryCount;
    if (longMpdu)
    {
        retryCount = m_slrc[ac];
        maxRetryCount = m_maxSlrc;
    }
    else
    {
        retryCount = m_ssrc[ac];
        maxRetryCount = m_maxSsrc;
    }
    bool normally = retryCount < maxRetryCount;
    NS_LOG_DEBUG("WifiRemoteStationManager::NeedRetransmission count: "
                 << retryCount << " result: " << std::boolalpha << normally);
    return DoNeedRetransmission(Lookup(mpdu->GetHeader().GetAddr1()), mpdu->GetPacket(), normally);
}

bool
WifiRemoteStationManager::NeedFragmentation(Ptr<const WifiMpdu> mpdu)
{
    NS_LOG_FUNCTION(this << *mpdu);
    if (mpdu->GetHeader().GetAddr1().IsGroup())
    {
        return false;
    }
    bool normally = mpdu->GetSize() > GetFragmentationThreshold();
    NS_LOG_DEBUG("WifiRemoteStationManager::NeedFragmentation result: " << std::boolalpha
                                                                        << normally);
    return DoNeedFragmentation(Lookup(mpdu->GetHeader().GetAddr1()), mpdu->GetPacket(), normally);
}

void
WifiRemoteStationManager::DoSetFragmentationThreshold(uint32_t threshold)
{
    NS_LOG_FUNCTION(this << threshold);
    if (threshold < 256)
    {
        /*
         * ASN.1 encoding of the MAC and PHY MIB (256 ... 8000)
         */
        NS_LOG_WARN("Fragmentation threshold should be larger than 256. Setting to 256.");
        m_fragmentationThreshold = 256;
    }
    else
    {
        /*
         * The length of each fragment shall be an even number of octets, except for the last
         * fragment if an MSDU or MMPDU, which may be either an even or an odd number of octets.
         */
        if (threshold % 2 != 0)
        {
            NS_LOG_WARN("Fragmentation threshold should be an even number. Setting to "
                        << threshold - 1);
            m_fragmentationThreshold = threshold - 1;
        }
        else
        {
            m_fragmentationThreshold = threshold;
        }
    }
}

uint32_t
WifiRemoteStationManager::DoGetFragmentationThreshold() const
{
    return m_fragmentationThreshold;
}

uint32_t
WifiRemoteStationManager::GetNFragments(Ptr<const WifiMpdu> mpdu)
{
    NS_LOG_FUNCTION(this << *mpdu);
    // The number of bytes a fragment can support is (Threshold - WIFI_HEADER_SIZE - WIFI_FCS).
    uint32_t nFragments =
        (mpdu->GetPacket()->GetSize() /
         (GetFragmentationThreshold() - mpdu->GetHeader().GetSize() - WIFI_MAC_FCS_LENGTH));

    // If the size of the last fragment is not 0.
    if ((mpdu->GetPacket()->GetSize() %
         (GetFragmentationThreshold() - mpdu->GetHeader().GetSize() - WIFI_MAC_FCS_LENGTH)) > 0)
    {
        nFragments++;
    }
    NS_LOG_DEBUG("WifiRemoteStationManager::GetNFragments returning " << nFragments);
    return nFragments;
}

uint32_t
WifiRemoteStationManager::GetFragmentSize(Ptr<const WifiMpdu> mpdu, uint32_t fragmentNumber)
{
    NS_LOG_FUNCTION(this << *mpdu << fragmentNumber);
    NS_ASSERT(!mpdu->GetHeader().GetAddr1().IsGroup());
    uint32_t nFragment = GetNFragments(mpdu);
    if (fragmentNumber >= nFragment)
    {
        NS_LOG_DEBUG("WifiRemoteStationManager::GetFragmentSize returning 0");
        return 0;
    }
    // Last fragment
    if (fragmentNumber == nFragment - 1)
    {
        uint32_t lastFragmentSize =
            mpdu->GetPacket()->GetSize() -
            (fragmentNumber *
             (GetFragmentationThreshold() - mpdu->GetHeader().GetSize() - WIFI_MAC_FCS_LENGTH));
        NS_LOG_DEBUG("WifiRemoteStationManager::GetFragmentSize returning " << lastFragmentSize);
        return lastFragmentSize;
    }
    // All fragments but the last, the number of bytes is (Threshold - WIFI_HEADER_SIZE - WIFI_FCS).
    else
    {
        uint32_t fragmentSize =
            GetFragmentationThreshold() - mpdu->GetHeader().GetSize() - WIFI_MAC_FCS_LENGTH;
        NS_LOG_DEBUG("WifiRemoteStationManager::GetFragmentSize returning " << fragmentSize);
        return fragmentSize;
    }
}

uint32_t
WifiRemoteStationManager::GetFragmentOffset(Ptr<const WifiMpdu> mpdu, uint32_t fragmentNumber)
{
    NS_LOG_FUNCTION(this << *mpdu << fragmentNumber);
    NS_ASSERT(!mpdu->GetHeader().GetAddr1().IsGroup());
    NS_ASSERT(fragmentNumber < GetNFragments(mpdu));
    uint32_t fragmentOffset = fragmentNumber * (GetFragmentationThreshold() -
                                                mpdu->GetHeader().GetSize() - WIFI_MAC_FCS_LENGTH);
    NS_LOG_DEBUG("WifiRemoteStationManager::GetFragmentOffset returning " << fragmentOffset);
    return fragmentOffset;
}

bool
WifiRemoteStationManager::IsLastFragment(Ptr<const WifiMpdu> mpdu, uint32_t fragmentNumber)
{
    NS_LOG_FUNCTION(this << *mpdu << fragmentNumber);
    NS_ASSERT(!mpdu->GetHeader().GetAddr1().IsGroup());
    bool isLast = fragmentNumber == (GetNFragments(mpdu) - 1);
    NS_LOG_DEBUG("WifiRemoteStationManager::IsLastFragment returning " << std::boolalpha << isLast);
    return isLast;
}

uint8_t
WifiRemoteStationManager::GetDefaultTxPowerLevel() const
{
    return m_defaultTxPowerLevel;
}

WifiRemoteStationInfo
WifiRemoteStationManager::GetInfo(Mac48Address address)
{
    return LookupState(address)->m_info;
}

std::optional<double>
WifiRemoteStationManager::GetMostRecentRssi(Mac48Address address) const
{
    auto station = Lookup(address);
    auto rssi = station->m_rssiAndUpdateTimePair.first;
    auto ts = station->m_rssiAndUpdateTimePair.second;
    if (ts.IsStrictlyPositive())
    {
        return rssi;
    }
    return std::nullopt;
}

std::shared_ptr<WifiRemoteStationState>
WifiRemoteStationManager::LookupState(Mac48Address address) const
{
    NS_LOG_FUNCTION(this << address);
    auto stateIt = m_states.find(address);

    if (stateIt != m_states.end())
    {
        NS_LOG_DEBUG("WifiRemoteStationManager::LookupState returning existing state");
        return stateIt->second;
    }

    auto state = std::make_shared<WifiRemoteStationState>();
    state->m_state = WifiRemoteStationState::BRAND_NEW;
    state->m_address = address;
    state->m_aid = 0;
    state->m_operationalRateSet.push_back(GetDefaultMode());
    state->m_operationalMcsSet.push_back(GetDefaultMcs());
    state->m_dsssSupported = false;
    state->m_erpOfdmSupported = false;
    state->m_ofdmSupported = false;
    state->m_htCapabilities = nullptr;
    state->m_vhtCapabilities = nullptr;
    state->m_heCapabilities = nullptr;
    state->m_ehtCapabilities = nullptr;
    state->m_mleCommonInfo = nullptr;
    state->m_emlsrEnabled = false;
    state->m_channelWidth = m_wifiPhy->GetChannelWidth();
    state->m_guardInterval = GetGuardInterval();
    state->m_ness = 0;
    state->m_aggregation = false;
    state->m_qosSupported = false;
    state->m_isInPsMode = false;
    const_cast<WifiRemoteStationManager*>(this)->m_states.insert({address, state});
    NS_LOG_DEBUG("WifiRemoteStationManager::LookupState returning new state");
    return state;
}

WifiRemoteStation*
WifiRemoteStationManager::Lookup(Mac48Address address) const
{
    NS_LOG_FUNCTION(this << address);
    NS_ASSERT(!address.IsGroup());
    NS_ASSERT(address != m_wifiMac->GetAddress());
    auto stationIt = m_stations.find(address);

    if (stationIt != m_stations.end())
    {
        return stationIt->second;
    }

    WifiRemoteStation* station = DoCreateStation();
    station->m_state = LookupState(address).get();
    station->m_rssiAndUpdateTimePair = std::make_pair(0, Seconds(0));
    const_cast<WifiRemoteStationManager*>(this)->m_stations.insert({address, station});
    return station;
}

void
WifiRemoteStationManager::SetAssociationId(Mac48Address remoteAddress, uint16_t aid)
{
    NS_LOG_FUNCTION(this << remoteAddress << aid);
    LookupState(remoteAddress)->m_aid = aid;
}

void
WifiRemoteStationManager::SetQosSupport(Mac48Address from, bool qosSupported)
{
    NS_LOG_FUNCTION(this << from << qosSupported);
    LookupState(from)->m_qosSupported = qosSupported;
}

void
WifiRemoteStationManager::SetEmlsrEnabled(const Mac48Address& from, bool emlsrEnabled)
{
    NS_LOG_FUNCTION(this << from << emlsrEnabled);
    LookupState(from)->m_emlsrEnabled = emlsrEnabled;
}

void
WifiRemoteStationManager::AddStationHtCapabilities(Mac48Address from, HtCapabilities htCapabilities)
{
    // Used by all stations to record HT capabilities of remote stations
    NS_LOG_FUNCTION(this << from << htCapabilities);
    auto state = LookupState(from);
    if (htCapabilities.GetSupportedChannelWidth() == 1)
    {
        state->m_channelWidth = 40;
    }
    else
    {
        state->m_channelWidth = 20;
    }
    SetQosSupport(from, true);
    for (const auto& mcs : m_wifiPhy->GetMcsList(WIFI_MOD_CLASS_HT))
    {
        if (htCapabilities.IsSupportedMcs(mcs.GetMcsValue()))
        {
            AddSupportedMcs(from, mcs);
        }
    }
    state->m_htCapabilities = Create<const HtCapabilities>(htCapabilities);
}

void
WifiRemoteStationManager::AddStationVhtCapabilities(Mac48Address from,
                                                    VhtCapabilities vhtCapabilities)
{
    // Used by all stations to record VHT capabilities of remote stations
    NS_LOG_FUNCTION(this << from << vhtCapabilities);
    auto state = LookupState(from);
    if (vhtCapabilities.GetSupportedChannelWidthSet() == 1)
    {
        state->m_channelWidth = 160;
    }
    else
    {
        state->m_channelWidth = 80;
    }
    for (uint8_t i = 1; i <= m_wifiPhy->GetMaxSupportedTxSpatialStreams(); i++)
    {
        for (const auto& mcs : m_wifiPhy->GetMcsList(WIFI_MOD_CLASS_VHT))
        {
            if (vhtCapabilities.IsSupportedMcs(mcs.GetMcsValue(), i))
            {
                AddSupportedMcs(from, mcs);
            }
        }
    }
    state->m_vhtCapabilities = Create<const VhtCapabilities>(vhtCapabilities);
}

void
WifiRemoteStationManager::AddStationHeCapabilities(Mac48Address from, HeCapabilities heCapabilities)
{
    // Used by all stations to record HE capabilities of remote stations
    NS_LOG_FUNCTION(this << from << heCapabilities);
    auto state = LookupState(from);
    if ((m_wifiPhy->GetPhyBand() == WIFI_PHY_BAND_5GHZ) ||
        (m_wifiPhy->GetPhyBand() == WIFI_PHY_BAND_6GHZ))
    {
        if (heCapabilities.GetChannelWidthSet() & 0x04)
        {
            state->m_channelWidth = 160;
        }
        else if (heCapabilities.GetChannelWidthSet() & 0x02)
        {
            state->m_channelWidth = 80;
        }
        // For other cases at 5 GHz, the supported channel width is set by the VHT capabilities
    }
    else if (m_wifiPhy->GetPhyBand() == WIFI_PHY_BAND_2_4GHZ)
    {
        if (heCapabilities.GetChannelWidthSet() & 0x01)
        {
            state->m_channelWidth = 40;
        }
        else
        {
            state->m_channelWidth = 20;
        }
    }
    if (heCapabilities.GetHeSuPpdu1xHeLtf800nsGi())
    {
        state->m_guardInterval = 800;
    }
    else
    {
        // todo: Using 3200ns, default value for HeConfiguration::GuardInterval
        state->m_guardInterval = 3200;
    }
    for (const auto& mcs : m_wifiPhy->GetMcsList(WIFI_MOD_CLASS_HE))
    {
        if (heCapabilities.GetHighestMcsSupported() >= mcs.GetMcsValue())
        {
            AddSupportedMcs(from, mcs);
        }
    }
    state->m_heCapabilities = Create<const HeCapabilities>(heCapabilities);
    SetQosSupport(from, true);
}

void
WifiRemoteStationManager::AddStationEhtCapabilities(Mac48Address from,
                                                    EhtCapabilities ehtCapabilities)
{
    // Used by all stations to record EHT capabilities of remote stations
    NS_LOG_FUNCTION(this << from << ehtCapabilities);
    auto state = LookupState(from);
    for (const auto& mcs : m_wifiPhy->GetMcsList(WIFI_MOD_CLASS_EHT))
    {
        for (uint8_t mapType = 0; mapType < EhtMcsAndNssSet::EHT_MCS_MAP_TYPE_MAX; ++mapType)
        {
            if (ehtCapabilities.GetHighestSupportedRxMcs(
                    static_cast<EhtMcsAndNssSet::EhtMcsMapType>(mapType)) >= mcs.GetMcsValue())
            {
                AddSupportedMcs(from, mcs);
            }
        }
    }
    state->m_ehtCapabilities = Create<const EhtCapabilities>(ehtCapabilities);
    SetQosSupport(from, true);
}

void
WifiRemoteStationManager::AddStationMleCommonInfo(
    Mac48Address from,
    const std::shared_ptr<CommonInfoBasicMle>& mleCommonInfo)
{
    NS_LOG_FUNCTION(this << from);
    auto state = LookupState(from);
    state->m_mleCommonInfo = mleCommonInfo;
    // insert another entry in m_states indexed by the MLD address and pointing to the same state
    const_cast<WifiRemoteStationManager*>(this)->m_states.insert(
        {mleCommonInfo->m_mldMacAddress, state});
}

Ptr<const HtCapabilities>
WifiRemoteStationManager::GetStationHtCapabilities(Mac48Address from)
{
    return LookupState(from)->m_htCapabilities;
}

Ptr<const VhtCapabilities>
WifiRemoteStationManager::GetStationVhtCapabilities(Mac48Address from)
{
    return LookupState(from)->m_vhtCapabilities;
}

Ptr<const HeCapabilities>
WifiRemoteStationManager::GetStationHeCapabilities(Mac48Address from)
{
    return LookupState(from)->m_heCapabilities;
}

Ptr<const EhtCapabilities>
WifiRemoteStationManager::GetStationEhtCapabilities(Mac48Address from)
{
    return LookupState(from)->m_ehtCapabilities;
}

std::optional<std::reference_wrapper<CommonInfoBasicMle::EmlCapabilities>>
WifiRemoteStationManager::GetStationEmlCapabilities(const Mac48Address& from)
{
    if (auto state = LookupState(from);
        state->m_mleCommonInfo && state->m_mleCommonInfo->m_emlCapabilities)
    {
        return state->m_mleCommonInfo->m_emlCapabilities.value();
    }
    return std::nullopt;
}

std::optional<std::reference_wrapper<CommonInfoBasicMle::MldCapabilities>>
WifiRemoteStationManager::GetStationMldCapabilities(const Mac48Address& from)
{
    if (auto state = LookupState(from);
        state->m_mleCommonInfo && state->m_mleCommonInfo->m_mldCapabilities)
    {
        return state->m_mleCommonInfo->m_mldCapabilities.value();
    }
    return std::nullopt;
}

bool
WifiRemoteStationManager::GetLdpcSupported(Mac48Address address) const
{
    Ptr<const HtCapabilities> htCapabilities = LookupState(address)->m_htCapabilities;
    Ptr<const VhtCapabilities> vhtCapabilities = LookupState(address)->m_vhtCapabilities;
    Ptr<const HeCapabilities> heCapabilities = LookupState(address)->m_heCapabilities;
    bool supported = false;
    if (htCapabilities)
    {
        supported |= htCapabilities->GetLdpc();
    }
    if (vhtCapabilities)
    {
        supported |= vhtCapabilities->GetRxLdpc();
    }
    if (heCapabilities)
    {
        supported |= heCapabilities->GetLdpcCodingInPayload();
    }
    return supported;
}

WifiMode
WifiRemoteStationManager::GetDefaultMode() const
{
    NS_ASSERT(m_wifiPhy);
    auto defaultTxMode = m_wifiPhy->GetDefaultMode();
    NS_ASSERT(defaultTxMode.IsMandatory());
    return defaultTxMode;
}

WifiMode
WifiRemoteStationManager::GetDefaultMcs() const
{
    return HtPhy::GetHtMcs0();
}

WifiMode
WifiRemoteStationManager::GetDefaultModeForSta(const WifiRemoteStation* st) const
{
    NS_LOG_FUNCTION(this << st);

    if (!GetHtSupported() || !GetHtSupported(st))
    {
        return GetDefaultMode();
    }

    // find the highest modulation class supported by both stations
    WifiModulationClass modClass = WIFI_MOD_CLASS_HT;
    if (GetHeSupported() && GetHeSupported(st))
    {
        modClass = WIFI_MOD_CLASS_HE;
    }
    else if (GetVhtSupported() && GetVhtSupported(st))
    {
        modClass = WIFI_MOD_CLASS_VHT;
    }

    // return the MCS with lowest index
    return *m_wifiPhy->GetPhyEntity(modClass)->begin();
}

void
WifiRemoteStationManager::Reset()
{
    NS_LOG_FUNCTION(this);
    m_states.clear();
    for (auto& state : m_stations)
    {
        delete (state.second);
    }
    m_stations.clear();
    m_bssBasicRateSet.clear();
    m_bssBasicMcsSet.clear();
    m_ssrc.fill(0);
    m_slrc.fill(0);
}

void
WifiRemoteStationManager::AddBasicMode(WifiMode mode)
{
    NS_LOG_FUNCTION(this << mode);
    if (mode.GetModulationClass() >= WIFI_MOD_CLASS_HT)
    {
        NS_FATAL_ERROR("It is not allowed to add a HT rate in the BSSBasicRateSet!");
    }
    for (uint8_t i = 0; i < GetNBasicModes(); i++)
    {
        if (GetBasicMode(i) == mode)
        {
            return;
        }
    }
    m_bssBasicRateSet.push_back(mode);
}

uint8_t
WifiRemoteStationManager::GetNBasicModes() const
{
    return static_cast<uint8_t>(m_bssBasicRateSet.size());
}

WifiMode
WifiRemoteStationManager::GetBasicMode(uint8_t i) const
{
    NS_ASSERT(i < GetNBasicModes());
    return m_bssBasicRateSet[i];
}

uint32_t
WifiRemoteStationManager::GetNNonErpBasicModes() const
{
    uint32_t size = 0;
    for (auto i = m_bssBasicRateSet.begin(); i != m_bssBasicRateSet.end(); i++)
    {
        if (i->GetModulationClass() == WIFI_MOD_CLASS_ERP_OFDM)
        {
            continue;
        }
        size++;
    }
    return size;
}

WifiMode
WifiRemoteStationManager::GetNonErpBasicMode(uint8_t i) const
{
    NS_ASSERT(i < GetNNonErpBasicModes());
    uint32_t index = 0;
    bool found = false;
    for (auto j = m_bssBasicRateSet.begin(); j != m_bssBasicRateSet.end();)
    {
        if (i == index)
        {
            found = true;
        }
        if (j->GetModulationClass() != WIFI_MOD_CLASS_ERP_OFDM)
        {
            if (found)
            {
                break;
            }
        }
        index++;
        j++;
    }
    return m_bssBasicRateSet[index];
}

void
WifiRemoteStationManager::AddBasicMcs(WifiMode mcs)
{
    NS_LOG_FUNCTION(this << +mcs.GetMcsValue());
    for (uint8_t i = 0; i < GetNBasicMcs(); i++)
    {
        if (GetBasicMcs(i) == mcs)
        {
            return;
        }
    }
    m_bssBasicMcsSet.push_back(mcs);
}

uint8_t
WifiRemoteStationManager::GetNBasicMcs() const
{
    return static_cast<uint8_t>(m_bssBasicMcsSet.size());
}

WifiMode
WifiRemoteStationManager::GetBasicMcs(uint8_t i) const
{
    NS_ASSERT(i < GetNBasicMcs());
    return m_bssBasicMcsSet[i];
}

WifiMode
WifiRemoteStationManager::GetNonUnicastMode() const
{
    if (m_nonUnicastMode == WifiMode())
    {
        if (GetNBasicModes() > 0)
        {
            return GetBasicMode(0);
        }
        else
        {
            return GetDefaultMode();
        }
    }
    else
    {
        return m_nonUnicastMode;
    }
}

bool
WifiRemoteStationManager::DoNeedRts(WifiRemoteStation* station, uint32_t size, bool normally)
{
    return normally;
}

bool
WifiRemoteStationManager::DoNeedRetransmission(WifiRemoteStation* station,
                                               Ptr<const Packet> packet,
                                               bool normally)
{
    return normally;
}

bool
WifiRemoteStationManager::DoNeedFragmentation(WifiRemoteStation* station,
                                              Ptr<const Packet> packet,
                                              bool normally)
{
    return normally;
}

void
WifiRemoteStationManager::DoReportAmpduTxStatus(WifiRemoteStation* station,
                                                uint16_t nSuccessfulMpdus,
                                                uint16_t nFailedMpdus,
                                                double rxSnr,
                                                double dataSnr,
                                                uint16_t dataChannelWidth,
                                                uint8_t dataNss)
{
    NS_LOG_DEBUG("DoReportAmpduTxStatus received but the manager does not handle A-MPDUs!");
}

WifiMode
WifiRemoteStationManager::GetSupported(const WifiRemoteStation* station, uint8_t i) const
{
    NS_ASSERT(i < GetNSupported(station));
    return station->m_state->m_operationalRateSet[i];
}

WifiMode
WifiRemoteStationManager::GetMcsSupported(const WifiRemoteStation* station, uint8_t i) const
{
    NS_ASSERT(i < GetNMcsSupported(station));
    return station->m_state->m_operationalMcsSet[i];
}

WifiMode
WifiRemoteStationManager::GetNonErpSupported(const WifiRemoteStation* station, uint8_t i) const
{
    NS_ASSERT(i < GetNNonErpSupported(station));
    // IEEE 802.11g standard defines that if the protection mechanism is enabled, RTS, CTS and
    // CTS-To-Self frames should select a rate in the BSSBasicRateSet that corresponds to an 802.11b
    // basic rate. This is a implemented here to avoid changes in every RAA, but should maybe be
    // moved in case it breaks standard rules.
    uint32_t index = 0;
    bool found = false;
    for (auto j = station->m_state->m_operationalRateSet.begin();
         j != station->m_state->m_operationalRateSet.end();)
    {
        if (i == index)
        {
            found = true;
        }
        if (j->GetModulationClass() != WIFI_MOD_CLASS_ERP_OFDM)
        {
            if (found)
            {
                break;
            }
        }
        index++;
        j++;
    }
    return station->m_state->m_operationalRateSet[index];
}

Mac48Address
WifiRemoteStationManager::GetAddress(const WifiRemoteStation* station) const
{
    return station->m_state->m_address;
}

uint16_t
WifiRemoteStationManager::GetChannelWidth(const WifiRemoteStation* station) const
{
    return station->m_state->m_channelWidth;
}

bool
WifiRemoteStationManager::GetShortGuardIntervalSupported(const WifiRemoteStation* station) const
{
    Ptr<const HtCapabilities> htCapabilities = station->m_state->m_htCapabilities;

    if (!htCapabilities)
    {
        return false;
    }
    return htCapabilities->GetShortGuardInterval20();
}

uint16_t
WifiRemoteStationManager::GetGuardInterval(const WifiRemoteStation* station) const
{
    return station->m_state->m_guardInterval;
}

bool
WifiRemoteStationManager::GetAggregation(const WifiRemoteStation* station) const
{
    return station->m_state->m_aggregation;
}

uint8_t
WifiRemoteStationManager::GetNumberOfSupportedStreams(const WifiRemoteStation* station) const
{
    Ptr<const HtCapabilities> htCapabilities = station->m_state->m_htCapabilities;

    if (!htCapabilities)
    {
        return 1;
    }
    return htCapabilities->GetRxHighestSupportedAntennas();
}

uint8_t
WifiRemoteStationManager::GetNess(const WifiRemoteStation* station) const
{
    return station->m_state->m_ness;
}

Ptr<WifiPhy>
WifiRemoteStationManager::GetPhy() const
{
    return m_wifiPhy;
}

Ptr<WifiMac>
WifiRemoteStationManager::GetMac() const
{
    return m_wifiMac;
}

uint8_t
WifiRemoteStationManager::GetNSupported(const WifiRemoteStation* station) const
{
    return static_cast<uint8_t>(station->m_state->m_operationalRateSet.size());
}

bool
WifiRemoteStationManager::GetQosSupported(const WifiRemoteStation* station) const
{
    return station->m_state->m_qosSupported;
}

bool
WifiRemoteStationManager::GetHtSupported(const WifiRemoteStation* station) const
{
    return bool(station->m_state->m_htCapabilities);
}

bool
WifiRemoteStationManager::GetVhtSupported(const WifiRemoteStation* station) const
{
    return bool(station->m_state->m_vhtCapabilities);
}

bool
WifiRemoteStationManager::GetHeSupported(const WifiRemoteStation* station) const
{
    return bool(station->m_state->m_heCapabilities);
}

bool
WifiRemoteStationManager::GetEhtSupported(const WifiRemoteStation* station) const
{
    return (bool)(station->m_state->m_ehtCapabilities);
}

bool
WifiRemoteStationManager::GetEmlsrSupported(const WifiRemoteStation* station) const
{
    auto mleCommonInfo = station->m_state->m_mleCommonInfo;
    return mleCommonInfo && mleCommonInfo->m_emlCapabilities &&
           mleCommonInfo->m_emlCapabilities->emlsrSupport == 1;
}

bool
WifiRemoteStationManager::GetEmlsrEnabled(const WifiRemoteStation* station) const
{
    return station->m_state->m_emlsrEnabled;
}

uint8_t
WifiRemoteStationManager::GetNMcsSupported(const WifiRemoteStation* station) const
{
    return static_cast<uint8_t>(station->m_state->m_operationalMcsSet.size());
}

uint32_t
WifiRemoteStationManager::GetNNonErpSupported(const WifiRemoteStation* station) const
{
    uint32_t size = 0;
    for (auto i = station->m_state->m_operationalRateSet.begin();
         i != station->m_state->m_operationalRateSet.end();
         i++)
    {
        if (i->GetModulationClass() == WIFI_MOD_CLASS_ERP_OFDM)
        {
            continue;
        }
        size++;
    }
    return size;
}

uint16_t
WifiRemoteStationManager::GetChannelWidthSupported(Mac48Address address) const
{
    return LookupState(address)->m_channelWidth;
}

bool
WifiRemoteStationManager::GetShortGuardIntervalSupported(Mac48Address address) const
{
    Ptr<const HtCapabilities> htCapabilities = LookupState(address)->m_htCapabilities;

    if (!htCapabilities)
    {
        return false;
    }
    return htCapabilities->GetShortGuardInterval20();
}

uint8_t
WifiRemoteStationManager::GetNumberOfSupportedStreams(Mac48Address address) const
{
    Ptr<const HtCapabilities> htCapabilities = LookupState(address)->m_htCapabilities;

    if (!htCapabilities)
    {
        return 1;
    }
    return htCapabilities->GetRxHighestSupportedAntennas();
}

uint8_t
WifiRemoteStationManager::GetNMcsSupported(Mac48Address address) const
{
    return static_cast<uint8_t>(LookupState(address)->m_operationalMcsSet.size());
}

bool
WifiRemoteStationManager::GetDsssSupported(const Mac48Address& address) const
{
    return (LookupState(address)->m_dsssSupported);
}

bool
WifiRemoteStationManager::GetErpOfdmSupported(const Mac48Address& address) const
{
    return (LookupState(address)->m_erpOfdmSupported);
}

bool
WifiRemoteStationManager::GetOfdmSupported(const Mac48Address& address) const
{
    return (LookupState(address)->m_ofdmSupported);
}

bool
WifiRemoteStationManager::GetHtSupported(Mac48Address address) const
{
    return bool(LookupState(address)->m_htCapabilities);
}

bool
WifiRemoteStationManager::GetVhtSupported(Mac48Address address) const
{
    return bool(LookupState(address)->m_vhtCapabilities);
}

bool
WifiRemoteStationManager::GetHeSupported(Mac48Address address) const
{
    return bool(LookupState(address)->m_heCapabilities);
}

bool
WifiRemoteStationManager::GetEhtSupported(Mac48Address address) const
{
    return (bool)(LookupState(address)->m_ehtCapabilities);
}

bool
WifiRemoteStationManager::GetEmlsrSupported(const Mac48Address& address) const
{
    auto mleCommonInfo = LookupState(address)->m_mleCommonInfo;
    return mleCommonInfo && mleCommonInfo->m_emlCapabilities &&
           mleCommonInfo->m_emlCapabilities->emlsrSupport == 1;
}

bool
WifiRemoteStationManager::GetEmlsrEnabled(const Mac48Address& address) const
{
    if (auto stateIt = m_states.find(address); stateIt != m_states.cend())
    {
        return stateIt->second->m_emlsrEnabled;
    }
    return false;
}

void
WifiRemoteStationManager::SetDefaultTxPowerLevel(uint8_t txPower)
{
    m_defaultTxPowerLevel = txPower;
}

uint8_t
WifiRemoteStationManager::GetNumberOfAntennas() const
{
    return m_wifiPhy->GetNumberOfAntennas();
}

uint8_t
WifiRemoteStationManager::GetMaxNumberOfTransmitStreams() const
{
    return m_wifiPhy->GetMaxSupportedTxSpatialStreams();
}

bool
WifiRemoteStationManager::UseLdpcForDestination(Mac48Address dest) const
{
    return (GetLdpcSupported() && GetLdpcSupported(dest));
}

} // namespace ns3
