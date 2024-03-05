/*
 * Copyright (c) 2008 INRIA
 * Copyright (c) 2009 MIRKO BANCHI
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
 * Authors: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 *          Mirko Banchi <mk.banchi@gmail.com>
 */

#ifndef WIFI_HELPER_H
#define WIFI_HELPER_H

#include "wifi-mac-helper.h"

#include "ns3/qos-utils.h"
#include "ns3/trace-helper.h"
#include "ns3/wifi-phy.h"

#include <functional>
#include <vector>

namespace ns3
{

class WifiNetDevice;
class Node;
class RadiotapHeader;
class QueueItem;

/**
 * \brief create PHY objects
 *
 * This base class must be implemented by new PHY implementation which wish to integrate
 * with the \ref ns3::WifiHelper class.
 */
class WifiPhyHelper : public PcapHelperForDevice, public AsciiTraceHelperForDevice
{
  public:
    /**
     * Constructor
     *
     * \param nLinks the number of links to configure (>1 only for 11be devices)
     */
    WifiPhyHelper(uint8_t nLinks = 1);
    ~WifiPhyHelper() override;

    /**
     * \param node the node on which the PHY object(s) will reside
     * \param device the device within which the PHY object(s) will reside
     *
     * \returns new PHY objects.
     *
     * Subclasses must implement this method to allow the ns3::WifiHelper class
     * to create PHY objects from ns3::WifiHelper::Install.
     */
    virtual std::vector<Ptr<WifiPhy>> Create(Ptr<Node> node, Ptr<WifiNetDevice> device) const = 0;

    /**
     * \param name the name of the attribute to set
     * \param v the value of the attribute
     *
     * Set an attribute of all the underlying PHY object.
     */
    void Set(std::string name, const AttributeValue& v);

    /**
     * \param name the name of the attribute to set
     * \param v the value of the attribute
     * \param linkId ID of the link to configure (>0 only for 11be devices)
     *
     * Set an attribute of the given underlying PHY object.
     */
    void Set(uint8_t linkId, std::string name, const AttributeValue& v);

    /**
     * Helper function used to set the interference helper.
     *
     * \tparam Args \deduced Template type parameter pack for the sequence of name-value pairs.
     * \param type the type of interference helper
     * \param args A sequence of name-value pairs of the attributes to set.
     */
    template <typename... Args>
    void SetInterferenceHelper(std::string type, Args&&... args);

    /**
     * Helper function used to set the error rate model.
     *
     * \tparam Args \deduced Template type parameter pack for the sequence of name-value pairs.
     * \param type the type of error rate model
     * \param args A sequence of name-value pairs of the attributes to set.
     */
    template <typename... Args>
    void SetErrorRateModel(std::string type, Args&&... args);

    /**
     * \tparam Args \deduced Template type parameter pack for the sequence of name-value pairs.
     * \param linkId ID of the link to configure (>0 only for 11be devices)
     * \param type the type of the error rate model to set.
     * \param args A sequence of name-value pairs of the attributes to set.
     *
     * Set the error rate model and its attributes to use for the given link when Install is called.
     */
    template <typename... Args>
    void SetErrorRateModel(uint8_t linkId, std::string type, Args&&... args);

    /**
     * Helper function used to set the frame capture model.
     *
     * \tparam Args \deduced Template type parameter pack for the sequence of name-value pairs.
     * \param type the type of frame capture model
     * \param args A sequence of name-value pairs of the attributes to set.
     */
    template <typename... Args>
    void SetFrameCaptureModel(std::string type, Args&&... args);

    /**
     * \tparam Args \deduced Template type parameter pack for the sequence of name-value pairs.
     * \param linkId ID of the link to configure (>0 only for 11be devices)
     * \param type the type of the frame capture model to set.
     * \param args A sequence of name-value pairs of the attributes to set.
     *
     * Set the frame capture model and its attributes to use for the given link when Install is
     * called.
     */
    template <typename... Args>
    void SetFrameCaptureModel(uint8_t linkId, std::string type, Args&&... args);

    /**
     * Helper function used to set the preamble detection model.
     *
     * \tparam Args \deduced Template type parameter pack for the sequence of name-value pairs.
     * \param type the type of preamble detection model
     * \param args A sequence of name-value pairs of the attributes to set.
     */
    template <typename... Args>
    void SetPreambleDetectionModel(std::string type, Args&&... args);

    /**
     * \tparam Args \deduced Template type parameter pack for the sequence of name-value pairs.
     * \param linkId ID of the link to configure (>0 only for 11be devices)
     * \param type the type of the preamble detection model to set.
     * \param args A sequence of name-value pairs of the attributes to set.
     *
     * Set the preamble detection model and its attributes to use for the given link when Install is
     * called.
     */
    template <typename... Args>
    void SetPreambleDetectionModel(uint8_t linkId, std::string type, Args&&... args);

    /**
     * Disable the preamble detection model on all links.
     */
    void DisablePreambleDetectionModel();

    /**
     * An enumeration of the pcap data link types (DLTs) which this helper
     * supports.  See http://wiki.wireshark.org/Development/LibpcapFileFormat
     * for more information on these formats.
     */
    enum SupportedPcapDataLinkTypes
    {
        DLT_IEEE802_11 =
            PcapHelper::DLT_IEEE802_11, /**< IEEE 802.11 Wireless LAN headers on packets */
        DLT_PRISM_HEADER =
            PcapHelper::DLT_PRISM_HEADER, /**< Include Prism monitor mode information */
        DLT_IEEE802_11_RADIO =
            PcapHelper::DLT_IEEE802_11_RADIO /**< Include Radiotap link layer information */
    };

    /**
     * Set the data link type of PCAP traces to be used. This function has to be
     * called before EnablePcap(), so that the header of the pcap file can be
     * written correctly.
     *
     * \see SupportedPcapDataLinkTypes
     *
     * \param dlt The data link type of the pcap file (and packets) to be used
     */
    void SetPcapDataLinkType(SupportedPcapDataLinkTypes dlt);

    /**
     * Get the data link type of PCAP traces to be used.
     *
     * \see SupportedPcapDataLinkTypes
     *
     * \returns The data link type of the pcap file (and packets) to be used
     */
    PcapHelper::DataLinkType GetPcapDataLinkType() const;

  protected:
    /**
     * \param file the pcap file wrapper
     * \param packet the packet
     * \param channelFreqMhz the channel frequency
     * \param txVector the TXVECTOR
     * \param aMpdu the A-MPDU information
     * \param staId the STA-ID (only used for MU)
     *
     * Handle TX pcap.
     */
    static void PcapSniffTxEvent(Ptr<PcapFileWrapper> file,
                                 Ptr<const Packet> packet,
                                 uint16_t channelFreqMhz,
                                 WifiTxVector txVector,
                                 MpduInfo aMpdu,
                                 uint16_t staId = SU_STA_ID);
    /**
     * \param file the pcap file wrapper
     * \param packet the packet
     * \param channelFreqMhz the channel frequency
     * \param txVector the TXVECTOR
     * \param aMpdu the A-MPDU information
     * \param signalNoise the RX signal and noise information
     * \param staId the STA-ID (only used for MU)
     *
     * Handle RX pcap.
     */
    static void PcapSniffRxEvent(Ptr<PcapFileWrapper> file,
                                 Ptr<const Packet> packet,
                                 uint16_t channelFreqMhz,
                                 WifiTxVector txVector,
                                 MpduInfo aMpdu,
                                 SignalNoiseDbm signalNoise,
                                 uint16_t staId = SU_STA_ID);

    std::vector<ObjectFactory> m_phys;                   ///< PHY objects
    ObjectFactory m_interferenceHelper;                  ///< interference helper
    std::vector<ObjectFactory> m_errorRateModel;         ///< error rate model
    std::vector<ObjectFactory> m_frameCaptureModel;      ///< frame capture model
    std::vector<ObjectFactory> m_preambleDetectionModel; ///< preamble detection model

  private:
    /**
     * Get the Radiotap header for a transmitted packet.
     *
     * \param header the radiotap header to be filled in
     * \param packet the packet
     * \param channelFreqMhz the channel frequency
     * \param txVector the TXVECTOR
     * \param aMpdu the A-MPDU information
     * \param staId the STA-ID
     */
    static void GetRadiotapHeader(RadiotapHeader& header,
                                  Ptr<Packet> packet,
                                  uint16_t channelFreqMhz,
                                  WifiTxVector txVector,
                                  MpduInfo aMpdu,
                                  uint16_t staId);

    /**
     * Get the Radiotap header for a received packet.
     *
     * \param header the radiotap header to be filled in
     * \param packet the packet
     * \param channelFreqMhz the channel frequency
     * \param txVector the TXVECTOR
     * \param aMpdu the A-MPDU information
     * \param staId the STA-ID
     * \param signalNoise the rx signal and noise information
     */
    static void GetRadiotapHeader(RadiotapHeader& header,
                                  Ptr<Packet> packet,
                                  uint16_t channelFreqMhz,
                                  WifiTxVector txVector,
                                  MpduInfo aMpdu,
                                  uint16_t staId,
                                  SignalNoiseDbm signalNoise);

    /**
     * \brief Enable pcap output the indicated net device.
     *
     * NetDevice-specific implementation mechanism for hooking the trace and
     * writing to the trace file.
     *
     * \param prefix Filename prefix to use for pcap files.
     * \param nd Net device for which you want to enable tracing.
     * \param promiscuous If true capture all possible packets available at the device.
     * \param explicitFilename Treat the prefix as an explicit filename if true
     */
    void EnablePcapInternal(std::string prefix,
                            Ptr<NetDevice> nd,
                            bool promiscuous,
                            bool explicitFilename) override;

    /**
     * \brief Enable ASCII trace output on the indicated net device.
     *
     * NetDevice-specific implementation mechanism for hooking the trace and
     * writing to the trace file.
     *
     * \param stream The output stream object to use when logging ASCII traces.
     * \param prefix Filename prefix to use for ASCII trace files.
     * \param nd Net device for which you want to enable tracing.
     * \param explicitFilename Treat the prefix as an explicit filename if true
     */
    void EnableAsciiInternal(Ptr<OutputStreamWrapper> stream,
                             std::string prefix,
                             Ptr<NetDevice> nd,
                             bool explicitFilename) override;

    PcapHelper::DataLinkType m_pcapDlt; ///< PCAP data link type
};

/**
 * \brief helps to create WifiNetDevice objects
 *
 * This class can help to create a large set of similar
 * WifiNetDevice objects and to configure a large set of
 * their attributes during creation.
 */
class WifiHelper
{
  public:
    virtual ~WifiHelper();

    /**
     * Create a Wifi helper in an empty state: all its parameters
     * must be set before calling ns3::WifiHelper::Install
     *
     * The default state is defined as being an Adhoc MAC layer with an ARF rate control algorithm
     * and both objects using their default attribute values.
     * By default, configure MAC and PHY for 802.11a.
     */
    WifiHelper();

    /**
     * Helper function used to set the station manager
     *
     * \tparam Args \deduced Template type parameter pack for the sequence of name-value pairs.
     * \param type the type of station manager
     * \param args A sequence of name-value pairs of the attributes to set.
     */
    template <typename... Args>
    void SetRemoteStationManager(std::string type, Args&&... args);

    /**
     * \tparam Args \deduced Template type parameter pack for the sequence of name-value pairs.
     * \param linkId ID of the link to configure (>0 only for 11be devices)
     * \param type the type of the preamble detection model to set.
     * \param args A sequence of name-value pairs of the attributes to set.
     *
     * Set the remote station manager model and its attributes to use for the given link.
     * If the helper stored a remote station manager model for the first N links only
     * (corresponding to link IDs from 0 to N-1) and the given linkId is M >= N, then a
     * remote station manager model using the given attributes is configured for all links
     * with ID from N to M.
     */
    template <typename... Args>
    void SetRemoteStationManager(uint8_t linkId, std::string type, Args&&... args);

    /**
     * Helper function used to set the OBSS-PD algorithm
     *
     * \tparam Args \deduced Template type parameter pack for the sequence of name-value pairs.
     * \param type the type of OBSS-PD algorithm
     * \param args A sequence of name-value pairs of the attributes to set.
     */
    template <typename... Args>
    void SetObssPdAlgorithm(std::string type, Args&&... args);

    /// Callback invoked to determine the MAC queue selected for a given packet
    typedef std::function<std::size_t(Ptr<QueueItem>)> SelectQueueCallback;

    /**
     * \param f the select queue callback
     *
     * Set the select queue callback to set on the NetDevice queue interface aggregated
     * to the WifiNetDevice, in case WifiMac with QoS enabled is used
     */
    void SetSelectQueueCallback(SelectQueueCallback f);

    /**
     * Disable flow control only if you know what you are doing. By disabling
     * flow control, this NetDevice will be sent packets even if there is no
     * room for them (such packets will be likely dropped by this NetDevice).
     * Also, any queue disc installed on this NetDevice will have no effect,
     * as every packet enqueued to the traffic control layer queue disc will
     * be immediately dequeued.
     */
    void DisableFlowControl();

    /**
     * \param phy the PHY helper to create PHY objects
     * \param mac the MAC helper to create MAC objects
     * \param first lower bound on the set of nodes on which a wifi device must be created
     * \param last upper bound on the set of nodes on which a wifi device must be created
     * \returns a device container which contains all the devices created by this method.
     */
    NetDeviceContainer virtual Install(const WifiPhyHelper& phy,
                                       const WifiMacHelper& mac,
                                       NodeContainer::Iterator first,
                                       NodeContainer::Iterator last) const;
    /**
     * \param phy the PHY helper to create PHY objects
     * \param mac the MAC helper to create MAC objects
     * \param c the set of nodes on which a wifi device must be created
     * \returns a device container which contains all the devices created by this method.
     */
    virtual NetDeviceContainer Install(const WifiPhyHelper& phy,
                                       const WifiMacHelper& mac,
                                       NodeContainer c) const;
    /**
     * \param phy the PHY helper to create PHY objects
     * \param mac the MAC helper to create MAC objects
     * \param node the node on which a wifi device must be created
     * \returns a device container which contains all the devices created by this method.
     */
    virtual NetDeviceContainer Install(const WifiPhyHelper& phy,
                                       const WifiMacHelper& mac,
                                       Ptr<Node> node) const;
    /**
     * \param phy the PHY helper to create PHY objects
     * \param mac the MAC helper to create MAC objects
     * \param nodeName the name of node on which a wifi device must be created
     * \returns a device container which contains all the devices created by this method.
     */
    virtual NetDeviceContainer Install(const WifiPhyHelper& phy,
                                       const WifiMacHelper& mac,
                                       std::string nodeName) const;
    /**
     * \param standard the standard to configure during installation
     *
     * This method sets standards-compliant defaults for WifiMac
     * parameters such as SIFS time, slot time, timeout values, etc.,
     * based on the standard selected.  It results in
     * WifiMac::ConfigureStandard(standard) being called on each
     * installed MAC object.
     *
     * The default standard of 802.11a will be applied if SetStandard()
     * is not called.
     *
     * Note that WifiMac::ConfigureStandard () will overwrite certain
     * defaults in the attribute system, so if a user wants to manipulate
     * any default values affected by ConfigureStandard() while using this
     * helper, the user should use a post-install configuration such as
     * Config::Set() on any objects that this helper creates, such as:
     * \code
     * Config::Set ("/NodeList/0/DeviceList/0/$ns3::WifiNetDevice/Mac/Slot", TimeValue (MicroSeconds
     * (slot))); \endcode
     *
     * \sa WifiMac::ConfigureStandard
     * \sa Config::Set
     */
    virtual void SetStandard(WifiStandard standard);

    /**
     * Helper function used to configure the HT options listed as attributes of
     * the HtConfiguration class.
     *
     * \tparam Args \deduced Template type parameter pack for the sequence of name-value pairs.
     * \param args A sequence of name-value pairs of the attributes to set.
     */
    template <typename... Args>
    void ConfigHtOptions(Args&&... args);

    /**
     * Helper function used to configure the VHT options listed as attributes of
     * the VhtConfiguration class.
     *
     * \tparam Args \deduced Template type parameter pack for the sequence of name-value pairs.
     * \param args A sequence of name-value pairs of the attributes to set.
     */
    template <typename... Args>
    void ConfigVhtOptions(Args&&... args);

    /**
     * Helper function used to configure the HE options listed as attributes of
     * the HeConfiguration class.
     *
     * \tparam Args \deduced Template type parameter pack for the sequence of name-value pairs.
     * \param args A sequence of name-value pairs of the attributes to set.
     */
    template <typename... Args>
    void ConfigHeOptions(Args&&... args);

    /**
     * Helper function used to configure the EHT options listed as attributes of
     * the EhtConfiguration class.
     *
     * \tparam Args \deduced Template type parameter pack for the sequence of name-value pairs.
     * \param args A sequence of name-value pairs of the attributes to set.
     */
    template <typename... Args>
    void ConfigEhtOptions(Args&&... args);

    /**
     * Helper to enable all WifiNetDevice log components with one statement
     */
    static void EnableLogComponents();

    /**
     * Assign a fixed random variable stream number to the random variables
     * used by the PHY and MAC aspects of the Wifi models.  Each device in
     * container c has fixed stream numbers assigned to its random variables.
     * The Wifi channel (e.g. propagation loss model) is excluded.
     * Return the number of streams (possibly zero) that
     * have been assigned. The Install() method should have previously been
     * called by the user.
     *
     * \param c NetDeviceContainer of the set of net devices for which the
     *          WifiNetDevice should be modified to use fixed streams
     * \param stream first stream index to use
     * \return the number of stream indices assigned by this helper
     */
    int64_t AssignStreams(NetDeviceContainer c, int64_t stream);

  protected:
    mutable std::vector<ObjectFactory> m_stationManager; ///< station manager
    WifiStandard m_standard;                             ///< wifi standard
    ObjectFactory m_htConfig;                            ///< HT configuration
    ObjectFactory m_vhtConfig;                           ///< VHT configuration
    ObjectFactory m_heConfig;                            ///< HE configuration
    ObjectFactory m_ehtConfig;                           ///< EHT configuration
    SelectQueueCallback m_selectQueueCallback;           ///< select queue callback
    ObjectFactory m_obssPdAlgorithm;                     ///< OBSS_PD algorithm
    bool m_enableFlowControl;                            //!< whether to enable flow control
};

} // namespace ns3

/***************************************************************
 *  Implementation of the templates declared above.
 ***************************************************************/

namespace ns3
{

template <typename... Args>
void
WifiPhyHelper::SetInterferenceHelper(std::string type, Args&&... args)
{
    m_interferenceHelper.SetTypeId(type);
    m_interferenceHelper.Set(args...);
}

template <typename... Args>
void
WifiPhyHelper::SetErrorRateModel(std::string type, Args&&... args)
{
    for (std::size_t linkId = 0; linkId < m_phys.size(); linkId++)
    {
        SetErrorRateModel(linkId, type, std::forward<Args>(args)...);
    }
}

template <typename... Args>
void
WifiPhyHelper::SetErrorRateModel(uint8_t linkId, std::string type, Args&&... args)
{
    m_errorRateModel.at(linkId).SetTypeId(type);
    m_errorRateModel.at(linkId).Set(args...);
}

template <typename... Args>
void
WifiPhyHelper::SetFrameCaptureModel(std::string type, Args&&... args)
{
    for (std::size_t linkId = 0; linkId < m_phys.size(); linkId++)
    {
        SetFrameCaptureModel(linkId, type, std::forward<Args>(args)...);
    }
}

template <typename... Args>
void
WifiPhyHelper::SetFrameCaptureModel(uint8_t linkId, std::string type, Args&&... args)
{
    m_frameCaptureModel.at(linkId).SetTypeId(type);
    m_frameCaptureModel.at(linkId).Set(args...);
}

template <typename... Args>
void
WifiPhyHelper::SetPreambleDetectionModel(std::string type, Args&&... args)
{
    for (std::size_t linkId = 0; linkId < m_phys.size(); linkId++)
    {
        SetPreambleDetectionModel(linkId, type, std::forward<Args>(args)...);
    }
}

template <typename... Args>
void
WifiPhyHelper::SetPreambleDetectionModel(uint8_t linkId, std::string type, Args&&... args)
{
    m_preambleDetectionModel.at(linkId).SetTypeId(type);
    m_preambleDetectionModel.at(linkId).Set(args...);
}

template <typename... Args>
void
WifiHelper::SetRemoteStationManager(std::string type, Args&&... args)
{
    SetRemoteStationManager(0, type, std::forward<Args>(args)...);
}

template <typename... Args>
void
WifiHelper::SetRemoteStationManager(uint8_t linkId, std::string type, Args&&... args)
{
    if (m_stationManager.size() > linkId)
    {
        m_stationManager[linkId] = ObjectFactory(type, std::forward<Args>(args)...);
    }
    else
    {
        m_stationManager.resize(linkId + 1, ObjectFactory(type, std::forward<Args>(args)...));
    }
}

template <typename... Args>
void
WifiHelper::SetObssPdAlgorithm(std::string type, Args&&... args)
{
    m_obssPdAlgorithm.SetTypeId(type);
    m_obssPdAlgorithm.Set(args...);
}

template <typename... Args>
void
WifiHelper::ConfigHtOptions(Args&&... args)
{
    m_htConfig.Set(args...);
}

template <typename... Args>
void
WifiHelper::ConfigVhtOptions(Args&&... args)
{
    m_vhtConfig.Set(args...);
}

template <typename... Args>
void
WifiHelper::ConfigHeOptions(Args&&... args)
{
    m_heConfig.Set(args...);
}

template <typename... Args>
void
WifiHelper::ConfigEhtOptions(Args&&... args)
{
    m_ehtConfig.Set(args...);
}

} // namespace ns3

#endif /* WIFI_HELPER_H */
