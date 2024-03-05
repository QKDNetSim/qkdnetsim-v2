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
 * Authors: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 *          Ghada Badawy <gbadawy@gmail.com>
 *          Sébastien Deronne <sebastien.deronne@gmail.com>
 *
 * Ported from yans-wifi-phy.h by several contributors starting
 * with Nicola Baldo and Dean Armstrong
 */

#ifndef SPECTRUM_WIFI_PHY_H
#define SPECTRUM_WIFI_PHY_H

#include "wifi-phy.h"

#include "ns3/antenna-model.h"

#include <map>
#include <optional>

class SpectrumWifiPhyFilterTest;

namespace ns3
{

class SpectrumChannel;
struct SpectrumSignalParameters;
class WifiSpectrumPhyInterface;
struct WifiSpectrumSignalParameters;

/// Map a spectrum band associated with an RU to the RU specification
using HeRuBands = std::map<WifiSpectrumBandInfo, HeRu::RuSpec>;

/**
 * \brief 802.11 PHY layer model
 * \ingroup wifi
 *
 * This PHY implements a spectrum-aware enhancement of the 802.11 SpectrumWifiPhy
 * model.
 *
 * This PHY model depends on a channel loss and delay
 * model as provided by the ns3::SpectrumPropagationLossModel
 * and ns3::PropagationDelayModel classes.
 *
 */
class SpectrumWifiPhy : public WifiPhy
{
  public:
    /// allow SpectrumWifiPhyFilterTest class access
    friend class ::SpectrumWifiPhyFilterTest;

    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();

    SpectrumWifiPhy();
    ~SpectrumWifiPhy() override;

    // Implementation of pure virtual method.
    void SetDevice(const Ptr<WifiNetDevice> device) override;
    void StartTx(Ptr<const WifiPpdu> ppdu) override;
    Ptr<Channel> GetChannel() const override;
    uint16_t GetGuardBandwidth(uint16_t currentChannelWidth) const override;
    std::tuple<double, double, double> GetTxMaskRejectionParams() const override;
    WifiSpectrumBandInfo GetBand(uint16_t bandWidth, uint8_t bandIndex = 0) override;
    FrequencyRange GetCurrentFrequencyRange() const override;
    WifiSpectrumBandFrequencies ConvertIndicesToFrequencies(
        const WifiSpectrumBandIndices& indices) const override;

    /**
     * Attach a SpectrumChannel to use for a given frequency range.
     *
     * \param channel the SpectrumChannel to attach
     * \param freqRange the frequency range, bounded by a minFrequency and a maxFrequency in MHz
     */
    void AddChannel(const Ptr<SpectrumChannel> channel,
                    const FrequencyRange& freqRange = WHOLE_WIFI_SPECTRUM);

    /**
     * Input method for delivering a signal from the spectrum channel
     * and low-level PHY interface to this SpectrumWifiPhy instance.
     *
     * \param rxParams Input signal parameters
     * \param interface the Spectrum PHY interface for which the signal has been detected
     */
    void StartRx(Ptr<SpectrumSignalParameters> rxParams,
                 Ptr<const WifiSpectrumPhyInterface> interface);

    /**
     * \param antenna an AntennaModel to include in the transmitted
     *                SpectrumSignalParameters (in case any objects downstream of the
     *                SpectrumWifiPhy wish to adjust signal properties based on the
     *                transmitted antenna model.  This antenna is also used when
     *                the underlying WifiSpectrumPhyInterface::GetAntenna() method
     *                is called.
     *
     * Note:  this method may be split into separate SetTx and SetRx
     * methods in the future if the modeling need for this arises
     */
    void SetAntenna(const Ptr<AntennaModel> antenna);
    /**
     * Get the antenna model used for reception
     *
     * \return the AntennaModel used for reception
     */
    Ptr<AntennaModel> GetAntenna() const;

    /**
     * Callback invoked when the PHY model starts to process a signal
     *
     * \param signalType Whether signal is WiFi (true) or foreign (false)
     * \param senderNodeId Node Id of the sender of the signal
     * \param rxPower received signal power (dBm)
     * \param duration Signal duration
     */
    typedef void (*SignalArrivalCallback)(bool signalType,
                                          uint32_t senderNodeId,
                                          double rxPower,
                                          Time duration);

    /**
     * Configure a non-active spectrum PHY interface to operate on a given frequency with a given
     * width. The function searches for the non-active PHY interface that operates on the frequency
     * range corresponding to the spectrum portion specified by the caller. It takes care to
     * configure the RX spectrum model of the PHY interface and to update the bands tracked in
     * interference helper.
     *
     * \param frequency the center frequency in MHz the PHY interface should use
     * \param width the channel width in MHz the PHY interface should use
     */
    void ConfigureInterface(uint16_t frequency, uint16_t width);

    /**
     * This function is sending the signal to the Spectrum channel
     * after finishing the configuration of the transmit parameters.
     *
     * \param txParams the parameters to be provided to the Spectrum channel
     */
    void Transmit(Ptr<WifiSpectrumSignalParameters> txParams);

    /**
     * Determine the WifiPpdu to be used by the RX PHY based on the WifiPpdu sent by the TX PHY.
     *
     * \param ppdu the WifiPpdu transmitted by the TX PHY
     * \return the WifiPpdu to be used by the RX PHY
     */
    Ptr<const WifiPpdu> GetRxPpduFromTxPpdu(Ptr<const WifiPpdu> ppdu);

    /**
     * Get the currently active spectrum PHY interface
     *
     * \return the current spectrum PHY interface
     */
    Ptr<WifiSpectrumPhyInterface> GetCurrentInterface() const;

    /**
     * Get the map of interfaces attached to this spectrum PHY
     *
     * \return the map of interfaces attached to this spectrum PHY
     */
    const std::map<FrequencyRange, Ptr<WifiSpectrumPhyInterface>>& GetSpectrumPhyInterfaces() const;

    /**
     * \param callback the callback to invoke when operating channel has switched.
     */
    void SetChannelSwitchedCallback(Callback<void> callback);

  protected:
    void DoDispose() override;
    void DoInitialize() override;

    // The following method calls the base WifiPhy class method
    // but also generates a new SpectrumModel if called during runtime
    void DoChannelSwitch() override;

    std::map<FrequencyRange, Ptr<WifiSpectrumPhyInterface>>
        m_spectrumPhyInterfaces; //!< Spectrum PHY interfaces

    Ptr<WifiSpectrumPhyInterface>
        m_currentSpectrumPhyInterface; //!< The current Spectrum PHY interface (held for performance
                                       //!< reasons)

  private:
    /**
     * Perform run-time spectrum model change
     * \param spectrumPhyInterface the spectrum PHY interface for which the spectrum model should be
     * changed \param centerFrequency the center frequency in MHz the PHY interface should use
     * \param channelWidth the channel width in MHz the PHY interface should use
     */
    void ResetSpectrumModel(Ptr<WifiSpectrumPhyInterface> spectrumPhyInterface,
                            uint16_t centerFrequency,
                            uint16_t channelWidth);

    /**
     * This function is called to update the bands handled by the InterferenceHelper.
     * \param spectrumPhyInterface the spectrum PHY interface for which the bands should be updated
     */
    void UpdateInterferenceHelperBands(Ptr<WifiSpectrumPhyInterface> spectrumPhyInterface);

    /**
     * This function computes the RU bands that belong to a given spectrum PHY interface.
     *
     * \param spectrumPhyInterface the spectrum PHY interface to consider to compute the RU bands
     * \param guardBandwidth width of the guard band in MHz
     * \returns the computed RU bands for the spectrum PHY interface
     */
    HeRuBands GetHeRuBands(Ptr<WifiSpectrumPhyInterface> spectrumPhyInterface,
                           uint16_t guardBandwidth);

    /**
     * This function computes the bands that belong to a given spectrum PHY interface.
     *
     * \param spectrumPhyInterface the spectrum PHY interface to consider to compute the bands
     * \returns the computed bands for the spectrum PHY interface
     */
    WifiSpectrumBands ComputeBands(Ptr<WifiSpectrumPhyInterface> spectrumPhyInterface);

    /**
     * Get the info of a given band that belongs to a given spectrum PHY interface
     *
     * \param spectrumPhyInterface the spectrum PHY interface
     * \param bandWidth the width of the band to be returned (MHz)
     * \param bandIndex the index of the band to be returned
     *
     * \return the info that defines the band
     */
    WifiSpectrumBandInfo GetBandForInterface(Ptr<WifiSpectrumPhyInterface> spectrumPhyInterface,
                                             uint16_t bandWidth,
                                             uint8_t bandIndex = 0);

    /**
     * This is a helper function to convert start and stop indices to start and stop frequencies.
     *
     * \param spectrumPhyInterface the spectrum PHY interface to consider for the calculations
     * \param indices the start/stop indices to convert
     * \return the converted frequencies
     */
    WifiSpectrumBandFrequencies ConvertIndicesToFrequenciesForInterface(
        Ptr<WifiSpectrumPhyInterface> spectrumPhyInterface,
        const WifiSpectrumBandIndices& indices) const;

    /**
     * Determine whether the PHY shall issue a PHY-RXSTART.indication primitive in response to a
     * given PPDU.
     *
     * \param ppdu the PPDU
     * \return true if the PHY shall issue a PHY-RXSTART.indication primitive in response to a PPDU,
     * false otherwise
     */
    bool CanStartRx(Ptr<const WifiPpdu> ppdu) const;

    /**
     * Get the spectrum PHY interface that covers a band portion of the RF channel
     *
     * \param frequency the center frequency in MHz of the RF channel band
     * \param width the width in MHz of the RF channel band
     * \return the spectrum PHY interface that covers the indicated band of the RF channel
     */
    Ptr<WifiSpectrumPhyInterface> GetInterfaceCoveringChannelBand(uint16_t frequency,
                                                                  uint16_t width) const;

    /**
     * Notify the spectrum channel has switched
     */
    void NotifyChannelSwitched();

    Ptr<AntennaModel> m_antenna; //!< antenna model

    bool m_disableWifiReception;           //!< forces this PHY to fail to sync on any signal
    bool m_trackSignalsInactiveInterfaces; //!< flag whether signals coming from inactive spectrum
                                           //!< PHY interfaces are tracked

    TracedCallback<bool, uint32_t, double, Time> m_signalCb; //!< Signal callback

    double m_txMaskInnerBandMinimumRejection; //!< The minimum rejection (in dBr) for the inner band
                                              //!< of the transmit spectrum mask
    double m_txMaskOuterBandMinimumRejection; //!< The minimum rejection (in dBr) for the outer band
                                              //!< of the transmit spectrum mask
    double m_txMaskOuterBandMaximumRejection; //!< The maximum rejection (in dBr) for the outer band
                                              //!< of the transmit spectrum mask

    Callback<void> m_channelSwitchedCallback; //!< Callback when channel switched
};

} // namespace ns3

#endif /* SPECTRUM_WIFI_PHY_H */
