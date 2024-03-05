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

#ifndef QKDBUFFER_H
#define QKDBUFFER_H

#include <queue>
#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/ipv4-header.h"
#include "ns3/traced-value.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/event-id.h"
#include "ns3/qkd-key.h"
#include "ns3/node.h"
#include <vector>
#include <map>

namespace ns3 {

  /**
   * \defgroup qkd Quantum Key Distribution (QKD)
   * This section documents the API of the ns-3 QKD Network Simulation Module (QKDNetSim). 
   *
   * Be sure to read the manual BEFORE going down to the API.
   */

  /**
   * \ingroup qkd
   * \class QKDBuffer
   * \brief QKD buffer is a secure storage for QKD keys. QKDBuffer is assigned 
   * for each link using QKDControl on each side of the link (each node). 
   *
   * \note The two nodes that establish the logical QKD connection will implement 
   * one QKD buffer on each side which will be assigned by QKDControl entity.
   * The purpose of the QKD buffer is to collect enough key material for its 
   * subsequent use for cryptographic purposes. Due to the limited charging key 
   * rate of QKD protocols, QKDPostProcessing applications strive to save keys in 
   * QKD buffers to generate as many keys in advance. However, warehouses have a 
   * limited capacity that is defined with a maximum value. They also have a minimum 
   * capacity that describes the minimum amount of key required to establish initial 
   * post-processing operations. Also, the buffer implements a threshold value that 
   * may indicate that the necessary actions are being taken before the buffer 
   * is completely emptied.
   *
   * It is important to note that a QKD link has full application only when there are 
   * enough keys to apply for cryptographic purposes. Therefore, constant monitoring 
   * of the state of the QKD buffer is necessary to identify the statuses in which the 
   * QKD buffer can be found:
   *    READY - Amount of key is larger than threshold Mthr
   *    WARNING  - Amount of key is lower then threshold and the amount of keys 
   *    in the buffer is decreasing
   *    CHARGING - Amount of key is lower then threshold and the amount of keys 
   *    in the buffer is increasing
   *    EMPTY - The amount of keys in the buffer is lower than the minimal value
   *
   *    The states of the QKD buffer do not directly affect the communication, but it 
   *    can be used for  easier prioritization of traffic depending on the state of 
   *    the buffer. For example, in EMPTY state, QKD post-processing applications used 
   *    to establish a new key material should have the highest priority in traffic processing.
   */
  class QKDBuffer: public Object {
    public:

    static
    const uint32_t QKDSTATUS_READY = 0; //!< QKDStatus READY
    static
    const uint32_t QKDSTATUS_WARNING = 1; //!< QKDStatus WARNING
    static
    const uint32_t QKDSTATUS_CHARGING = 2; //!< QKDStatus CHARGING
    static
    const uint32_t QKDSTATUS_EMPTY = 3; //!< QKDStatus EMPTY

    /**
     * Data specific variables.
     */
    struct data {
      uint32_t value;
      uint32_t position;
    };

    /**
     * The key storage description
     */
    struct KeyStorage {
      Ptr <Node> alice;
      Ptr <Node> bob;
      std::map < uint32_t, QKDKey > keys;
      double publicChannelMetric;
      double quantumChannelMetric;
    };

    /**
     * \brief Get the TypeId.
     *
     * \return The TypeId for this class.
     */
    static TypeId GetTypeId(void);

    /**
     * \brief Constructor.
     */
    QKDBuffer();

    /**
     * \brief Destructor.
     */
    virtual~QKDBuffer();

    /**
     * \brief Initialize a QKD buffer.
     *
     * \param srcNode The source node.
     * \param dstNode The destination node.
     * \param Mmin The lower threshold value.
     * \param Mthr The threshold value.
     * \param Mmax The buffer's capacity.
     * \param Mcurrent The current amout of key material in the buffer.
     * \param useRealStorages Should the program use external file key storage?
     */
    void Init(
      Ptr <Node> srcNode,
      Ptr <Node> dstNode,
      uint32_t Mmin,
      uint32_t Mthr,
      uint32_t Mmax,
      uint32_t Mcurrent,
      bool useRealStorages
    );

    /**
     * \brief Destroy a QKD buffer.
     *
     * This is the pre-destructor function of the QKDBuffer.
     */
    void Dispose(void);

    /**
     * \brief Add new key to the storage.
     * 
     * \param key The QKD key object.
     * \param keyTransformed Is the key transformed?
     * \return The success indicator.
     */
    bool AddNewKey(Ptr <QKDKey> key, uint32_t keyTransformed);

    /**
     *   \brief Get the current state of the QKD buffer.
     *
     *   QKD buffer can be in one of the following states:
     *   – READY—when Mcur (t) ≥ Mthr ,
     *   – WARNING—when Mthr > Mcur (t) > Mmin and the previous state was READY,
     *   – CHARGING—when Mthr > Mcur (t) and the previous state was EMPTY,
     *   – EMTPY—when Mmin ≥ Mcur (t) and the previous state was WARNING or CHARGING
     *  
     *   \return The state.
     */
    uint32_t FetchState(void);

    /**
     *   \brief Get the previous state of the QKD buffer. Help function used for ploting graphs.
     *
     *   \return The integer representation of the QKD buffer state.
     */
    uint32_t FetchPreviousState(void);

    /**
     *   \brief Update the state of the buffer.
     */
    void CheckState(void);

    /**
     *   \brief Help function used for ploting graphs.
     */
    void KeyCalculation();

    /*
     *   \brief Get the time difference between the current time and time at which
     *   last key charging process finished.
     *
     *   \return The time difference.
     */
    int64_t FetchDeltaTime();

    /**
     *   \brief Get the time value about the time duration of last key charging process.
     *
     *   \return The time value. 
     */
    int64_t FetchLastKeyChargingTimeDuration();

    /**
     *   \brief Get the average duration of key charging process in the long run.
     *   
     *   \return The average duration of key charging period.
     */
    double FetchAverageKeyChargingTimePeriod();

    /**
     *   \brief Get the maximal number of values which are used
     *   for calculation of average key charging time period.
     *
     *   \return The maximal number of recorded key charging time periods; the default value is 5.
     */
    uint32_t FetchMaxNumberOfRecordedKeyChargingTimePeriods();

    /**
     *   \brief Get previous - before latest change. Help function used for ploting graphs.
     *   \return The integer representation of the previous QKD storage key material.
     */
    uint32_t GetMCurrentPrevious(void) const;

    /**
     *   \brief Get the threshold value of QKD storage.
     *   
     *   The threshold value Mthr (t) at the time of measurement t is used to indicate the
     *   state of the QKD buffer where it holds that Mthr (t) ≤ Mmax.
     *
     *   \return The threshold value.
     */
    uint32_t GetMthr(void) const;

    /**
     *   \brief Set the threshold value of the QKD storage.
     *   \param The threshold value.
     */
    void SetMthr(uint32_t thr);

    /**
     *   \brief Initialize total graph. Help function for total graph ploting.
     */
    void InitTotalGraph() const;

    /**
     *   \brief Get the QKD buffer identifier.
     *   \return The buffer indentifier.
     */
    uint32_t GetId(void) const;

    /**
     *   \brief Set the QKD source node.
     *   \param The source node.
     */
    void SetSrcNode(Ptr <Node> );

    /**
     *   \brief Get the QKD source node.   
     *   \return The source node.
     */
    Ptr <Node> GetSrcNode();

    /**
     *   \brief Set the QKD destination node.
     *   \param The destination node.
     */
    void SetDstNode(Ptr <Node> );

    /**
     *   \brief Get the QKD destination node.
     *   \return The destination node.
     */
    Ptr <Node> GetDstNode();

    /**
     *   \brief Set the index of the buffer per local node.
     *   \param The index.
     */
    void SetIndex(uint32_t);
    /**
     *   \brief Get the index of the buffer per local node.
     *   \return The index.
     */
    uint32_t GetIndex();

    /**
     *   \brief Define equal operator on the QKD buffer object.
     *   \param o The other QKD buffer.
     *   \return True if buffers are identical; False otherwise.
     */
    bool operator == (QKDBuffer
      const & o) const;

    Ptr <Node> m_srcNode; //!< The source node.
    Ptr <Node> m_dstNode; //!< The destination node.
    uint32_t m_bufferID; //!< The unique buffer identifier.
    static uint32_t nBuffers; //!< The number of the created buffers - a static value.

    /**
     *   \brief Get default size of the key (ETSI QKD 014).
     *   \return The default key size.
     */
    uint32_t GetKeySize();

    /**
     *   \brief Get the amount of stored keys in bits.
     *   \return The amount of stored keys in bits.
     */
    uint64_t GetKeyCountBit();

    /**
     * \brief Get the amount of the key material in bits that is ready to be served.
     * \return The amount of available key material in bits.
     * 
     * This function provides the information on the amount of key material that is
     * ready to be served, and is not reserved for the other purposes.
     */
    uint64_t GetReadyKeyCountBit();

    /**
     * \brief Get tge amount of key material in bits that is ready to be served and belongs to a set of targeted keys.
     * \return The amount of available key material in bits that is of the size of requested keys.
     */
    uint64_t GetTargetKeyCountBit();
  
    /**
     *   \brief Get the number of stored keys. (ETSI QKD 014)
     *   \return The number of stored keys.
     */
    uint32_t GetKeyCount();

    /**
     *   \brief Get the minimum number of stored keys. (ETSI QKD 014)
     *   \return The minimum number of stored keys.
     */
    uint32_t GetMinKeyCount();

    /**
     *   \brief Get the maximum number of stored keys. (ETSI QKD 014)
     *   \return The maximum number of stored keys.
     */
    uint32_t GetMaxKeyCount();

    /**
     *   \brief Get the maximum amount of stored keys in bits. (ETSI QKD 014)
     *   \return The maximum amount of stored keys in bits.
     */
    uint64_t GetMaxKeyCountBit();

    /**
     *   \brief Get the minimum key size that can be served. (ETSI QKD 014)
     *   \return The minimum key size that can be served.
     */
    uint32_t GetMinKeySize();

    /**
     *   \brief Get the minimum key size that can be served in bits. (ETSI QKD 014)
     *   \return The minimum key size that can be served in bits.
     */
    uint64_t GetMinKeySizeBit();

    /**
     *   \brief Get the maximal key size that can be served in bits. (ETSI QKD 014)
     *   \return The maximal key size that can be served in bits.
     */
    uint64_t GetMaxKeySizeBit();

    /**
     * \brief Get the number of the available keys with a given size.
     * \param keySize The key size.
     * \return The key number.
     */
    uint32_t    GetKeyCount (uint32_t keySize);

    /**
     * \brief Check if the state of the key equals to a given state.
     * \param keyId The key identifier.
     * \param keyState The key state to compare with.
     * \return The comparison result.
     */
    bool        ProbeKeyStatus (std::string keyId, QKDKey::QKDKeyState_e keyState);

    /**
     * \brief Get the key of a given size.
     * \param keySize The key size.
     * \return The key (NULL is returned if the key is not found).
     */
    Ptr<QKDKey>   FetchKeyBySize( const uint32_t& keySize);

    /**
     * \brief Get the key of a given identifier.
     * \param keyID The key identifier.
     * \return The key (NULL is returned if the key is not found).
     */
    Ptr <QKDKey>  FetchKeyByID(std::string keyID);

    /**
     * \brief Get the key of a given identifier.
     * \param keyID The key identifier.
     * \param fillProcessActive Is asked by the fill process?
     * \return The key (NULL is returned if the key is not found).
     */
    Ptr <QKDKey>  FetchKeyByID(std::string keyID, uint32_t fillProcessActive);

    /**
     * \brief Reserve the QKD key.
     * \param keyId The key identifier.
     */
    void            ReserveKey (std::string keyId);

    /**
     * \brief Release the key reservation.
     * \param keyId The key identifier.
     */
    void            ReleaseReservation (std::string keyId);

    /**
     * \brief Record the key target size.
     * \param size The key size in bits.
     *
     * Must keep a record on the requested key sizes to avoid
     * their usage in the key transformation functions!
     */
    void            RecordTargetSize (uint32_t size);

    /**
     * \brief Serach for the optimal key to transform.
     * \param targetSize The target size.
     * \return The optimal transformation candidate -- key.
     * 
     * The search algorithm will prefer keys whose size is
     * larger then the target size.
     */
    Ptr<QKDKey>     SearchOptimalKeyToTransform (uint32_t targetSize);

    /**
     * \brief Get average key generation rate.
     * \return The average key generation rate.
     */
    double GetAverageKeyGenerationRate();

    /**
     * \brief Get average key consumption rate.
     * \return The average key consumption rate.
     */
    double GetAverageKeyConsumptionRate();

    /**
     * \brief Update key consumption statistics.
     * \param key The key that is consumed.
     */
    void UpdateKeyConsumptionStatistics(Ptr<QKDKey> key);

    /**
     * \brief Update key generation statistics.
     * \param key The key that is generated.
     */
    void UpdateKeyGenerationStatistics(Ptr<QKDKey> key);

  private:

    std::vector<uint32_t> m_targetSizeSet; //!< The list of requested key sizes.
    uint32_t m_defaultKeySize; //!< The default key size as required by the ETSI QKD 014 interface details.
    bool m_useRealStorages; //<! Whether to use real storages or virtual buffers (still in development).
    uint32_t m_nextKeyID; //!< The identifie of the next key to be generated.
    std::map < std::string, Ptr <QKDKey> > m_keys; //!< The list of available keys with their identifiers.

    uint32_t m_noEntry; //!< Help value used for graph ploting
    uint32_t m_period; //!< Help value used for graph ploting
    uint32_t m_noAddNewValue; //!< Help value used for graph ploting
    uint32_t m_bitsUsedInTimePeriod; //!< Help value used for graph ploting

    uint32_t m_recalculateTimePeriod; //!< The period of time (in seconds) to calculate average amount of the key in the buffer. The default value is 5.
    std::vector < struct QKDBuffer::data > m_previousValues; //!< Help vector used for graph ploting
    
    double m_c; //!< The average amount of key in the buffer during the recalculate time period.
    bool m_isRisingCurve; //!< Whether curve on graph is rising or not.
    uint32_t m_previousStatus; //!< The previous status; important for deciding about further status that can be selected.
    uint32_t m_minKeyBit; //!< The minimal amount of key material in the QKD key storage.
    uint32_t m_maxKeyBit; //!< The maximal amount of key material in the QKD key storage.
    uint32_t m_thresholdKeyBit; //!< The threshold amount of key material in the QKD key storage.
    uint32_t m_minimalKeyCount; //!< The minimal number of stored keys.
    uint32_t m_maximalKeyCount; //!< The maximal number of stored keys.

    TracedCallback < uint32_t > m_thresholdKeyBitChangeTrace; //!< A traceback for available key bits.
    TracedCallback < uint32_t > m_thresholdKeyBitIncreaseTrace; //!< A traceback for generated key bits.
    TracedCallback < uint32_t > m_thresholdKeyBitDecreaseTrace; //!< A traceback for consumed key bits.

    uint32_t m_currentKeyBit; //!< The current amount of key material in the QKD key storage.
    uint32_t m_currentKeyBitReally; //!< The current amount of key material used for real tracking of storage (transform!).
    uint64_t m_currentReadyKeyBit; //!< The current amount of key material in the QKD buffer that are ready to be served.
    uint64_t m_currentTargetKeyBit; //!< The current amount of key material in the QKD buffer that is already targeted. Should not be used to transform keys!
    uint32_t m_currentKeyBitPrevious; //!< The previous value of current amount of key material in the QKD key storage.
    int64_t m_lastKeyChargingTimeStamp; //!< The timestamp of a last key charging (when the new key material was added).
    int64_t m_lastKeyConsumptionTimeStamp; //!<  The timestamp of a last key consumption (when the last key material was fetched).
    int64_t m_lastKeyChargingTimeDuration; //!<  The timestamp of a last key usage.
    int64_t m_lastKeyConsumptionTimeDuration; //!< The timestamp of a last key fetch operation.
    uint32_t m_maxNumberOfRecordedKeyChargingTimePeriods; //!< The maximal number of values which are used for calculation of the average key charging time period.
    uint32_t m_maxNumberOfRecordedKeyConsumptionTimePeriods; //!< The maximal number of values which are used for calculation of the average key consumption time period.
    std::vector < int64_t > m_lastChargedKeySizes; //!< The size of the several last generated keys.
    std::vector < int64_t > m_lastConsumedKeySizes; //!< The size of the several last consumed keys.
    std::vector < int64_t > m_chargingTimePeriods; //!< The durations of the serveral last charging time periods.
    std::vector < int64_t > m_consumptionTimePeriods; //!< The durations of the serveral last consumption time periods.
    uint32_t m_status; //!< The state of the Net Device transmit state machine.
    double m_averageKeyChargingTimePeriod; //!< The average duration of the key charging time period.
    double m_averageKeyConsumptionTimePeriod; //!< The average duration of the key consumption time period.
    double m_averageKeyChargingSize; //!< The average key charging size.
    double m_averageKeyConsumptionSize; //!< The average key consumption size.
    double m_averageKeyGenerationRate; //!< The average key generation rate.
    double m_averageKeyConsumptionRate; //!< The average key consumption rate.
    EventId m_calculateRoutingMetric; //!< The event to calculate routing metric.
    TracedCallback < Ptr<QKDKey> > m_newKeyAddedTrace; //!< A trace of newly added keys.
    TracedCallback < Ptr<QKDKey> > m_transformedKeyAddedTrace; //!< A trace for tranformed keys.
    TracedCallback < Ptr<QKDKey> > m_keyServedTrace; //!< A trace for served keys.
    TracedCallback < Ptr<QKDKey> > m_keyReservedTrace; //!< A trace for reserved keys.
    TracedCallback < uint32_t > m_currentKeyBitChangeTrace; //!< A trace for current bit change.
    TracedCallback < uint32_t > m_currentKeyBitIncreaseTrace; //!< A trace of increase in amount of key bits.
    TracedCallback < uint32_t > m_currentKeyBitDecreaseTrace; //!< A trace of decrease in amount of key bits.
    TracedCallback < uint32_t > m_StatusChangeTrace; //!< A trace of status changes.
    TracedCallback < double > m_CMetricChangeTrace; //!< A trace of c metric changes.
    
    TracedCallback < double > m_averageKeyGenerationRateTrace; //!< A trace of the average key generation rate.
    TracedCallback < double > m_averageKeyConsumptionRateTrace; //!< A trace of the average key consumption rate.

    uint32_t m_srcNodeBufferListIndex; //!< The index in the source node buffer list. 

    std::map < uint32_t, QKDBuffer::KeyStorage > m_destinations; //<! A map of QKD destinations and respective QKD buffers.

  };
}

#endif /* QKDBUFFER_H */