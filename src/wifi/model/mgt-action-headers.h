/*
 * Copyright (c) 2006 INRIA
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

#ifndef MGT_ACTION_HEADERS_H
#define MGT_ACTION_HEADERS_H

#include "status-code.h"

#include "ns3/header.h"

#include <list>
#include <optional>

namespace ns3
{

class Packet;

/**
 * \ingroup wifi
 *
 * See IEEE 802.11 chapter 7.3.1.11
 * Header format: | category: 1 | action value: 1 |
 *
 */
class WifiActionHeader : public Header
{
  public:
    WifiActionHeader();
    ~WifiActionHeader() override;

    /*
     * Compatible with table 8-38 IEEE 802.11, Part11, (Year 2012)
     * Category values - see 802.11-2012 Table 8-38
     */

    /// CategoryValue enumeration
    enum CategoryValue : uint8_t // table 9-51 of IEEE 802.11-2020
    {
        SPECTRUM_MANAGEMENT = 0,
        QOS = 1,
        BLOCK_ACK = 3,
        PUBLIC = 4,
        RADIO_MEASUREMENT = 5, // Category: Radio Measurement
        MESH = 13,             // Category: Mesh
        MULTIHOP = 14,         // not used so far
        SELF_PROTECTED = 15,   // Category: Self Protected
        DMG = 16,              // Category: DMG
        FST = 18,              // Category: Fast Session Transfer
        UNPROTECTED_DMG = 20,  // Category: Unprotected DMG
        PROTECTED_EHT = 37,    // Category: Protected EHT
        // Since vendor specific action has no stationary Action value,the parse process is not
        // here. Refer to vendor-specific-action in wave module.
        VENDOR_SPECIFIC_ACTION = 127,
        // values 128 to 255 are illegal
    };

    /// QosActionValue enumeration
    enum QosActionValue : uint8_t
    {
        ADDTS_REQUEST = 0,
        ADDTS_RESPONSE = 1,
        DELTS = 2,
        SCHEDULE = 3,
        QOS_MAP_CONFIGURE = 4,
    };

    /**
     * Block Ack Action field values
     * See 802.11 Table 8-202
     */
    enum BlockAckActionValue : uint8_t
    {
        BLOCK_ACK_ADDBA_REQUEST = 0,
        BLOCK_ACK_ADDBA_RESPONSE = 1,
        BLOCK_ACK_DELBA = 2
    };

    /// PublicActionValue enumeration
    enum PublicActionValue : uint8_t
    {
        QAB_REQUEST = 16,
        QAB_RESPONSE = 17,
    };

    /// RadioMeasurementActionValue enumeration
    enum RadioMeasurementActionValue : uint8_t
    {
        RADIO_MEASUREMENT_REQUEST = 0,
        RADIO_MEASUREMENT_REPORT = 1,
        LINK_MEASUREMENT_REQUEST = 2,
        LINK_MEASUREMENT_REPORT = 3,
        NEIGHBOR_REPORT_REQUEST = 4,
        NEIGHBOR_REPORT_RESPONSE = 5
    };

    /// MeshActionValue enumeration
    enum MeshActionValue : uint8_t
    {
        LINK_METRIC_REPORT = 0,              // Action Value:0 in Category 13: Mesh
        PATH_SELECTION = 1,                  // Action Value:1 in Category 13: Mesh
        PORTAL_ANNOUNCEMENT = 2,             // Action Value:2 in Category 13: Mesh
        CONGESTION_CONTROL_NOTIFICATION = 3, // Action Value:3 in Category 13: Mesh
        MDA_SETUP_REQUEST =
            4, // Action Value:4 in Category 13: Mesh MCCA-Setup-Request (not used so far)
        MDA_SETUP_REPLY =
            5, // Action Value:5 in Category 13: Mesh MCCA-Setup-Reply (not used so far)
        MDAOP_ADVERTISEMENT_REQUEST =
            6, // Action Value:6 in Category 13: Mesh MCCA-Advertisement-Request (not used so far)
        MDAOP_ADVERTISEMENTS = 7,      // Action Value:7 in Category 13: Mesh (not used so far)
        MDAOP_SET_TEARDOWN = 8,        // Action Value:8 in Category 13: Mesh (not used so far)
        TBTT_ADJUSTMENT_REQUEST = 9,   // Action Value:9 in Category 13: Mesh (not used so far)
        TBTT_ADJUSTMENT_RESPONSE = 10, // Action Value:10 in Category 13: Mesh (not used so far)
    };

    /// MultihopActionValue enumeration
    enum MultihopActionValue : uint8_t
    {
        PROXY_UPDATE = 0,              // not used so far
        PROXY_UPDATE_CONFIRMATION = 1, // not used so far
    };

    /// SelfProtectedActionValue enumeration
    enum SelfProtectedActionValue : uint8_t // Category: 15 (Self Protected)
    {
        PEER_LINK_OPEN = 1,    // Mesh Peering Open
        PEER_LINK_CONFIRM = 2, // Mesh Peering Confirm
        PEER_LINK_CLOSE = 3,   // Mesh Peering Close
        GROUP_KEY_INFORM = 4,  // Mesh Group Key Inform
        GROUP_KEY_ACK = 5,     // Mesh Group Key Acknowledge
    };

    /**
     * DMG Action field values
     * See 802.11ad Table 8-281b
     */
    enum DmgActionValue : uint8_t
    {
        DMG_POWER_SAVE_CONFIGURATION_REQUEST = 0,
        DMG_POWER_SAVE_CONFIGURATION_RESPONSE = 1,
        DMG_INFORMATION_REQUEST = 2,
        DMG_INFORMATION_RESPONSE = 3,
        DMG_HANDOVER_REQUEST = 4,
        DMG_HANDOVER_RESPONSE = 5,
        DMG_DTP_REQUEST = 6,
        DMG_DTP_RESPONSE = 7,
        DMG_RELAY_SEARCH_REQUEST = 8,
        DMG_RELAY_SEARCH_RESPONSE = 9,
        DMG_MULTI_RELAY_CHANNEL_MEASUREMENT_REQUEST = 10,
        DMG_MULTI_RELAY_CHANNEL_MEASUREMENT_REPORT = 11,
        DMG_RLS_REQUEST = 12,
        DMG_RLS_RESPONSE = 13,
        DMG_RLS_ANNOUNCEMENT = 14,
        DMG_RLS_TEARDOWN = 15,
        DMG_RELAY_ACK_REQUEST = 16,
        DMG_RELAY_ACK_RESPONSE = 17,
        DMG_TPA_REQUEST = 18,
        DMG_TPA_RESPONSE = 19,
        DMG_TPA_REPORT = 20,
        DMG_ROC_REQUEST = 21,
        DMG_ROC_RESPONSE = 22
    };

    /**
     * FST Action field values
     * See 802.11ad Table 8-281x
     */
    enum FstActionValue : uint8_t
    {
        FST_SETUP_REQUEST = 0,
        FST_SETUP_RESPONSE = 1,
        FST_TEAR_DOWN = 2,
        FST_ACK_REQUEST = 3,
        FST_ACK_RESPONSE = 4,
        ON_CHANNEL_TUNNEL_REQUEST = 5
    };

    /**
     * Unprotected DMG action field values
     * See 802.11ad Table 8-281ae
     */
    enum UnprotectedDmgActionValue : uint8_t
    {
        UNPROTECTED_DMG_ANNOUNCE = 0,
        UNPROTECTED_DMG_BRP = 1,
        UNPROTECTED_MIMO_BF_SETUP = 2,
        UNPROTECTED_MIMO_BF_POLL = 3,
        UNPROTECTED_MIMO_BF_FEEDBACK = 4,
        UNPROTECTED_MIMO_BF_SELECTION = 5,
    };

    /**
     * Protected EHT action field values
     * See 802.11be D3.0 Table 9-623c
     */
    enum ProtectedEhtActionValue : uint8_t
    {
        PROTECTED_EHT_TID_TO_LINK_MAPPING_REQUEST = 0,
        PROTECTED_EHT_TID_TO_LINK_MAPPING_RESPONSE = 1,
        PROTECTED_EHT_TID_TO_LINK_MAPPING_TEARDOWN = 2,
        PROTECTED_EHT_EPCS_PRIORITY_ACCESS_ENABLE_REQUEST = 3,
        PROTECTED_EHT_EPCS_PRIORITY_ACCESS_ENABLE_RESPONSE = 4,
        PROTECTED_EHT_EPCS_PRIORITY_ACCESS_TEARDOWN = 5,
        PROTECTED_EHT_EML_OPERATING_MODE_NOTIFICATION = 6,
        PROTECTED_EHT_LINK_RECOMMENDATION = 7,
        PROTECTED_EHT_MULTI_LINK_OPERATION_UPDATE_REQUEST = 8,
        PROTECTED_EHT_MULTI_LINK_OPERATION_UPDATE_RESPONSE = 9,
    };

    /**
     * typedef for union of different ActionValues
     */
    typedef union {
        QosActionValue qos;                                 ///< qos
        BlockAckActionValue blockAck;                       ///< block ack
        RadioMeasurementActionValue radioMeasurementAction; ///< radio measurement
        PublicActionValue publicAction;                     ///< public
        SelfProtectedActionValue selfProtectedAction;       ///< self protected
        MultihopActionValue multihopAction;                 ///< multi hop
        MeshActionValue meshAction;                         ///< mesh
        DmgActionValue dmgAction;                           ///< dmg
        FstActionValue fstAction;                           ///< fst
        UnprotectedDmgActionValue unprotectedDmgAction;     ///< unprotected dmg
        ProtectedEhtActionValue protectedEhtAction;         ///< protected eht
    } ActionValue;                                          ///< the action value

    /**
     * Set action for this Action header.
     *
     * \param type category
     * \param action action
     */
    void SetAction(CategoryValue type, ActionValue action);

    /**
     * Return the category value.
     *
     * \return CategoryValue
     */
    CategoryValue GetCategory() const;
    /**
     * Return the action value.
     *
     * \return ActionValue
     */
    ActionValue GetAction() const;

    /**
     * Peek an Action header from the given packet.
     *
     * \param pkt the given packet
     * \return the category value and the action value in the peeked Action header
     */
    static std::pair<CategoryValue, ActionValue> Peek(Ptr<const Packet> pkt);

    /**
     * Remove an Action header from the given packet.
     *
     * \param pkt the given packet
     * \return the category value and the action value in the removed Action header
     */
    static std::pair<CategoryValue, ActionValue> Remove(Ptr<Packet> pkt);

    /**
     * Register this type.
     * \return The TypeId.
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

  private:
    uint8_t m_category;    //!< Category of the action
    uint8_t m_actionValue; //!< Action value
};

/**
 * \ingroup wifi
 * Implement the header for management frames of type Add Block Ack request.
 */
class MgtAddBaRequestHeader : public Header
{
  public:
    /**
     * Register this type.
     * \return The TypeId.
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * Enable delayed BlockAck.
     */
    void SetDelayedBlockAck();
    /**
     * Enable immediate BlockAck
     */
    void SetImmediateBlockAck();
    /**
     * Set Traffic ID (TID).
     *
     * \param tid traffic ID
     */
    void SetTid(uint8_t tid);
    /**
     * Set timeout.
     *
     * \param timeout timeout
     */
    void SetTimeout(uint16_t timeout);
    /**
     * Set buffer size.
     *
     * \param size buffer size
     */
    void SetBufferSize(uint16_t size);
    /**
     * Set the starting sequence number.
     *
     * \param seq the starting sequence number
     */
    void SetStartingSequence(uint16_t seq);
    /**
     * Enable or disable A-MSDU support.
     *
     * \param supported enable or disable A-MSDU support
     */
    void SetAmsduSupport(bool supported);

    /**
     * Return the starting sequence number.
     *
     * \return the starting sequence number
     */
    uint16_t GetStartingSequence() const;
    /**
     * Return the Traffic ID (TID).
     *
     * \return TID
     */
    uint8_t GetTid() const;
    /**
     * Return whether the Block Ack policy is immediate Block Ack.
     *
     * \return true if immediate Block Ack is being used, false otherwise
     */
    bool IsImmediateBlockAck() const;
    /**
     * Return the timeout.
     *
     * \return timeout
     */
    uint16_t GetTimeout() const;
    /**
     * Return the buffer size.
     *
     * \return the buffer size.
     */
    uint16_t GetBufferSize() const;
    /**
     * Return whether A-MSDU capability is supported.
     *
     * \return true is A-MSDU is supported, false otherwise
     */
    bool IsAmsduSupported() const;

  private:
    /**
     * Return the raw parameter set.
     *
     * \return the raw parameter set
     */
    uint16_t GetParameterSet() const;
    /**
     * Set the parameter set from the given raw value.
     *
     * \param params raw parameter set value
     */
    void SetParameterSet(uint16_t params);
    /**
     * Return the raw sequence control.
     *
     * \return the raw sequence control
     */
    uint16_t GetStartingSequenceControl() const;
    /**
     * Set sequence control with the given raw value.
     *
     * \param seqControl the raw sequence control
     */
    void SetStartingSequenceControl(uint16_t seqControl);

    uint8_t m_dialogToken{1};   //!< Not used for now
    uint8_t m_amsduSupport{1};  //!< Flag if A-MSDU is supported
    uint8_t m_policy{1};        //!< Block Ack policy
    uint8_t m_tid{0};           //!< Traffic ID
    uint16_t m_bufferSize{0};   //!< Buffer size
    uint16_t m_timeoutValue{0}; //!< Timeout
    uint16_t m_startingSeq{0};  //!< Starting sequence number
};

/**
 * \ingroup wifi
 * Implement the header for management frames of type Add Block Ack response.
 */
class MgtAddBaResponseHeader : public Header
{
  public:
    /**
     * Register this type.
     * \return The TypeId.
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * Enable delayed BlockAck.
     */
    void SetDelayedBlockAck();
    /**
     * Enable immediate BlockAck.
     */
    void SetImmediateBlockAck();
    /**
     * Set Traffic ID (TID).
     *
     * \param tid traffic ID
     */
    void SetTid(uint8_t tid);
    /**
     * Set timeout.
     *
     * \param timeout timeout
     */
    void SetTimeout(uint16_t timeout);
    /**
     * Set buffer size.
     *
     * \param size buffer size
     */
    void SetBufferSize(uint16_t size);
    /**
     * Set the status code.
     *
     * \param code the status code
     */
    void SetStatusCode(StatusCode code);
    /**
     * Enable or disable A-MSDU support.
     *
     * \param supported enable or disable A-MSDU support
     */
    void SetAmsduSupport(bool supported);

    /**
     * Return the status code.
     *
     * \return the status code
     */
    StatusCode GetStatusCode() const;
    /**
     * Return the Traffic ID (TID).
     *
     * \return TID
     */
    uint8_t GetTid() const;
    /**
     * Return whether the Block Ack policy is immediate Block Ack.
     *
     * \return true if immediate Block Ack is being used, false otherwise
     */
    bool IsImmediateBlockAck() const;
    /**
     * Return the timeout.
     *
     * \return timeout
     */
    uint16_t GetTimeout() const;
    /**
     * Return the buffer size.
     *
     * \return the buffer size.
     */
    uint16_t GetBufferSize() const;
    /**
     * Return whether A-MSDU capability is supported.
     *
     * \return true is A-MSDU is supported, false otherwise
     */
    bool IsAmsduSupported() const;

  private:
    /**
     * Return the raw parameter set.
     *
     * \return the raw parameter set
     */
    uint16_t GetParameterSet() const;
    /**
     * Set the parameter set from the given raw value.
     *
     * \param params raw parameter set value
     */
    void SetParameterSet(uint16_t params);

    uint8_t m_dialogToken{1};   //!< Not used for now
    StatusCode m_code{};        //!< Status code
    uint8_t m_amsduSupport{1};  //!< Flag if A-MSDU is supported
    uint8_t m_policy{1};        //!< Block ACK policy
    uint8_t m_tid{0};           //!< Traffic ID
    uint16_t m_bufferSize{0};   //!< Buffer size
    uint16_t m_timeoutValue{0}; //!< Timeout
};

/**
 * \ingroup wifi
 * Implement the header for management frames of type Delete Block Ack.
 */
class MgtDelBaHeader : public Header
{
  public:
    /**
     * Register this type.
     * \return The TypeId.
     */
    static TypeId GetTypeId();

    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * Check if the initiator bit in the DELBA is set.
     *
     * \return true if the initiator bit in the DELBA is set,
     *         false otherwise
     */
    bool IsByOriginator() const;
    /**
     * Return the Traffic ID (TID).
     *
     * \return TID
     */
    uint8_t GetTid() const;
    /**
     * Set Traffic ID (TID).
     *
     * \param tid traffic ID
     */
    void SetTid(uint8_t tid);
    /**
     * Set the initiator bit in the DELBA.
     */
    void SetByOriginator();
    /**
     * Un-set the initiator bit in the DELBA.
     */
    void SetByRecipient();

  private:
    /**
     * Return the raw parameter set.
     *
     * \return the raw parameter set
     */
    uint16_t GetParameterSet() const;
    /**
     * Set the parameter set from the given raw value.
     *
     * \param params raw parameter set value
     */
    void SetParameterSet(uint16_t params);

    uint16_t m_initiator{0};  //!< initiator
    uint16_t m_tid{0};        //!< Traffic ID
    uint16_t m_reasonCode{1}; //!< Not used for now. Always set to 1: "Unspecified reason"
};

/**
 * \ingroup wifi
 * Implement the header for Action frames of type EML Operating Mode Notification.
 */
class MgtEmlOmn : public Header
{
  public:
    MgtEmlOmn() = default;

    /**
     * Register this type.
     * \return The TypeId.
     */
    static TypeId GetTypeId();
    TypeId GetInstanceTypeId() const override;
    void Print(std::ostream& os) const override;
    uint32_t GetSerializedSize() const override;
    void Serialize(Buffer::Iterator start) const override;
    uint32_t Deserialize(Buffer::Iterator start) override;

    /**
     * EML Control field.
     */
    struct EmlControl
    {
        uint8_t emlsrMode : 1;                  //!< EMLSR Mode
        uint8_t emlmrMode : 1;                  //!< EMLMR Mode
        uint8_t emlsrParamUpdateCtrl : 1;       //!< EMLSR Parameter Update Control
        uint8_t : 5;                            //!< reserved
        std::optional<uint16_t> linkBitmap;     //!< EMLSR/EMLMR Link Bitmap
        std::optional<uint8_t> mcsMapCountCtrl; //!< MCS Map Count Control
        // TODO Add EMLMR Supported MCS And NSS Set subfield when EMLMR is supported
    };

    /**
     * EMLSR Parameter Update field.
     */
    struct EmlsrParamUpdate
    {
        uint8_t paddingDelay : 3;    //!< EMLSR Padding Delay
        uint8_t transitionDelay : 3; //!< EMLSR Transition Delay
    };

    /**
     * Set the bit position in the link bitmap corresponding to the given link.
     *
     * \param linkId the ID of the given link
     */
    void SetLinkIdInBitmap(uint8_t linkId);
    /**
     * \return the ID of the links whose bit position in the link bitmap is set to 1
     */
    std::list<uint8_t> GetLinkBitmap() const;

    uint8_t m_dialogToken{0};                             //!< Dialog Token
    EmlControl m_emlControl{};                            //!< EML Control field
    std::optional<EmlsrParamUpdate> m_emlsrParamUpdate{}; //!< EMLSR Parameter Update field
};

} // namespace ns3

#endif /* MGT_ACTION_HEADERS_H */
