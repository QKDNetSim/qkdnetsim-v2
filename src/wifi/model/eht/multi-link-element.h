/*
 * Copyright (c) 2021 Universita' degli Studi di Napoli Federico II
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

#ifndef MULTI_LINK_ELEMENT_H
#define MULTI_LINK_ELEMENT_H

#include "ns3/nstime.h"
#include "ns3/wifi-information-element.h"
#include "ns3/wifi-mac-header.h"

#include <memory>
#include <optional>
#include <variant>

namespace ns3
{

class MgtAssocRequestHeader;
class MgtReassocRequestHeader;
class MgtAssocResponseHeader;

/// variant holding a reference to a (Re)Association Request
using AssocReqRefVariant = std::variant<std::reference_wrapper<MgtAssocRequestHeader>,
                                        std::reference_wrapper<MgtReassocRequestHeader>>;

/**
 * Common Info field of the Basic Multi-Link element.
 * See Sec. 9.4.2.312.2.2 of 802.11be D1.5
 */
struct CommonInfoBasicMle
{
    /**
     * Medium Synchronization Delay Information subfield
     */
    struct MediumSyncDelayInfo
    {
        uint8_t mediumSyncDuration;            //!< Medium Synchronization Duration
        uint8_t mediumSyncOfdmEdThreshold : 4; //!< Medium Synchronization OFDM ED Threshold
        uint8_t mediumSyncMaxNTxops : 4;       //!< Medium Synchronization MAximum Number of TXOPs
    };

    /**
     * EML Capabilities subfield
     */
    struct EmlCapabilities
    {
        uint8_t emlsrSupport : 1;         //!< EMLSR Support
        uint8_t emlsrPaddingDelay : 3;    //!< EMLSR Padding Delay
        uint8_t emlsrTransitionDelay : 3; //!< EMLSR Transition Delay
        uint8_t emlmrSupport : 1;         //!< EMLMR Support
        uint8_t emlmrDelay : 3;           //!< EMLMR Delay
        uint8_t transitionTimeout : 4;    //!< Transition Timeout
    };

    /**
     * MLD Capabilities subfield
     */
    struct MldCapabilities
    {
        uint8_t maxNSimultaneousLinks : 4;   //!< Max number of simultaneous links
        uint8_t srsSupport : 1;              //!< SRS Support
        uint8_t tidToLinkMappingSupport : 2; //!< TID-To-Link Mapping Negotiation Supported
        uint8_t freqSepForStrApMld : 5; //!< Frequency Separation For STR/AP MLD Type Indication
        uint8_t aarSupport : 1;         //!< AAR Support
    };

    /**
     * Subfields
     */
    Mac48Address m_mldMacAddress;                  //!< MLD MAC Address
    std::optional<uint8_t> m_linkIdInfo;           //!< Link ID Info
    std::optional<uint8_t> m_bssParamsChangeCount; //!< BSS Parameters Change Count
    std::optional<MediumSyncDelayInfo>
        m_mediumSyncDelayInfo;                        //!< Medium Synchronization Delay Information
    std::optional<EmlCapabilities> m_emlCapabilities; //!< EML Capabilities
    std::optional<MldCapabilities> m_mldCapabilities; //!< MLD Capabilities

    /**
     * Get the Presence Bitmap subfield of the Common Info field
     *
     * \return the Presence Bitmap subfield of the Common Info field
     */
    uint16_t GetPresenceBitmap() const;
    /**
     * Get the size of the serialized Common Info field
     *
     * \return the size of the serialized Common Info field
     */
    uint8_t GetSize() const;
    /**
     * Serialize the Common Info field
     *
     * \param start iterator pointing to where the Common Info field should be written to
     */
    void Serialize(Buffer::Iterator& start) const;
    /**
     * Deserialize the Common Info field
     *
     * \param start iterator pointing to where the Common Info field should be read from
     * \param presence the value of the Presence Bitmap field indicating which subfields
     *                 are present in the Common Info field
     * \return the number of bytes read
     */
    uint8_t Deserialize(Buffer::Iterator start, uint16_t presence);

    /**
     * \param delay the EMLSR Padding delay
     * \return the encoded value for the EMLSR Padding Delay subfield
     */
    static uint8_t EncodeEmlsrPaddingDelay(Time delay);
    /**
     * \param value the value for the EMLSR Padding Delay subfield
     * \return the corresponding EMLSR Padding delay
     */
    static Time DecodeEmlsrPaddingDelay(uint8_t value);

    /**
     * \param delay the EMLSR Transition delay
     * \return the encoded value for the EMLSR Transition Delay subfield
     */
    static uint8_t EncodeEmlsrTransitionDelay(Time delay);
    /**
     * \param value the value for the EMLSR Transition Delay subfield
     * \return the corresponding EMLSR Transition delay
     */
    static Time DecodeEmlsrTransitionDelay(uint8_t value);

    /**
     * Set the Medium Synchronization Duration subfield of the Medium Synchronization
     * Delay Information in the Common Info field.
     *
     * \param delay the timer duration (must be a multiple of 32 microseconds)
     */
    void SetMediumSyncDelayTimer(Time delay);
    /**
     * Set the Medium Synchronization OFDM ED Threshold subfield of the Medium Synchronization
     * Delay Information in the Common Info field.
     *
     * \param threshold the threshold in dBm (ranges from -72 to -62 dBm)
     */
    void SetMediumSyncOfdmEdThreshold(int8_t threshold);
    /**
     * Set the Medium Synchronization Maximum Number of TXOPs subfield of the Medium Synchronization
     * Delay Information in the Common Info field. A value of zero indicates no limit on the
     * maximum number of TXOPs.
     *
     * \param nTxops the maximum number of TXOPs a non-AP STA is allowed to attempt to
     *               initiate while the MediumSyncDelay timer is running at a non-AP STA
     */
    void SetMediumSyncMaxNTxops(uint8_t nTxops);
    /**
     * Get the Medium Synchronization Duration subfield of the Medium Synchronization Delay
     * Information in the Common Info field. Make sure that the Medium Synchronization Delay
     * Information subfield is present.
     *
     * \return the timer duration
     */
    Time GetMediumSyncDelayTimer() const;
    /**
     * Get the Medium Synchronization OFDM ED Threshold in dBm. Make sure that the Medium
     * Synchronization Delay Information subfield is present.
     *
     * \return the threshold in dBm
     */
    int8_t GetMediumSyncOfdmEdThreshold() const;
    /**
     * Get the maximum number of TXOPs a non-AP STA is allowed to attempt to initiate
     * while the MediumSyncDelay timer is running at a non-AP STA. If no value is returned,
     * no limit is imposed on the number of TXOPs. Make sure that the Medium Synchronization
     * Delay Information subfield is present.
     *
     * \return the number of TXOPs
     */
    std::optional<uint8_t> GetMediumSyncMaxNTxops() const;
};

/**
 * \brief The Multi-Link element
 * \ingroup wifi
 *
 * The 802.11be Multi-Link element (see Sec.9.4.2.312 of 802.11be D1.5)
 *
 * TODO:
 * - Add setters/getters for EML Capabilities and MLD Capabilities subfields of
 *   the Common Info field of the Basic variant of a Multi-Link Element.
 * - Add support for variants other than the Basic one.
 */
class MultiLinkElement : public WifiInformationElement
{
  public:
    /**
     * \ingroup wifi
     * Multi-Link element variants
     *
     * Note that Multi-Link element variants can be added to this enum only when
     * the corresponding CommonInfo variant is implemented. This is because the
     * index of m_commonInfo, which is a std::variant, is casted to this enum and
     * the index of the "unset" variant must correspond to UNSET.
     */
    enum Variant : uint8_t
    {
        BASIC_VARIANT = 0,
        // PROBE_REQUEST_VARIANT,
        // RECONFIGURATION_VARIANT,
        // TDLS_VARIANT,
        // PRIORITY_ACCESS_VARIANT,
        UNSET
    };

    /**
     * \ingroup wifi
     * SubElement IDs
     */
    enum SubElementId : uint8_t
    {
        PER_STA_PROFILE_SUBELEMENT_ID = 0
    };

    /// Typedef for structure holding a reference to the containing frame
    using ContainingFrame = std::variant<std::monostate,
                                         std::reference_wrapper<const MgtAssocRequestHeader>,
                                         std::reference_wrapper<const MgtReassocRequestHeader>,
                                         std::reference_wrapper<const MgtAssocResponseHeader>>;

    /**
     * Construct a Multi-Link Element with no variant set.
     *
     * \param frame the management frame containing this Multi-Link Element
     */
    MultiLinkElement(ContainingFrame frame = {});
    /**
     * Constructor
     *
     * \param variant the Multi-Link element variant (cannot be UNSET)
     * \param frame the management frame containing this Multi-Link Element
     */
    MultiLinkElement(Variant variant, ContainingFrame frame = {});

    WifiInformationElementId ElementId() const override;
    WifiInformationElementId ElementIdExt() const override;
    uint16_t GetInformationFieldSize() const override;
    void SerializeInformationField(Buffer::Iterator start) const override;
    uint16_t DeserializeInformationField(Buffer::Iterator start, uint16_t length) override;

    /**
     * Get the Multi-Link element variant
     *
     * \return the Multi-Link element variant
     */
    Variant GetVariant() const;

    /// \return a reference to the Common Info field (the MLE variant must be Basic)
    CommonInfoBasicMle& GetCommonInfoBasic();

    /// \return a const reference to the Common Info field (the MLE variant must be Basic)
    const CommonInfoBasicMle& GetCommonInfoBasic() const;

    /**
     * Set the MLD MAC Address subfield in the Common Info field. Make sure that
     * this is a Basic Multi-Link Element.
     *
     * \param address the MLD MAC address
     */
    void SetMldMacAddress(Mac48Address address);

    /**
     * Return the MLD MAC Address subfield in the Common Info field. Make sure that
     * this is a Basic Multi-Link Element.
     *
     * \return the MLD MAC Address subfield in the Common Info field.
     */
    Mac48Address GetMldMacAddress() const;

    /**
     * Set the Link ID Info subfield in the Common Info field. Make sure that
     * this is a Basic Multi-Link Element.
     *
     * \param linkIdInfo the link ID information
     */
    void SetLinkIdInfo(uint8_t linkIdInfo);
    /**
     * Return true if the Link ID Info subfield in the Common Info field is present
     * and false otherwise. Make sure that this is a Basic Multi-Link Element.
     *
     * \return true if the Link ID Info subfield in the Common Info field is present
     *         and false otherwise
     */
    bool HasLinkIdInfo() const;
    /**
     * Return the Link ID Info subfield in the Common Info field. Make sure that
     * this is a Basic Multi-Link Element and the Link ID Info subfield is present.
     *
     * \return the Link ID Info subfield in the Common Info field
     */
    uint8_t GetLinkIdInfo() const;

    /**
     * Set the BSS Parameters Change Count subfield in the Common Info field. Make sure that
     * this is a Basic Multi-Link Element.
     *
     * \param count the BSS Parameters Change Count
     */
    void SetBssParamsChangeCount(uint8_t count);
    /**
     * Return true if the BSS Parameters Change Count subfield in the Common Info field is present
     * and false otherwise. Make sure that this is a Basic Multi-Link Element.
     *
     * \return true if the BSS Parameters Change Count subfield in the Common Info field is present
     *         and false otherwise
     */
    bool HasBssParamsChangeCount() const;
    /**
     * Return the BSS Parameters Change Count subfield in the Common Info field. Make sure that
     * this is a Basic Multi-Link Element and the BSS Parameters Change Count subfield is present.
     *
     * \return the BSS Parameters Change Count subfield in the Common Info field
     */
    uint8_t GetBssParamsChangeCount() const;

    /**
     * Set the EMLSR Support subfield of the EML Capabilities subfield in the Common Info field
     * to 1 if EMLSR mode is supported and set it to 0 otherwise. Make sure that this is a Basic
     * Multi-Link Element.
     *
     * \param supported whether EMLSR mode is supported
     */
    void SetEmlsrSupported(bool supported);
    /**
     * Set the EMLSR Padding Delay subfield of the EML Capabilities subfield in the
     * Common Info field. Make sure that this is a Basic Multi-Link Element.
     *
     * \param delay the EMLSR Padding delay (0us, 32us, 64us, 128us or 256us)
     */
    void SetEmlsrPaddingDelay(Time delay);
    /**
     * Set the EMLSR Transition Delay subfield of the EML Capabilities subfield in the
     * Common Info field. Make sure that this is a Basic Multi-Link Element.
     *
     * \param delay the EMLSR Transition delay (0us, 16us, 32us, 64us, 128us or 256us)
     */
    void SetEmlsrTransitionDelay(Time delay);
    /**
     * Set the Transition Timeout subfield of the EML Capabilities subfield in the
     * Common Info field. Make sure that this is a Basic Multi-Link Element.
     *
     * \param timeout the Transition Timeout (0us or 2^n us, with n=7..16)
     */
    void SetTransitionTimeout(Time timeout);
    /**
     * Return true if the EML Capabilities subfield in the Common Info field is present
     * and false otherwise. Make sure that this is a Basic Multi-Link Element.
     *
     * \return whether the EML Capabilities subfield in the Common Info field is present
     */
    bool HasEmlCapabilities() const;
    /**
     * Return true if the EMLSR Support subfield of the EML Capabilities subfield in the
     * Common Info field is set to 1 and false otherwise. Make sure that this is a Basic
     * Multi-Link Element and the EML Capabilities subfield is present.
     *
     * \return whether the EMLSR Support subfield is set to 1
     */
    bool IsEmlsrSupported() const;
    /**
     * Get the EMLSR Padding Delay subfield of the EML Capabilities subfield in the
     * Common Info field. Make sure that this is a Basic Multi-Link Element and the
     * EML Capabilities subfield is present.
     *
     * \return the EMLSR Padding Delay
     */
    Time GetEmlsrPaddingDelay() const;
    /**
     * Get the EMLSR Transition Delay subfield of the EML Capabilities subfield in the
     * Common Info field. Make sure that this is a Basic Multi-Link Element and the
     * EML Capabilities subfield is present.
     *
     * \return the EMLSR Transition Delay
     */
    Time GetEmlsrTransitionDelay() const;
    /**
     * Get the Transition Timeout subfield of the EML Capabilities subfield in the
     * Common Info field. Make sure that this is a Basic Multi-Link Element and the
     * EML Capabilities subfield is present.
     *
     * \return the Transition Timeout
     */
    Time GetTransitionTimeout() const;

    mutable ContainingFrame m_containingFrame; //!< reference to the mgt frame containing this MLE

    /**
     * \ingroup wifi
     * Per-STA Profile Subelement of Multi-Link element.
     * See Sec. 9.4.2.312.2.3 of 802.11be D1.5
     *
     * The frame body of the management frame included in the Per-STA Profile field
     * is stored as a (unique) pointer to the Header base class, because we cannot
     * include mgt-headers.h here (otherwise, we would create a circular dependency).
     *
     * TODO:
     * - complete the implementation of STA Control and STA Info subfields
     */
    class PerStaProfileSubelement : public WifiInformationElement
    {
      public:
        /**
         * Constructor
         *
         * \param variant the Multi-Link element variant
         */
        PerStaProfileSubelement(Variant variant);

        /**
         * Copy constructor performing a deep copy of the object
         *
         * \param perStaProfile the object to copy
         */
        PerStaProfileSubelement(const PerStaProfileSubelement& perStaProfile);
        /**
         * Copy assignment operator performing a deep copy of the object
         *
         * \param perStaProfile the object to copy-assign
         * \return a reference to this object
         */
        PerStaProfileSubelement& operator=(const PerStaProfileSubelement& perStaProfile);
        /**
         * Use default move assignment operator
         *
         * \param perStaProfile the object to move-assign
         * \return a reference to this object
         */
        PerStaProfileSubelement& operator=(PerStaProfileSubelement&& perStaProfile) = default;

        WifiInformationElementId ElementId() const override;

        /**
         * Set the Link ID subfield in the STA Control field
         *
         * \param linkId the Link ID value
         */
        void SetLinkId(uint8_t linkId);
        /**
         * Get the Link ID subfield in the STA Control field
         *
         * \return the Link ID subfield in the STA Control field
         */
        uint8_t GetLinkId() const;

        /**
         * Set the Complete Profile flag in the STA Control field
         */
        void SetCompleteProfile();
        /**
         * \return whether the Complete Profile flag in the STA Control field is set
         */
        bool IsCompleteProfileSet() const;

        /**
         * Set the STA MAC Address subfield in the STA Info field
         *
         * \param address the MAC address to set
         */
        void SetStaMacAddress(Mac48Address address);
        /**
         * Return true if the STA MAC Address subfield in the STA Info field is present
         *
         * \return true if the STA MAC Address subfield in the STA Info field is present
         */
        bool HasStaMacAddress() const;
        /**
         * Get the STA MAC Address subfield in the STA Info field, if present
         *
         * \return the STA MAC Address subfield in the STA Info field, if present
         */
        Mac48Address GetStaMacAddress() const;

        /**
         * Include the given (Re)Association Request frame body in the STA Profile field
         * of this Per-STA Profile subelement
         *
         * \param assoc the given (Re)Association Request frame body
         */
        void SetAssocRequest(
            const std::variant<MgtAssocRequestHeader, MgtReassocRequestHeader>& assoc);
        /** \copydoc SetAssocRequest */
        void SetAssocRequest(std::variant<MgtAssocRequestHeader, MgtReassocRequestHeader>&& assoc);
        /**
         * Return true if an Association Request frame body is included in the
         * STA Profile field of this Per-STA Profile subelement
         *
         * \return true if an Association Request frame body is included
         */
        bool HasAssocRequest() const;
        /**
         * Return true if a Reassociation Request frame body is included in the
         * STA Profile field of this Per-STA Profile subelement
         *
         * \return true if a Reassociation Request frame body is included
         */
        bool HasReassocRequest() const;
        /**
         * Get the (Re)Association Request frame body included in the STA Profile
         * field of this Per-STA Profile subelement
         *
         * \return the (Re)Association Request frame body
         */
        AssocReqRefVariant GetAssocRequest() const;

        /**
         * Include the given (Re)Association Response frame body in the STA Profile field
         * of this Per-STA Profile subelement
         *
         * \param assoc the given (Re)Association Response frame body
         */
        void SetAssocResponse(const MgtAssocResponseHeader& assoc);
        /** \copydoc SetAssocResponse */
        void SetAssocResponse(MgtAssocResponseHeader&& assoc);
        /**
         * Return true if a (Re)Association Response frame body is included in the
         * STA Profile field of this Per-STA Profile subelement
         *
         * \return true if a (Re)Association Response frame body is included
         */
        bool HasAssocResponse() const;
        /**
         * Get the (Re)Association Response frame body included in the STA Profile
         * field of this Per-STA Profile subelement
         *
         * \return the (Re)Association Response frame body
         */
        MgtAssocResponseHeader& GetAssocResponse() const;

        /**
         * Get the size in bytes of the serialized STA Info Length subfield of
         * the STA Info field
         *
         * \return the size in bytes of the serialized STA Info Length subfield
         */
        uint8_t GetStaInfoLength() const;

        mutable ContainingFrame
            m_containingFrame; //!< the mgt frame containing this Per-STA Profile

      private:
        uint16_t GetInformationFieldSize() const override;
        void SerializeInformationField(Buffer::Iterator start) const override;
        uint16_t DeserializeInformationField(Buffer::Iterator start, uint16_t length) override;

        Variant m_variant;            //!< Multi-Link element variant
        uint16_t m_staControl;        //!< STA Control field
        Mac48Address m_staMacAddress; //!< STA MAC address
        std::variant<std::monostate,
                     std::unique_ptr<MgtAssocRequestHeader>,
                     std::unique_ptr<MgtReassocRequestHeader>,
                     std::unique_ptr<MgtAssocResponseHeader>>
            m_staProfile; /**< STA Profile field, containing the frame body of a frame of the
                               same type as the frame containing the Multi-Link Element */
    };

    /**
     * Add a Per-STA Profile Subelement in the Link Info field
     */
    void AddPerStaProfileSubelement();
    /**
     * Return the number of Per-STA Profile Subelement in the Link Info field
     *
     * \return the number of Per-STA Profile Subelement in the Link Info field
     */
    std::size_t GetNPerStaProfileSubelements() const;
    /**
     * Get a reference to the <i>i</i>-th Per-STA Profile Subelement in the Link Info field
     *
     * \param i the index of the Per-STA Profile Subelement in the Link Info field
     * \return a reference to the <i>i</i>-th Per-STA Profile Subelement in the Link Info field
     */
    PerStaProfileSubelement& GetPerStaProfile(std::size_t i);
    /**
     * Get a reference to the <i>i</i>-th Per-STA Profile Subelement in the Link Info field
     *
     * \param i the index of the Per-STA Profile Subelement in the Link Info field
     * \return a reference to the <i>i</i>-th Per-STA Profile Subelement in the Link Info field
     */
    const PerStaProfileSubelement& GetPerStaProfile(std::size_t i) const;

  private:
    /**
     * Set the variant of this Multi-Link Element
     *
     * \param variant the variant of this Multi-Link Element
     */
    void SetVariant(Variant variant);

    /// Typedef for structure holding a Common Info field
    using CommonInfo = std::variant<CommonInfoBasicMle,
                                    // TODO Add other variants
                                    std::monostate /* UNSET variant*/>;

    CommonInfo m_commonInfo; //!< Common Info field

    /*
     * Link Info field
     */
    std::vector<PerStaProfileSubelement>
        m_perStaProfileSubelements; //!< Per-STA Profile Subelements
};

} // namespace ns3

#endif /* MULTI_LINK_ELEMENT_H */
