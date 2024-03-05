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
 * Author: Miralem Mehic <miralem.mehic@ieee.org>, 
 *         Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *         Oliver Mauhart <oliver.maurhart@ait.ac.at>
 */

#ifndef QKD_APP_HEADER_H
#define QKD_APP_HEADER_H

#include <queue>
#include <string>
#include "ns3/packet.h"
#include "ns3/header.h"
#include "ns3/object.h"

namespace ns3 { 

/**
 * \ingroup qkd
 * \class QKDAppHeader
 * \brief QKD app packet header that carries info about used encryption, auth tag and other.
 * 
 * \note
 *      0       4       8               16              24              32
 *      0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0
 *   0  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                            Length                             |
 *   4  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                            Msg-Id                             |
 *   8  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |   E   |   A   | 
 *  16  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                       Encryption Key Id                       |
 *  20  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                     Authentication Key Id                     |
 *  24  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                             A-Tag ...                         |
 *  28  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                          ... A-Tag                            |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * with:
 * 
 *      Length:         total size of packet, including the length field itself
 *      Msg-Id:         message number (inside a channel)
 *      E:              Type of used encryption cipher where value 0 means unencrypted packet
 *      A:              Type of used authentication algorithm where value 0 means non-authenticated packet
 *      E-KeyId:        Encryption Key Id
 *      A-KeyId:        Authentication Key Id
 *      A-Tag:          Authentication tag
 * 
 */     

class QKDAppHeader : public Header
{
    public:

        /**
        * \brief Constructor
        */
        QKDAppHeader ();

        /**
        * \brief Get the type ID.
        * \return the object TypeId
        */
        static TypeId GetTypeId ();
        /**
        * \brief Get the type ID.
        * \return The object TypeId.
        */
        TypeId      GetInstanceTypeId () const;

        /**
         * \brief Print the QKDApp packet.
         * \param os The stream.
         */
        void        Print (std::ostream &os) const;

        /**
         * \brief Compare the two QKDApp packets.
         * \param o The other packets.
         * \return The equality result.
         */
        bool        operator== (QKDAppHeader const & o) const;

        /**
         * \brief Get the serialized size of a packet.
         * \return The size.
         */
        uint32_t    GetSerializedSize () const;

        /**
         * \brief Serialize the packet.
         * \param start The starting point.
         */
        void        Serialize (Buffer::Iterator start) const;

        /**
         * \brief Deserialize the packet.
         * \param start The starting point. 
         */
        uint32_t    Deserialize (Buffer::Iterator start);

        /**
        * \brief Set the message length.
        * \param value The length.
        */
        void 		SetLength (uint32_t value);

        /**
        * \brief Get message length.
        * \return The messsage length.
        */
        uint32_t 	GetLength (void) const;
        
        /**
        * \brief Set message identifier.
        * \param value The identifier.
        */
        void 		SetMessageId (uint32_t value);

        /**
        * \brief Get message identifier.
        * \return The identifier.
        */
        uint32_t 	GetMessageId (void) const;

        /**
        * \brief Set the encrypted field.
        * \param value The encrypted flag.
        */
        void 		SetEncrypted (uint32_t value);

        /**
        * \brief Read the encrypted field.
        * \return The encrypted flag.
        */
        uint32_t  	GetEncrypted (void) const;
 
        /**
        * \brief Set the authentication field.
        * \param value The authentication flag.
        */
        void 		SetAuthenticated (uint32_t value);

        /**
        * \brief Read the authentication field.
        * \return The authentication flag.
        */
        uint32_t 	GetAuthenticated (void) const;

        /**
        * \brief Set the encryption key identifier.
        * \param value The encryption key identifier.
        */
        void 		SetEncryptionKeyId (std::string  value);

        /**
        * \brief Read the encryption key identifier.
        * \return The encryption key identifier.
        */
        std::string GetEncryptionKeyId (void) const;

        /**
        * \brief Set the authentication key identifier.
        * \param keyID The authentication key identifier.
        */
        void 		SetAuthenticationKeyId (std::string  keyID);

        /**
        * \brief Read the authentication key identifier.
        * \return The authentication key identifier.
        */
        std::string GetAuthenticationKeyId (void) const;

        /**
        * \brief Set the authentication tag.
        * \param value The authentication tag.
        */
        void 		SetAuthTag (std::string value);

        /**
        * \brief Read the authentication tag.
        * \return The authentication tag.
        */
        std::string GetAuthTag (void) const;

        /**
         * \brief Check that type is valid.
         * \return The success indicator.
         */
        bool IsValid () const
        {
            return m_valid;
        }
         
    private:

        uint32_t        m_length;                   //!< The message length field.
        uint32_t        m_messageId;                //!< The message identifier field.

        uint8_t         m_encryped;                 //!< The encryption flag.
        uint8_t         m_authenticated;            //!< The authentication flag.  

        std::string     m_encryptionKeyId;          //!< The encryption key identifier field. 
        std::string     m_authenticationKeyId;      //!< The authentication key identifier field.
        std::string     m_authTag;                  //!< The authentication tag field.

        bool            m_valid;                    //!< Is the header valid or corrupted?

    };


}  
// namespace ns3

#endif /* QKD_APP_HEADER_H */


