

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
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@ieee.org>
 */
#ifndef QKD_KEY_H
#define QKD_KEY_H

#include <stdint.h>  
#include <algorithm>
#include <stdint.h> 

#include "ns3/packet.h"
#include "ns3/object.h"
#include "ns3/callback.h"
#include "ns3/assert.h"
#include "ns3/ptr.h"
#include "ns3/simulator.h"
#include <time.h>
#include "ns3/nstime.h"
#include "ns3/traced-callback.h"
#include "ns3/random-variable-stream.h"
#include "ns3/deprecated.h"
#include <string>
#include <iomanip>
#include <vector>
#include <bitset>
/*
#include <crypto++/iterhash.h>
#include <crypto++/secblock.h>
*/
namespace ns3 {

/**
 * \ingroup qkd
 * \brief The QKD key is an elementary class of QKDNetSim. It is used 
 *  to describe the key that is established in the QKD process. 

 *  \noteIn the QKD process, keys are stored as blocks. 
 *  Each QKDKey is identified using a unique 32 long character identifier. 
 *  The key is also marked with the timestamp of its origin, its length, 
 *  and the condition in which the key is located. QKDKey can be found 
 *  in one of the following states:
 *      INIT - the call for the establishment of the key record is initiated
 *      READY - the key is successfully created and stored
 *      SERVED - the key is served for usage on request
 *      TRANSFORMED - the key is generated as the result of transform operation
 *      USED - the key is used for cryptographic operations (under construction)
 *      OBSOLETE - the key validity has expired (under construction)
 *      RESTORED - the key is restored for further usage (under construction)
 */
class QKDKey : public Object
{
    public:

        /**
         * \brief The QKD key states.
         */
        enum QKDKeyState_e {
            INIT,
            READY,
            SERVED,
            TRANSFORMED,
            USED,
            OBSOLETE,
            RESTORED,
            RESERVED
        };

        /**
        * \brief Get the TypeId.
        * \return The TypeId for this class.
        */
        static TypeId GetTypeId (void);

        /**
        * \brief Constructor. Create a random QKD key.
        * \param keySize The key size.
        */
        QKDKey (uint64_t keySize); 

        /**
        * \brief Constructor. Create a QKD key.
        * \param keyId The key identifier.
        * \param KeyIdnum The internal key identifier.
        * \param keySize The key size.
        */
        QKDKey (std::string keyId, uint64_t keyIdnum, uint64_t keySize); 

        /**
         * \brief Constructor. Create a QKD key.
         * \param keyId The key identifier.
         * \param keyIdnum The internal key identifier.
         * \param key The key value.
         */
        QKDKey (std::string keyId, uint64_t keyIdnum, std::string key);

        /**
         * \brief Constructor. Create a QKD key.
         * \param keyId The key identifier.
         * \param key The key value.
         */
        QKDKey (std::string keyId, std::string key); //KMS key generation!
 
        /**
         * \brief Get the key identifier.
         * \return The key identifier.
         */
        std::string        GetId (void) const;

        /**
         * \brief Set the key identifier.
         * \param value The key identifier.
         */
        void               SetId (std::string value);

        /**
        *   \brief Copy the key.
        *   \return The QKD key object.
        */
        Ptr<QKDKey>     Copy (void) const; 

        /**
        * \brief Get key value in byte* format.
        * 
        * Convert key from std::String to byte*.
        * 
        * \return The key value in byte* format.
        */  
        uint8_t *       GetKey (void); 

        /**
         * \brief Get QKD key value.
         * \return The key value.
         */
        std::string     GetKeyString (void);

        /**
        * \brief Get key value in bit notation.
        * \return The key value in bit notation.
        */  
        std::string GetKeyBinary();

        /**
        *   \brief Get the key size in bytes.
        *   \return The key size.
        */
        uint64_t        GetSize(void) const;

        /**
         * \brief Get the key size in bits.
         * \return The key size.
         */
        uint64_t        GetSizeInBits(void) const;

        /**
        *   \brief Set the key size.
        *   \param sizeInBytes The key size in bytes.
        */
        void            SetSize(uint64_t sizeInBytes);

        /**
         * \brief Mark the key as ready.
         */
        void            MarkReady();

        /**
         * \brief Mark the key as used.
         */
        void            MarkUsed();

        /**
         * \brief Mark the key as restored.
         */
        void            MarkRestored();

        /**
         * \brief Mark the key as served.
         */
        void            MarkServed();

        /**
         * \brief Mark the key as reserved.
         */
        void            MarkReserved();

        /**
         * \brief Mark the key as transformed.
         */
        void            MarkTransformed();

        /**
        *   \brief Get the key value and switch the key state to SERVED.
        *   \return The key value.
        */
        std::string     ConsumeKeyString (void);

        /**
        *   \brief Get the key value.
        *   \return The key value.
        */
        std::string     ToString (void);

        /**
         * \brief Get a random string.
         * \param len The length of the string.
         * \return The random string.
         */
        std::string     GenerateRandomString(const int len);

        /**
        * \brief Get the current state of the key.
        * \return The current state of the key.
        */
        QKDKeyState_e GetState () const; 

        /**
        * \brief Get the current state of the key in a string format.
        * \return The current state of the key.
        */
        std::string GetStateString () const;

        /**
        * \brief Get the given state in a string format.
        * \param state The key state.
        * \return The key state expressed in string format.
        */
        static std::string GetStateString (QKDKeyState_e state);

        /**
        * \brief Change the state of the key. Fires the `StateTransition` trace source.
        * \param state The new state.
        */
        void SwitchToState (QKDKeyState_e state);

        /**
        * \brief Get the key timestamp.
        * \return The key timestamp.
        */
        Time GetKeyTimestamp();

        /// The `StateTransition` trace source.
        ns3::TracedCallback<const std::string &, const std::string &> m_stateTransitionTrace;

    private:
        uint64_t            m_internalID; //<! The internal key identifier.
        std::string         m_id;       //<! The key identifier.
        static uint64_t     m_globalUid; //<! The global static key identifier.
        uint64_t            m_sizeInBytes; //<! The key size in bytes.
        uint64_t            m_sizeInBits; //<! The key size in bits.
        std::string         m_key;  //<! The key value.
        Time                m_timestamp; //<! The key timestamp. 
        QKDKeyState_e       m_state; //!< The key state.
        Ptr<UniformRandomVariable> m_random; //<! The uniform random variable.
        
    };

} // namespace ns3

#endif /* QKD_KEY_H */
