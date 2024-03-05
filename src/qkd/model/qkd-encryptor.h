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
 
#ifndef QKDEncryptor_H
#define QKDEncryptor_H

#include <algorithm>
#include <stdint.h>

#include "ns3/header.h"
#include "ns3/tcp-header.h"
#include "ns3/udp-header.h" 
#include "ns3/icmpv4.h"

#include "ns3/dsdv-packet.h"  
#include "ns3/aodv-packet.h" 
#include "ns3/olsr-header.h" 

#include "ns3/packet.h"
#include "ns3/tag.h" 
#include "ns3/object.h"
#include "ns3/callback.h"
#include "ns3/assert.h"
#include "ns3/ptr.h"
#include "ns3/deprecated.h"
#include "ns3/traced-value.h"
#include "ns3/packet-metadata.h"
#include "ns3/trace-source-accessor.h"
#include "ns3/qkd-buffer.h" 
#include "ns3/qkd-key.h"
#include "ns3/net-device.h"
#include "ns3/node.h" 

#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/osrng.h>
#include <crypto++/ccm.h>
#include <crypto++/vmac.h>
#include <crypto++/iterhash.h>
#include <crypto++/secblock.h>
#include <crypto++/sha.h>
#include <cryptopp/base64.h>
#include <vector>

typedef unsigned char byte;
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <crypto++/md5.h> 

namespace ns3 {

/**
 * \ingroup qkd
 * \class QKD Encryptor
 * \brief QKD Encryptor is a class used to perform encryption, decryption, authentication, 
 *  atuhentication-check and encoding operations.
 *
 *  \note QKD Encryptor uses cryptographic algorithms and schemes from
 *  Crypto++ free and open source C++ class cryptographic library. Currently, 
 *  QKD Encryptor supports following crypto-graphic algorithms and schemes:
 *      - One-Time Pad (OTP) cipher,
 *      - Advanced Encryption Standard (AES) block cipher,
 *      - VMAC message authentication code (MAC) algorithm,
 *      - MD5 MAC algorithm (not safe),
 *      - SHA1 MAC algorithm.
 * 
 *  As these algorithms can put a significant computational load on machines performing 
 *  the simulation, the users can turn off actual execution of such algorithms and allow 
 *  efficient simulation with more significant QKD topologies. 
 */
class QKDEncryptor : public Object
{
public:
     
    /**
     * \brief Encryption type.
     */
    enum EncryptionType {
        UNENCRYPTED,
        QKDCRYPTO_OTP,
        QKDCRYPTO_AES
    };

    /**
     * \brief Authentication type.
     */
    enum AuthenticationType {
        UNAUTHENTICATED,
        QKDCRYPTO_AUTH_VMAC,
        QKDCRYPTO_AUTH_MD5,
        QKDCRYPTO_AUTH_SHA1
    };

    /**
    * \brief Constructor.
    */
    QKDEncryptor (EncryptionType type1, AuthenticationType type2);
    /**
    * \brief Constructor.
    */
    QKDEncryptor (EncryptionType type1, AuthenticationType type2, uint32_t authTagLength);
    /**
    * \brief Constructor.
    */
    void ChangeSettings (EncryptionType type1, AuthenticationType type2, uint32_t authTagLength);
    /**
    * \brief Destructor.
    */
    virtual ~QKDEncryptor (); 

    /**
    * \brief Get the TypeId.
    * \return The TypeId for this class.
    */
    static TypeId GetTypeId (void);
    
    /**
    *  \brief Set node on which qkd encryptor is installed.
     * \param node The node
    */
    void SetNode (Ptr<Node> node);

    /**
    *  \brief Get details about the node on which qkd encryptor is installed.
     * \return The node
    */
    Ptr<Node> GetNode ();

    /**
    *  \brief Set the internal index identifier in the qkd encryptor container. @featureTask
     * \param index The internal index identifier.
    */
    void SetIndex (uint32_t index);

    /**
    *  \brief Get the internal index identifier in the qkd encryptor container. @featureTask
     * \return The internal index identifier.
    */
    uint32_t GetIndex ();
  
    /**
    *  \brief Apply the One-Time Pad cipher.
     * \param key The encryption/decryption key.
     * \param data The plaintext/ciphertext.
     * \return The ciphertext/plaintext.
    */
    std::string OTP (const std::string& key, const std::string& data);
        
    /**
    *   \brief Encrypt data using AES algorithm.
    *   \param  key The encryption key.
    *   \param  data The plaintext.
    *   \return The ciphertext.
    */
    std::string AESEncrypt (const std::string& key, const std::string& data);

    /**
    *   \brief Decrypt data using AES algorithm.
    *   \param  key The decryption key.
    *   \param  data The ciphertext.
    *   \return The plaintext.
    */
    std::string AESDecrypt (const std::string& key, const std::string& data);

    /**
     * \brief Encrypt a plaintext.
     * \param input The plaintext.
     * \param key The encryption key.
     * \return The ciphertext.
     */
    std::string EncryptMsg(std::string input, std::string key);

    /**
     * \brief Decrypt a ciphertext.
     * \param input The ciphertext.
     * \param key The encryption key.
     * \return The plaintext.
     */
    std::string DecryptMsg (std::string input, std::string key);

    /**
    *   \brief Calculate an authentication tag on a message.
    *   \param  data The message.
    *   \param  key The authentication key (if VMAC is applied).
    *   \return The authentication tag.
    */
    std::string Authenticate(std::string& data, std::string key = "0");

    /**
    *   \brief Authenticate the packet.
    *   \param  payload The packet payload.
    *   \param  authTag The received authentication tag.
    *   \param  key The authentication key.
    *   \return The authentication result.
    */
    bool CheckAuthentication(std::string payload, std::string authTag, std::string key = "0");

    /**
    *   \brief Encode the string to the HEX string.
    *   \param  data The input string.
    *   \return The HEX encoded string.
    */
    std::string HexEncode(const std::string& data);

    /**
    *   \brief  Decode the HEX string.
    *   \param  data The input HEX string.
    *   \return The decoded string.
    */
    std::string HexDecode(const std::string& data);

    /**
     * \brief Base64 encoder.
     * \param input The input data.
     * \return The base64 encoded input.
     */
    std::string Base64Encode(std::string input);

    /**
     * \brief Base64 decoder.
     * \param input The input data.
     * \return The decoded input.
     */ 
    std::string Base64Decode(std::string input); 
 
    /**
    *   \brief Calculate authentication tag in Wegman-Carter fashion.
    *   \param  key The authentication key.
    *   \param  inputString The input message.
    *   \return The authentication tag.
    */
    std::string VMAC (std::string& key, std::string& inputString);

    /**
    *   \brief Calculate MD5 authentication tag.
    *   \param  inputString The input message.
    *   \return The authentication tag.
    */
    std::string MD5 (std::string& inputString);

    /**
    *   \brief  Calucale SHA1 authentication tag.
    *   \param  inputString The input message. 
    *   \return The authentication tag.
    */
    std::string SHA1 (std::string& inputString);  

private:

    byte m_iv [ CryptoPP::AES::BLOCKSIZE ];

    Ptr<Node>   m_node; //!< A pointer to the node on which the encryptor is installed.
    uint32_t    m_index; //!< An index in the qkd encryptor container.

    bool        m_encryptionEnabled;  //!< Execute the actual encryption algorithm?
    bool        m_compressionEnabled; //!< Should compression algorithms be used?
    uint32_t    m_authenticationTagLengthInBits; //!< A length of the authentication tag in bits (32 by default).
    
    EncryptionType m_encryptionType;  //!< The encryption algorithm.
    AuthenticationType m_authenticationType; //!< The authentication algorithm.

    TracedCallback<Ptr<Packet> > m_encryptionTrace; //!< A trace callback for the encryption.
    TracedCallback<Ptr<Packet> > m_decryptionTrace; //!< A trace callback for the decryption.

    TracedCallback<Ptr<Packet>, std::string > m_authenticationTrace; //!< A trace callback for the authentication.
    TracedCallback<Ptr<Packet>, std::string > m_deauthenticationTrace; //!< A trace callback for the authentication check.


}; 
} // namespace ns3

#endif /* QKDEncryptor_QKD_H */
