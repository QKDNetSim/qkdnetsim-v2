/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
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
 * Author: Miralem Mehic <miralem.mehic@ieee.org>
 */

#define NS_LOG_APPEND_CONTEXT                                   \
  if (GetObject<Node> ()) { std::clog << "[node " << GetObject<Node> ()->GetId () << "] "; }

#include <string>
#include <cstdarg>
#include <iostream>
#include <sstream>
#include "ns3/packet.h"
#include "ns3/assert.h"
#include "ns3/log.h" 
#include "ns3/node.h" 
#include "qkd-encryptor.h"  

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDEncryptor"); 

NS_OBJECT_ENSURE_REGISTERED (QKDEncryptor);
 
static const std::string base64_chars = 
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789+/";

static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}
 
TypeId 
QKDEncryptor::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDEncryptor")
    .SetParent<Object> () 
    .AddAttribute ("CompressionEnabled", "Indicates whether a compression of packets is enabled.",
                    BooleanValue (false),
                    MakeBooleanAccessor (&QKDEncryptor::m_compressionEnabled),
                    MakeBooleanChecker ())
    .AddAttribute ("EncryptionEnabled", "Indicates whether a real encryption of packets is enabled.",
                    BooleanValue (false),
                    MakeBooleanAccessor (&QKDEncryptor::m_encryptionEnabled),
                    MakeBooleanChecker ())
    
    .AddTraceSource ("PacketEncrypted",
                    "The change trance for currenly ecrypted packet",
                     MakeTraceSourceAccessor (&QKDEncryptor::m_encryptionTrace),
                     "ns3::QKDEncryptor::PacketEncrypted")
    .AddTraceSource ("PacketDecrypted",
                    "The change trance for currenly decrypted packet",
                     MakeTraceSourceAccessor (&QKDEncryptor::m_decryptionTrace),
                     "ns3::QKDEncryptor::PacketDecrypted")

    .AddTraceSource ("PacketAuthenticated",
                    "The change trance for currenly authenticated packet",
                     MakeTraceSourceAccessor (&QKDEncryptor::m_authenticationTrace),
                     "ns3::QKDEncryptor::PacketAuthenticated")
    .AddTraceSource ("PacketDeAuthenticated",
                    "The change trance for currenly deauthenticated packet",
                     MakeTraceSourceAccessor (&QKDEncryptor::m_deauthenticationTrace),
                     "ns3::QKDEncryptor::PacketDeAuthenticated")
    ; 
  return tid;
}
 
QKDEncryptor::QKDEncryptor (
  EncryptionType encryptionType, 
  AuthenticationType authenticationType
){ 
    NS_LOG_FUNCTION (this << encryptionType << authenticationType); 
    ChangeSettings(encryptionType, authenticationType, 256);
    memset( m_iv,  0x00, CryptoPP::AES::BLOCKSIZE );
}

QKDEncryptor::QKDEncryptor (
  EncryptionType encryptionType, 
  AuthenticationType authenticationType, 
  uint32_t authTagLength
){ 
    NS_LOG_FUNCTION (this << encryptionType << authenticationType);  
    ChangeSettings(encryptionType, authenticationType, authTagLength);
}

void
QKDEncryptor::ChangeSettings (
  EncryptionType encryptionType, 
  AuthenticationType authenticationType, 
  uint32_t authTagLength
){ 
    if(authTagLength != 128 && authTagLength != 256  ){
     NS_FATAL_ERROR( this << "Crypto++ supports VMAC with 16 or 32 bytes authentication tag length!");
    }

    m_encryptionType = encryptionType;
    m_authenticationType = authenticationType;
    m_authenticationTagLengthInBits = authTagLength;
}


QKDEncryptor::~QKDEncryptor ()
{
  //NS_LOG_FUNCTION  (this);  
} 
 
void 
QKDEncryptor::SetNode (Ptr<Node> node){
    m_node = node;
}
Ptr<Node> 
QKDEncryptor::GetNode (){
    return m_node;
}

void 
QKDEncryptor::SetIndex (uint32_t index){
	m_index = index;
}
uint32_t 
QKDEncryptor::GetIndex (){
	return m_index;
}

std::string
QKDEncryptor::EncryptMsg (std::string input, std::string key)
{
  NS_LOG_FUNCTION(this << m_encryptionType << input.length() << key.length() );

  std::string output;
  switch (m_encryptionType)
  {
    case UNENCRYPTED:
      output = input;
      break;
    case QKDCRYPTO_OTP:
      output = OTP(key, input);
      break;
    case QKDCRYPTO_AES:
      output = AESEncrypt(key, input);
      break;
  }
  return output;
}

std::string
QKDEncryptor::DecryptMsg (std::string input, std::string key) 
{
  NS_LOG_FUNCTION(this << m_encryptionType << input.length() << key.length() );

  std::string output;
  switch (m_encryptionType)
  {
    case UNENCRYPTED:
      output = input;
      break;
    case QKDCRYPTO_OTP:
      output = OTP(key, input);
      break;
    case QKDCRYPTO_AES:
      output = AESDecrypt(key, input);
      break;
  }
  return output;
}

std::string
QKDEncryptor::Authenticate (std::string& inputString, std::string key)
{ 
    NS_LOG_FUNCTION (this << inputString.length() << key.length()); 
    switch (m_authenticationType)
    {
        case UNAUTHENTICATED:
            break;
        case QKDCRYPTO_AUTH_VMAC:  
            return VMAC (key, inputString); 
            break;
        case QKDCRYPTO_AUTH_MD5: 
            return MD5 (inputString);
            break;
        case QKDCRYPTO_AUTH_SHA1: 
            return SHA1 (inputString);
            break;
    }
    std::string temp;
    return temp;
}

bool
QKDEncryptor::CheckAuthentication(std::string payload, std::string authTag, std::string key)
{    
    //@toDo: authentication tag is different even though key and received tag are good, and payload seems to be correct! 
    std::string genAuthTag = Authenticate(payload, key); 
    NS_LOG_FUNCTION( this << key << authTag << genAuthTag );
    if (genAuthTag == authTag) 
      return true;
    else
      return false;
}

    
/***************************************************************
*           CRYPTO++ CRYPTOGRAPHIC FUNCTIONS 
***************************************************************/

std::string
QKDEncryptor::Base64Encode(std::string input){

  std::string output;
  CryptoPP::StringSource(input, true,
    new CryptoPP::Base64Encoder(
      new CryptoPP::StringSink(output)
    ) // Base64Encoder
  ); // StringSource
  return output;
}

std::string
QKDEncryptor::Base64Decode(std::string input){

  std::string output;
  CryptoPP::StringSource(input, true,
    new CryptoPP::Base64Decoder(
      new CryptoPP::StringSink(output)
    ) // Base64Dencoder
  ); // StringSource
  return output;
}

std::string
QKDEncryptor::OTP (const std::string& key, const std::string& cipherText)
{

  NS_LOG_FUNCTION(this << cipherText.length() << key.length() );
  std::string output;

  if(key.size() != cipherText.size()){
      NS_FATAL_ERROR ("KEY SIZE DO NOT MATCH FOR OTP! \nKeySize:" << key.size() << "\nCipterText:" << cipherText.size() << "\n" );
      output = cipherText;  
  }else{
 
    for (std::size_t i = 0; i < cipherText.size(); i++){
      output.push_back(key[i] ^ cipherText[i]);
    }
  
  }

  return output;
}

std::string 
QKDEncryptor::AESEncrypt (const std::string& key, const std::string& data)
{
    NS_LOG_FUNCTION ( this << data.size() <<  key.length() );

    memset( m_iv,  0x00, CryptoPP::AES::BLOCKSIZE );
    std::string encryptData; 

    // Encryption
    CryptoPP::CTR_Mode< CryptoPP::AES >::Encryption encryptor;
    encryptor.SetKeyWithIV((byte*) key.c_str(), key.length(), m_iv);
    //encryptor.SetKeyWithIV( key, CryptoPP::AES::DEFAULT_KEYLENGTH, m_iv );
     
    CryptoPP::StreamTransformationFilter stf( encryptor, new CryptoPP::StringSink( encryptData ) );
    stf.Put( (byte*)data.c_str(), data.size() );
    stf.MessageEnd(); 
     
    return encryptData;
}

std::string 
QKDEncryptor::AESDecrypt (const std::string& key, const std::string& data)
{ 
    NS_LOG_FUNCTION  (this << data.size());  
    memset( m_iv,  0x00, CryptoPP::AES::BLOCKSIZE );
    std::string decryptData;
 
    // Decryption 
    CryptoPP::CTR_Mode< CryptoPP::AES >::Decryption decryptor;
    decryptor.SetKeyWithIV((byte*) key.c_str(), key.length(), m_iv);
    //decryptor.SetKeyWithIV( key, CryptoPP::AES::DEFAULT_KEYLENGTH, m_iv );
     
    CryptoPP::StreamTransformationFilter stf( decryptor, new CryptoPP::StringSink( decryptData ) );
    stf.Put( (byte*)data.c_str(), data.size() );
    stf.MessageEnd();

    return decryptData;
}


std::string 
QKDEncryptor::HexEncode(const std::string& data)
{
    NS_LOG_FUNCTION  (this << data.size());  

    std::string encoded;
    CryptoPP::StringSource ss(
        (byte*)data.data(), data.size(), true, 
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded))
    );
    return encoded;
}

std::string 
QKDEncryptor::HexDecode(const std::string& data)
{
    NS_LOG_FUNCTION  (this << data.size());  

    std::string decoded;
    CryptoPP::StringSource ss(
        (byte*)data.data(), data.size(), true, 
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded))
    );
    return decoded;
}

std::string
QKDEncryptor::VMAC (std::string& key, std::string& inputString)
{ 
    NS_LOG_FUNCTION (this << inputString.length() << key.length() <<  CryptoPP::AES::BLOCKSIZE  );   
    std::string outputString;
     
    memset( m_iv,  0x00, CryptoPP::AES::BLOCKSIZE ); //maximum is 16 bytes: VMAC(AES)-128: IV length 32 exceeds the maximum of 16

    byte digestBytes[key.length()];
    CryptoPP::VMAC<CryptoPP::AES> vmac;

    vmac.SetKeyWithIV((byte*) key.c_str(), key.length(), m_iv, CryptoPP::AES::BLOCKSIZE);
    vmac.CalculateDigest(digestBytes, (byte *) inputString.c_str(), inputString.length());

    CryptoPP::HexEncoder encoder;
    encoder.Attach(new CryptoPP::StringSink(outputString));
    encoder.Put(digestBytes, sizeof(digestBytes));
    encoder.MessageEnd();

    //outputString = outputString.substr(0, m_authenticationTagLengthInBits);

    return outputString; 
}

std::string 
QKDEncryptor::MD5(std::string& inputString)
{   
    NS_LOG_FUNCTION (this << inputString.length() );    

    byte digestBytes[CryptoPP::Weak::MD5::DIGESTSIZE];

    CryptoPP::Weak1::MD5 md5;
    md5.CalculateDigest(digestBytes, (byte *) inputString.c_str(), inputString.length());

    std::string outputString;
    CryptoPP::HexEncoder encoder;

    encoder.Attach(new CryptoPP::StringSink(outputString));
    encoder.Put(digestBytes, sizeof(digestBytes));
    encoder.MessageEnd();

    outputString = outputString.substr(0, m_authenticationTagLengthInBits);
    return outputString;  
} 
 
std::string 
QKDEncryptor::SHA1(std::string& inputString)
{   
    NS_LOG_FUNCTION (this << inputString.length() );    
  
    byte digestBytes[CryptoPP::SHA1::DIGESTSIZE];

    CryptoPP::SHA1 sha1;
    sha1.CalculateDigest(digestBytes, (byte *) inputString.c_str(), inputString.length());

    std::string outputString;
    CryptoPP::HexEncoder encoder;

    encoder.Attach(new CryptoPP::StringSink(outputString));
    encoder.Put(digestBytes, sizeof(digestBytes));
    encoder.MessageEnd();

    outputString = outputString.substr(0, m_authenticationTagLengthInBits);
    return outputString;  
}  

} // namespace ns3
