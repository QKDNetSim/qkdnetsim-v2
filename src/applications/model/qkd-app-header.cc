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

#include "ns3/log.h" 
#include "ns3/object-vector.h"
#include "ns3/pointer.h"
#include "ns3/uinteger.h"
#include "qkd-app-header.h"

namespace ns3 {
 
NS_LOG_COMPONENT_DEFINE ("QKDAppHeader");

NS_OBJECT_ENSURE_REGISTERED (QKDAppHeader);
 
QKDAppHeader::QKDAppHeader ():m_valid (true)
{ 
    m_length = 0;
    m_messageId = 0;
    m_encryped = 0;
    m_authenticated = 0;
}

TypeId
QKDAppHeader::GetTypeId ()
{
  static TypeId tid = TypeId ("ns3::QKDAppHeader")
    .SetParent<Header> ()
    .AddConstructor<QKDAppHeader> ()
  ;
  return tid;
}

TypeId
QKDAppHeader::GetInstanceTypeId () const
{
  return GetTypeId ();
}

uint32_t
QKDAppHeader::GetSerializedSize () const
{
  return 2  * sizeof(uint32_t) 
       + 2  * sizeof(uint8_t)  
       + 3 * 32 * sizeof(uint8_t); //@toDo: AuthTag is variable length!
}

void
QKDAppHeader::Serialize (Buffer::Iterator i) const
{
    i.WriteHtonU32 ((uint32_t) m_length);
    i.WriteHtonU32 ((uint32_t) m_messageId);
    i.WriteU8 ((uint8_t) m_encryped);
    i.WriteU8 ((uint8_t) m_authenticated); 

    char tmpBuffer1 [m_encryptionKeyId.length()];
    NS_LOG_FUNCTION( "CRYPTOTAGID:" << sizeof(tmpBuffer1)/sizeof(tmpBuffer1[0]) << " ---- " << m_encryptionKeyId.length()  );
    strcpy (tmpBuffer1, m_encryptionKeyId.c_str());
    i.Write ((uint8_t *)tmpBuffer1, m_encryptionKeyId.length());

    char tmpBuffer2 [m_authenticationKeyId.length()];
    NS_LOG_FUNCTION( "AUTHKEYID:" << sizeof(tmpBuffer2)/sizeof(tmpBuffer2[0]) << " ---- " << m_authenticationKeyId.length()  );
    strcpy (tmpBuffer2, m_authenticationKeyId.c_str());
    i.Write ((uint8_t *)tmpBuffer2, m_authenticationKeyId.length());
    
    char tmpBuffer3 [m_authTag.length()];
    NS_LOG_FUNCTION( "AUTHTAG:" << sizeof(tmpBuffer3)/sizeof(tmpBuffer3[0]) << " ---- " << m_authTag.length()  );
    strcpy (tmpBuffer3, m_authTag.c_str());
    i.Write ((uint8_t *)tmpBuffer3, m_authTag.length());
}

uint32_t
QKDAppHeader::Deserialize (Buffer::Iterator start)
{

    Buffer::Iterator i = start; 
    m_valid = false;

    m_length = i.ReadNtohU32 (); 
    m_messageId = i.ReadNtohU32 ();
    m_encryped = i.ReadU8 ();
    m_authenticated = i.ReadU8 (); 
    
    uint32_t len1 = 32;
    char tmpBuffer1 [len1];
    i.Read ((uint8_t*)tmpBuffer1, len1); 
    m_encryptionKeyId = std::string(tmpBuffer1).substr(0, len1);  

    uint32_t len2 = 32;
    char tmpBuffer2 [len2];
    i.Read ((uint8_t*)tmpBuffer2, len2); 
    m_authenticationKeyId = std::string(tmpBuffer2).substr(0, len2);  

    uint32_t len3 = 32;
    char tmpBuffer3 [len3];
    i.Read ((uint8_t*)tmpBuffer3, len3); 
    m_authTag = std::string(tmpBuffer3).substr(0, len3);  

    NS_LOG_DEBUG ("Deserialize m_length: " << (uint32_t) m_length 
                << " m_messageId: " << (uint32_t) m_messageId 
                << " m_encryptionKeyId: " << m_encryptionKeyId
                << " m_authenticationKeyId: " << m_authenticationKeyId 
                << " m_valid: " << (uint32_t) m_valid 
                << " m_authTag: " << m_authTag
    );
   
    uint32_t dist = i.GetDistanceFrom (start);
    NS_LOG_FUNCTION( this << dist << GetSerializedSize() );
    NS_ASSERT (dist == GetSerializedSize ());
    return dist;
}

void
QKDAppHeader::Print (std::ostream &os) const
{  
    os << "\n"
       << "MESSAGE ID: "    << (uint32_t) m_messageId << "\t"
       << "Length: "        << (uint32_t) m_length << "\t"

       << "Authenticated: " << (uint32_t) m_authenticated << "\t"
       << "Encrypted: "     << (uint32_t) m_encryped << "\t" 
       
       << "EncryptKeyID: "  << m_encryptionKeyId << "\t" 
       << "AuthKeyID: "     << m_authenticationKeyId << "\t"  
       
       << "AuthTag: "       << m_authTag << "\t\n";
       
}

bool
QKDAppHeader::operator== (QKDAppHeader const & o) const
{ 
    return (m_messageId == o.m_messageId && m_authenticationKeyId == o.m_authenticationKeyId && m_authTag == o.m_authTag);
}

std::ostream &
operator<< (std::ostream & os, QKDAppHeader const & h)
{
    h.Print (os);
    return os;
} 
 

void 		
QKDAppHeader::SetLength (uint32_t value){ 

    NS_LOG_FUNCTION  (this << value); 
    m_length = value;
}
uint32_t 	
QKDAppHeader::GetLength (void) const{

    NS_LOG_FUNCTION  (this << m_length); 
    return m_length;
}

void 		
QKDAppHeader::SetMessageId (uint32_t value){
    
    NS_LOG_FUNCTION  (this << value); 
    m_messageId = value;
}
uint32_t 	
QKDAppHeader::GetMessageId (void) const{
    
    NS_LOG_FUNCTION  (this << m_messageId); 
    return m_messageId;
}

void 		
QKDAppHeader::SetEncryptionKeyId (std::string  value){

    NS_LOG_FUNCTION  (this << value); 

    NS_ASSERT(value.size() <= 32);
    if (value.size() < 32) {
        uint32_t diff = 32-value.size();
        std::string newValue = std::string(diff, '0') + value;
        m_encryptionKeyId = newValue; 
    } else
        m_encryptionKeyId = value; 
}

std::string  	
QKDAppHeader::GetEncryptionKeyId (void) const{

    NS_LOG_FUNCTION  (this << m_encryptionKeyId); 
    return m_encryptionKeyId;
}


void 		
QKDAppHeader::SetAuthenticationKeyId (std::string  value){

    NS_LOG_FUNCTION  (this << value); 

    NS_ASSERT(value.size() <= 32);
    if (value.size() < 32) {
        uint32_t diff = 32-value.size();
        std::string newValue = std::string(diff, '0') + value;
        m_authenticationKeyId = newValue;
    } else
        m_authenticationKeyId = value; 
}

std::string 	
QKDAppHeader::GetAuthenticationKeyId (void) const{

    NS_LOG_FUNCTION  (this << m_authenticationKeyId); 
    return m_authenticationKeyId;
}

void 		
QKDAppHeader::SetAuthTag (std::string value){

    NS_LOG_FUNCTION  (this << value << value.size());
    m_authTag = value;
}

std::string
QKDAppHeader::GetAuthTag (void) const{

    NS_LOG_FUNCTION  (this << m_authTag << m_authTag.size());
    return m_authTag;
}

void        
QKDAppHeader::SetEncrypted (uint32_t value){
    
    NS_LOG_FUNCTION  (this << value); 
    m_encryped = value;
}
uint32_t    
QKDAppHeader::GetEncrypted (void) const{

    NS_LOG_FUNCTION  (this << m_encryped); 
    return (uint32_t) m_encryped;
}

void        
QKDAppHeader::SetAuthenticated (uint32_t value){

    NS_LOG_FUNCTION  (this << value);
    m_authenticated = value;
}
uint32_t    
QKDAppHeader::GetAuthenticated (void) const{

    NS_LOG_FUNCTION  (this << m_authenticated); 
    return (uint32_t) m_authenticated;
}
 

} // namespace ns3
