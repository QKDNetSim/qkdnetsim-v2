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
#include "ns3/packet.h"
#include "ns3/assert.h"
#include "ns3/log.h" 
#include "qkd-key.h" 
#include <string>
#include <cstdarg>

#include <iostream>
#include <ctime>
#include <unistd.h>
#include <cryptopp/base64.h>


namespace ns3 {

    NS_LOG_COMPONENT_DEFINE ("QKDKey"); 

    NS_OBJECT_ENSURE_REGISTERED (QKDKey);

    TypeId 
    QKDKey::GetTypeId (void)
    {
        static TypeId tid = TypeId ("ns3::QKDKey")
            .SetParent<Object> () 
            .AddTraceSource ("StateTransition",
                     "Trace fired upon every QKDKey state transition.",
                     MakeTraceSourceAccessor (&QKDKey::m_stateTransitionTrace),
                     "ns3::Application::StateTransitionCallback")
            ;
            return tid;
    }

    uint64_t QKDKey::m_globalUid = 0;
      
    Ptr<QKDKey> 
    QKDKey::Copy (void) const
    {
      // we need to invoke the copy constructor directly
      // rather than calling Create because the copy constructor
      // is private.
      return Ptr<QKDKey> (new QKDKey (*this), false);
    }


    /*
        @toDO: this funtion will need modification
        need to look like the other constructor!
    */
    QKDKey::QKDKey (uint64_t size)
      : m_sizeInBits (size),
        m_state (INIT)
    {
      NS_LOG_FUNCTION  (this  << size ); 

        m_globalUid++;
        m_internalID = m_globalUid;
        m_id = GenerateRandomString(8);
        m_id += "-";
        m_id += m_globalUid; 
        m_timestamp = Simulator::Now ();
        m_random = CreateObject<UniformRandomVariable> ();  

        if(m_sizeInBits%8 != 0) {
            NS_FATAL_ERROR( this << "Key size must divided with 8!" );
        }
        m_sizeInBytes = m_sizeInBits/8; 

        //ETSI 014 - Keys are encoded using Base64
        std::string randomString = GenerateRandomString(size/7);
        std::string keyBinary;
        for (std::size_t i = 0; i < randomString.size(); ++i){
          keyBinary += std::bitset<8>(randomString.c_str()[i]).to_string();
        }

        CryptoPP::StringSource(keyBinary, true,
            new CryptoPP::Base64Encoder(
              new CryptoPP::StringSink(m_key)
            ) // Base64Encoder
        ); // StringSource
        m_key = m_key.substr(0, m_sizeInBytes);
        NS_LOG_FUNCTION  (this << m_id << m_sizeInBytes << m_key.length() << GetStateString() ); 

        SwitchToState(READY);

    }

    QKDKey::QKDKey (
        std::string keyId, 
        uint64_t keyIdnum,
        uint64_t size)
      : m_id (keyId), 
        m_sizeInBits (size), 
        m_state (INIT)
    {
      NS_LOG_FUNCTION  (this << m_id << m_sizeInBytes ); 

        m_globalUid++;
        m_internalID = keyIdnum;
        m_timestamp = Simulator::Now ();
        m_random = CreateObject<UniformRandomVariable> ();  

        if(m_sizeInBits%8 != 0) {
            NS_FATAL_ERROR( this << "Key size must divided with 8! You tried to create a key of size " << m_sizeInBits << " (bits), " << m_sizeInBytes << " (bytes)" );
        }
        m_sizeInBytes = m_sizeInBits/8; 

        std::string randomString = GenerateRandomString(m_sizeInBytes);      
        m_key = randomString.substr(0, m_sizeInBytes);
 
        NS_LOG_FUNCTION ( this << m_internalID << m_key.length() << m_key ); 
        SwitchToState(READY);    
    }


    QKDKey::QKDKey (
        std::string keyId, 
        uint64_t keyIdnum,
        std::string key)
      : m_id (keyId),  
        m_key (key),
        m_state (INIT)
    {
      NS_LOG_FUNCTION  (this << m_id << m_key.length() ); 

        m_globalUid++;
        m_internalID = keyIdnum;
        m_timestamp = Simulator::Now ();
        m_sizeInBytes = m_key.length(); 
        m_sizeInBits = m_sizeInBytes*8;
        m_random = CreateObject<UniformRandomVariable> ();   

        NS_LOG_FUNCTION ( this << m_internalID << m_key.length() << m_key ); 
        SwitchToState(READY);    
    }

    QKDKey::QKDKey (
        std::string keyId,
        std::string key)
      : m_id (keyId),
        m_key (key),
        m_state (INIT)
    {
        m_timestamp = Simulator::Now ();
        m_sizeInBytes = m_key.length();
        m_sizeInBits = m_sizeInBytes*8; 
        m_random = CreateObject<UniformRandomVariable> ();  
        SwitchToState(READY);
    }

    std::string
    QKDKey::GetKeyString() //To get key content without changing its state!
    {
      NS_LOG_FUNCTION( this );
      return m_key;
    }

    std::string
    QKDKey::GetKeyBinary(){

		NS_LOG_FUNCTION(this);

		std::string keyBinary;
		for (std::size_t i = 0; i < m_key.size(); ++i){
	  		keyBinary += std::bitset<8>(m_key.c_str()[i]).to_string();
		}
		NS_LOG_FUNCTION(this);
		return keyBinary;
    }
 
    std::string        
    QKDKey::GetId (void) const
    {
        return m_id;
    }

    void            
    QKDKey::SetId (std::string value)
    {
        m_id = value;
    }
 
    uint64_t 
    QKDKey::GetSize (void) const
    {
      NS_LOG_FUNCTION  (this << m_id << m_sizeInBytes); 
      return m_sizeInBytes;
    }

    uint64_t
    QKDKey::GetSizeInBits(void) const
    {
        NS_LOG_FUNCTION(this << m_id << m_sizeInBytes*8);
        return m_sizeInBytes*8;
    }  
 
    void
    QKDKey::SetSize (uint64_t sizeInBytes)
    {
        NS_LOG_FUNCTION  (this << m_id << sizeInBytes); 

        if(sizeInBytes%8 != 0) NS_FATAL_ERROR( this << "Key size must divided with 8!" );  

        m_sizeInBytes = sizeInBytes;
        m_sizeInBits = m_sizeInBytes * 8;
    }

    std::string
    QKDKey::ConsumeKeyString (void)
    {
        NS_LOG_FUNCTION  (this << m_id << m_key.length() ); 
        SwitchToState(SERVED);
        return m_key;
    }

    std::string
    QKDKey::ToString (void)
    {
        NS_LOG_FUNCTION  (this << m_id << m_key.length() );  
        return m_key;
    }

    uint8_t *     
    QKDKey::GetKey(void)
    {
        NS_LOG_FUNCTION  (this << m_id << m_key.length() ); 
        SwitchToState(SERVED);
        uint8_t* temp = new uint8_t [m_key.length()];
        memcpy( temp, m_key.data(), m_key.length());
        return temp;
    }

    void
    QKDKey::MarkReady(){
        NS_LOG_FUNCTION( this << m_id << m_key.length() << m_state );
        SwitchToState(READY);
    }

    void
    QKDKey::MarkServed(){

        NS_LOG_FUNCTION  (this << m_id << m_key.length() << m_state ); 
        SwitchToState(SERVED);  
    }

    void
    QKDKey::MarkUsed(){

        NS_LOG_FUNCTION  (this << m_id << m_key.length() << m_state ); 
        SwitchToState(USED);  
    }

    void
    QKDKey::MarkRestored(){

        NS_LOG_FUNCTION  (this << m_id << m_key.length() << m_state ); 
        SwitchToState(RESTORED);  

    }

    void
    QKDKey::MarkReserved(){
        NS_LOG_FUNCTION( this << m_id << m_key.length() << m_state );
        SwitchToState(RESERVED);
    }

    void
    QKDKey::MarkTransformed(){
        NS_LOG_FUNCTION( this << m_id << m_key.length() << m_state );
        SwitchToState(TRANSFORMED);
    }

    std::string 
    QKDKey::GenerateRandomString(const int len) {

    	NS_LOG_FUNCTION ( this << m_internalID << len );

        std::string tmp_s;
        static const char alphanum[] =
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";

        uint32_t randVal = 0;
        for (int i = 0; i < len; ++i){ 
            randVal = round(m_random->GetValue (0, sizeof(alphanum) - 1));
            tmp_s += alphanum[ randVal ];
        } 
        return tmp_s;
    }

    QKDKey::QKDKeyState_e
    QKDKey::GetState () const
    {
      return m_state;
    }
 

    // static
    std::string
    QKDKey::GetStateString (QKDKey::QKDKeyState_e state)
    {
      switch (state)
        {
        case INIT:
          return "INIT";
          break;
        case READY:
          return "READY";
          break; 
        case SERVED:
          return "SERVED";
          break;
        case USED:
          return "USED";
          break; 
        case TRANSFORMED:
          return "TRANSFORMED";
          break; 
        case OBSOLETE:
          return "OBSOLETE";
          break;  
        case RESTORED:
          return "RESTORED";
          break; 
        case RESERVED:
          return "RESERVED";
          break; 
        default:
          NS_FATAL_ERROR ("Unknown state");
          return "FATAL_ERROR";
          break;
        }
    }


    std::string
    QKDKey::GetStateString () const
    {
      return GetStateString (m_state);
    }

    void
    QKDKey::SwitchToState (QKDKey::QKDKeyState_e state)
    {
      const std::string oldState = GetStateString ();
      const std::string newState = GetStateString (state);
      NS_LOG_FUNCTION (this << oldState << newState);
     
      m_state = state;

      NS_LOG_INFO (this << " QKDKey " << oldState
                        << " --> " << newState << ".");
      m_stateTransitionTrace (oldState, newState);
    }

    Time
    QKDKey::GetKeyTimestamp() 
    {
      return m_timestamp;
    }

} // namespace ns3
