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
 

#include <algorithm>                                                      
#include <numeric>    
#include "ns3/packet.h"
#include "ns3/simulator.h"
#include "ns3/log.h" 
#include "ns3/boolean.h"
#include "ns3/double.h"
#include "ns3/uinteger.h" 

#include "qkd-buffer.h"

namespace ns3 {

NS_LOG_COMPONENT_DEFINE ("QKDBuffer");

NS_OBJECT_ENSURE_REGISTERED (QKDBuffer);

TypeId 
QKDBuffer::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::QKDBuffer")
    .SetParent<Object> () 
    .AddConstructor<QKDBuffer> ()
    .AddAttribute ("Minimal", 
                   "The minimal amount of key material in QKD storage (bits)",
                   UintegerValue (1000000), //1Mb 
                   MakeUintegerAccessor (&QKDBuffer::m_minKeyBit),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("Maximal", 
                   "The maximal amount of key material in QKD storage (bits)",
                   UintegerValue (1000000000), //1Gb
                   MakeUintegerAccessor (&QKDBuffer::m_maxKeyBit),
                   MakeUintegerChecker<uint32_t> ())
    .AddAttribute ("Threshold", 
                   "The threshold amount of key material in QKD  (bits)",
                   UintegerValue (2000000), //2Mb
                   MakeUintegerAccessor (&QKDBuffer::m_thresholdKeyBit),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("Current", 
                   "The current amount of key material in QKD storage (bits)",
                   UintegerValue (5000000), //5Mb
                   MakeUintegerAccessor (&QKDBuffer::m_currentKeyBit),
                   MakeUintegerChecker<uint32_t> ())

    .AddAttribute ("CalculationTimePeriod", 
                   "The period of time (in seconds) to calculate average amount of the key in the buffer",
                   UintegerValue (5), // in seconds
                   MakeUintegerAccessor (&QKDBuffer::m_recalculateTimePeriod),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("MaxNumberOfRecordedKeyCharingTimePeriods", 
                   "The maximal number of values which are stored for calculation of average key charging rate",
                   UintegerValue (5), 
                   MakeUintegerAccessor (&QKDBuffer::m_maxNumberOfRecordedKeyChargingTimePeriods),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("MaxNumberOfRecordedKeyConsumptionTimePeriods", 
                   // It should be larger then numberOfKeyToFetchFromKMS within ETSI014 app to fetch long-term statistics. 
                   //If the value is too small then the it will reflect only burst ETSI 014 calls for keys
                   "The maximal number of values which are stored for calculation of average key consumption rate.",
                   UintegerValue (49), 
                   MakeUintegerAccessor (&QKDBuffer::m_maxNumberOfRecordedKeyConsumptionTimePeriods),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("DefaultKeySize", 
                   "The default key size",
                   UintegerValue (512), 
                   MakeUintegerAccessor (&QKDBuffer::m_defaultKeySize),
                   MakeUintegerChecker<uint32_t> ())     
    .AddAttribute ("MinimalKeyCount", 
                   "The minimal number of keys to be stored in the buffer (count of keys)",
                   UintegerValue (50),
                   MakeUintegerAccessor (&QKDBuffer::m_minimalKeyCount),
                   MakeUintegerChecker<uint32_t> ()) 
    .AddAttribute ("MaximalKeyCount", 
                   "The maximal number of keys to be stored in the buffer (count of keys)",
                   UintegerValue (50000),
                   MakeUintegerAccessor (&QKDBuffer::m_maximalKeyCount),
                   MakeUintegerChecker<uint32_t> ()) 

    .AddTraceSource ("ThresholdChange",
                     "The change trace for threshold amount of key material in QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_thresholdKeyBitChangeTrace),
                     "ns3::QKDBuffer::ThresholdChange") 

    .AddTraceSource ("ThresholdIncrease",
                     "The increase trace for threshold amount of key material in QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_thresholdKeyBitIncreaseTrace),
                     "ns3::QKDBuffer::ThresholdIncrease") 

    .AddTraceSource ("ThresholdDecrease",
                     "The decrease trace for threshold amount of key material in QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_thresholdKeyBitDecreaseTrace),
                     "ns3::QKDBuffer::ThresholdDecrease") 

    .AddTraceSource ("CurrentChange",
                    "The change trace for current amount of key material in QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_currentKeyBitChangeTrace),
                     "ns3::QKDBuffer::CurrentChange")

    .AddTraceSource ("CurrentIncrease",
                    "The increase trace for current amount of key material in QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_currentKeyBitIncreaseTrace),
                     "ns3::QKDBuffer::CurrentIncrease")

    .AddTraceSource ("CurrentDecrease",
                    "The decrease trace for current amount of key material in QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_currentKeyBitDecreaseTrace),
                     "ns3::QKDBuffer::CurrentDecrease")

    .AddTraceSource ("StatusChange",
                    "The change trace for current status of QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_StatusChangeTrace),
                     "ns3::QKDBuffer::StatusChange")
    .AddTraceSource ("CMetricChange",
                    "The change trace for current status of QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_CMetricChangeTrace),
                     "ns3::QKDBuffer::CMetricChange")
    .AddTraceSource ("AverageKeyGenerationRate",
                    "The average key rate of the QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_averageKeyGenerationRateTrace),
                     "ns3::QKDBuffer::AverageKeyGenerationRate")
    .AddTraceSource ("AverageKeyConsumptionRate",
                    "The average key rate of the QKD storage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_averageKeyConsumptionRateTrace),
                     "ns3::QKDBuffer::AverageKeyConsumptionRate")

    .AddTraceSource ("NewKeyAdded",
                    "The trace to monitor adding new key material to the buffer",
                     MakeTraceSourceAccessor (&QKDBuffer::m_newKeyAddedTrace),
                     "ns3::QKDBuffer::NewKeyAdded")
    .AddTraceSource ("TransformedKeyAdded",
                    "The trace to monitor adding transformed key material to the buffer",
                     MakeTraceSourceAccessor (&QKDBuffer::m_transformedKeyAddedTrace),
                     "ns3::QKDBuffer::TransformedKeyAdded")
    .AddTraceSource ("KeyServed", 
                     "The trace to monitor key usage",
                     MakeTraceSourceAccessor (&QKDBuffer::m_keyServedTrace),
                     "ns3::QKDBuffer::KeyServed")
    .AddTraceSource ("KeyReserved", 
                     "The trace to monitor key reservation",
                     MakeTraceSourceAccessor (&QKDBuffer::m_keyReservedTrace),
                     "ns3::QKDBuffer::KeyReserved")
    ; 
  return tid;
}

QKDBuffer::QKDBuffer()
{
    NS_LOG_FUNCTION(this);
}

void
QKDBuffer::Init(
  Ptr<Node> srcNode,
  Ptr<Node> dstNode,  
  uint32_t Mmin,
  uint32_t Mthr,
  uint32_t Mmax,
  uint32_t Mcurrent,
  bool     useRealStorages
)
{
    NS_LOG_FUNCTION(this << srcNode << dstNode); 
    m_srcNode = srcNode;  
    m_dstNode = dstNode;  
    m_nextKeyID = 0;
    m_minKeyBit = Mmin;
    m_thresholdKeyBit = Mmin;
    m_maxKeyBit = Mmax;
    m_currentKeyBit = Mcurrent;
    m_currentKeyBitReally = m_currentKeyBit;
    m_currentReadyKeyBit = Mcurrent;
    m_currentTargetKeyBit = 0;  
    m_useRealStorages = useRealStorages;
    
    m_bufferID = ++nBuffers;
    m_currentKeyBitPrevious = 0;  
    m_noEntry = 0; 
    m_period = 5;
    m_noAddNewValue = 0; 
     
    m_bitsUsedInTimePeriod = 0; 
    m_lastKeyChargingTimeStamp = 0; 
    m_previousStatus = 0;

    m_averageKeyGenerationRate = 0;
    m_averageKeyConsumptionRate = 0;

    m_lastKeyConsumptionTimeStamp = 0;
    m_lastKeyChargingTimeStamp = 0;

    m_lastKeyChargingTimeDuration = 0;
    m_lastKeyConsumptionTimeDuration = 0;

}

uint32_t QKDBuffer::nBuffers = 0;
 

QKDBuffer::~QKDBuffer ()
{
  NS_LOG_FUNCTION  (this);
  m_keys.clear();
  m_destinations.clear();
  m_targetSizeSet.clear();
}
 
void 
QKDBuffer::Dispose ()
{ 
    NS_LOG_FUNCTION  (this);
    Simulator::Cancel (m_calculateRoutingMetric); 
}

uint32_t
QKDBuffer::GetKeySize(){
  return m_defaultKeySize;
}

bool compareByData(const QKDBuffer::data &a, const QKDBuffer::data &b)
{
    return a.value > b.value;
}

void
QKDBuffer::KeyCalculation()
{   
    NS_LOG_FUNCTION  (this);
    //This function is used to define whether curve is going up or down (QKDGraphs)
    //This info is needed to define the state of the buffer (charging or warning)

    m_currentKeyBitPrevious = m_currentKeyBit;
    
    struct QKDBuffer::data q;
    q.value = m_currentKeyBit;
    q.position = m_noEntry;
   
    while( m_previousValues.size () > m_period ) m_previousValues.pop_back();
    m_previousValues.insert( m_previousValues.begin() ,q);
       
    //sort elements in descending order, first element has the maximum value
    std::sort(m_previousValues.begin(), m_previousValues.end(), compareByData);

    /*
    *   If maximal value is on the current location then it means that the current value is the highest in the period => function is rising
    *   Otherwise, function is going down
    */
    m_isRisingCurve = (m_previousValues[0].position == m_noEntry);
    CheckState(); 

    m_noEntry++;
}


uint32_t
QKDBuffer::GetKeyCount(){
  return m_keys.size(); 
}
uint32_t 
QKDBuffer::GetMinKeyCount(){
  return m_minimalKeyCount;
}
uint32_t 
QKDBuffer::GetMaxKeyCount(){
  return m_maximalKeyCount;
}
 
uint64_t
QKDBuffer::GetKeyCountBit(){
  return m_currentKeyBit;
}

uint64_t
QKDBuffer::GetReadyKeyCountBit(){
    return m_currentReadyKeyBit;
}

uint64_t
QKDBuffer::GetTargetKeyCountBit(){
    return m_currentTargetKeyBit;
}

uint64_t 
QKDBuffer::GetMinKeySizeBit(){
  return m_minKeyBit; 
}
uint64_t 
QKDBuffer::GetMaxKeySizeBit(){
  return m_maxKeyBit;
}

/**
*   Add new content to buffer
*   @param Ptr<QKDKey> key
*   @param uint32_t keyTransformed
*   Used when node receives information that new key material was establieshed
*/
bool
QKDBuffer::AddNewKey(Ptr<QKDKey> key, uint32_t keyTransformed)
{
    NS_LOG_FUNCTION ( this << key->GetId() << key->GetSizeInBits() << keyTransformed );
    NS_LOG_FUNCTION ( this << key->ToString());


    if((m_currentKeyBit + key->GetSizeInBits() >= m_maxKeyBit) && !keyTransformed) //It is expected to get transformed keys back to QKD buffer so we use m_currentKeyBit
    {
        NS_LOG_FUNCTION(this << "Buffer is full! Not able to add new " 
            << key->GetSizeInBits() << "bits, since the current is " 
            << m_currentKeyBit << " and max is " << m_maxKeyBit
        );        
        m_currentKeyBitChangeTrace (m_currentKeyBit);
        m_currentKeyBitIncreaseTrace (0);

    }else{

        m_keys.insert( std::make_pair(  key->GetId() ,  key) );
        m_currentKeyBit = m_currentKeyBit + key->GetSizeInBits();
        m_currentKeyBitReally = m_currentKeyBit;
        m_currentReadyKeyBit += key->GetSizeInBits();
        if(std::find(m_targetSizeSet.begin(), m_targetSizeSet.end(), key->GetSizeInBits()) != m_targetSizeSet.end()){
            m_currentTargetKeyBit += key->GetSizeInBits();
        }
        m_currentKeyBitChangeTrace (m_currentKeyBit);
        m_currentKeyBitIncreaseTrace (key->GetSizeInBits()); 
        
        if(keyTransformed){
            m_transformedKeyAddedTrace(key);
        }else{
            m_newKeyAddedTrace(key);
        }
    }

    /*
    * CALCULATE AVERAGE TIME PERIOD OF KEY CHARGING VALUE
    */

    if(keyTransformed == 0)
    {
        UpdateKeyGenerationStatistics(key);
        KeyCalculation();  
    }
 
    return true;
}

double
QKDBuffer::GetAverageKeyConsumptionRate(){

    NS_LOG_FUNCTION(this);

    //delete records older then 5 seconds
    int64_t currentTime = Simulator::Now ().GetSeconds();
    for(uint32_t i=0; i<m_consumptionTimePeriods.size(); i++){
        if(currentTime-m_consumptionTimePeriods[i] > 5){
            m_consumptionTimePeriods.erase(m_consumptionTimePeriods.begin()+i);
        }
    }

    //here we define temp variables
    double m_averageKeyConsumptionTimePeriodPeek = 0;
    double m_averageKeyConsumptionRatePeek = 0;
    std::vector < int64_t > m_consumptionTimePeriodsPeek = m_consumptionTimePeriods;

    //calculate average duration between key consumption requests (milliseconds) AND THE CURRENT TIME
    //Key consumption rate decreases with time if no new requests are detected. 
    //That is, when ETSI004 transformKeys operations are completed, no additional requests for keys are generated
    //If the ETSI004 connection is terminated, we need to calculate REAL consumption rate that depends on
    //the time when the sample (GetAverageKeyConsumptionRate) is taken (called)
    if(m_consumptionTimePeriods.size())
    {
        while( m_consumptionTimePeriodsPeek.size () > m_maxNumberOfRecordedKeyConsumptionTimePeriods ) m_consumptionTimePeriodsPeek.pop_back();

        for(uint32_t i=0; i<m_consumptionTimePeriods.size(); i++)
            NS_LOG_FUNCTION(this << "m_consumptionTimePeriods["<<i<<"]:" << m_consumptionTimePeriods[i]);
 
        m_consumptionTimePeriodsPeek.insert( m_consumptionTimePeriodsPeek.begin(), currentTime );

        double sum = 0;
        for(uint32_t i=0; i<m_consumptionTimePeriods.size(); i++)
            sum += currentTime-m_consumptionTimePeriods[i];

        m_averageKeyConsumptionTimePeriodPeek = sum / m_consumptionTimePeriodsPeek.size();

    }else{
      m_averageKeyConsumptionTimePeriodPeek = 0;
    }
    NS_LOG_DEBUG(this << " m_averageKeyConsumptionTimePeriodPeek (micro seconds): " << m_averageKeyConsumptionTimePeriodPeek );
    NS_LOG_DEBUG(this << " m_consumptionTimePeriodsPeek.size(): " << m_consumptionTimePeriodsPeek.size() );

    //average keyConsumptionSize is the same since no keys have been requested. 
    //we only ask for INFO about the key consumption rate, but we do not ask for keys here.

    //calculate average key generation rate (bits per seconds)
    if(m_averageKeyConsumptionSize && m_averageKeyConsumptionTimePeriodPeek){

        m_averageKeyConsumptionRatePeek = ((double) m_averageKeyConsumptionSize / (double) (m_averageKeyConsumptionTimePeriodPeek)); 
        
        NS_LOG_DEBUG (this << " m_averageKeyConsumptionSize (bits): " << m_averageKeyConsumptionSize );

        NS_LOG_DEBUG (this << " m_averageKeyConsumptionTimePeriod (seconds): " << m_averageKeyConsumptionTimePeriod);
        NS_LOG_DEBUG (this << " m_averageKeyConsumptionTimePeriodPeek (seconds): " << m_averageKeyConsumptionTimePeriodPeek );

        NS_LOG_DEBUG (this << " m_averageKeyConsumptionRate (bps): " << m_averageKeyConsumptionRate);
        NS_LOG_DEBUG (this << " m_averageKeyConsumptionRatePeek (bps): " << m_averageKeyConsumptionRatePeek);

        m_averageKeyConsumptionRate = m_averageKeyConsumptionRatePeek;
    }
    return round(m_averageKeyConsumptionRatePeek);
}

double
QKDBuffer::GetAverageKeyGenerationRate(){
    NS_LOG_FUNCTION(this);
    return round(m_averageKeyGenerationRate);
}

uint32_t 
QKDBuffer::FetchMaxNumberOfRecordedKeyChargingTimePeriods(){
    return m_maxNumberOfRecordedKeyChargingTimePeriods;
}

uint32_t
QKDBuffer::GetKeyCount (uint32_t keySize)
{
    NS_LOG_FUNCTION( this << keySize );
    uint32_t keyCount {0};
    for(std::map<std::string, Ptr<QKDKey> >::const_iterator it = m_keys.begin(); it != m_keys.end(); ++it){
        if(it->second->GetSizeInBits() == keySize && it->second->GetState() == QKDKey::READY)
            keyCount++;
    }

    return keyCount;
}

bool
QKDBuffer::ProbeKeyStatus (std::string keyId, QKDKey::QKDKeyState_e keyState){
    NS_LOG_FUNCTION( this << keyId );
    std::map<std::string, Ptr<QKDKey> >::iterator it = m_keys.find (keyId);
    if(it != m_keys.end()){
        if(it->second->GetState() == keyState)
            return true;
        else
            return false;
    }else{
        return false;
    }
}

/**
*   Fetch key from buffer with given key size!
*   This function is called by master KMS while selection keys to return
*   on ETSI 014 get_key request. Therefore, the selected key must be READY
*   and not reserved for other use.
*/
Ptr<QKDKey>
QKDBuffer::FetchKeyBySize (const uint32_t& keySize)
{   
    NS_LOG_FUNCTION(this << keySize << m_currentKeyBit << m_currentKeyBitReally); 
    
    Ptr<QKDKey> key = 0;
    for(std::map<std::string, Ptr<QKDKey> >::iterator it = m_keys.begin(); it != m_keys.end(); ++it){
        if(it->second->GetState() == QKDKey::READY && it->second->GetSizeInBits() == keySize){
            key = it->second;
            m_keys.erase (it); //Delete the key from the QKD buffer!
            
            UpdateKeyConsumptionStatistics(key);

            KeyCalculation();
            break;
        }
    }  
    if(!key) //Check
        NS_FATAL_ERROR( this << "Key of desired length is not available in the QKD buffer!");
    
    return key;
}

Ptr<QKDKey>
QKDBuffer::FetchKeyByID (std::string keyID)
{
    return FetchKeyByID (keyID, 0);
}    

//Note: Called even from the transform functions!
//Note: Function is allowed to return null value, processing left to the KMS.
Ptr<QKDKey>
QKDBuffer::FetchKeyByID (std::string keyID, uint32_t fillProcessActive)
{
    NS_LOG_FUNCTION(this << keyID << m_currentKeyBit << m_currentKeyBitReally << fillProcessActive); 

    Ptr<QKDKey> key = 0;
    NS_LOG_FUNCTION(this << "Searching for the key " << keyID << " ...");
    std::map<std::string, Ptr<QKDKey> >::iterator a = m_keys.find (keyID);
    if(a != m_keys.end ()){
        key = a->second;
        NS_LOG_FUNCTION(this << "Key is found " << key->GetId() << key->GetSizeInBits());
        m_keys.erase(a);
        NS_LOG_FUNCTION(this << "Key has been erased from the QKDBuffer " << key->GetId());

        NS_LOG_FUNCTION(this << "Returning key " << key->GetId() << " as the funtion output ...");

        if(fillProcessActive == 0) UpdateKeyConsumptionStatistics(key);
        else m_currentKeyBitReally -= key->GetSizeInBits();

    }else{
        NS_LOG_FUNCTION(this << "Key is not found ... Returning NULL value ...");
    }

    return key;
}

void
QKDBuffer::UpdateKeyConsumptionStatistics(Ptr<QKDKey> key)
{
    NS_LOG_FUNCTION(this);

    //Fire traces
    m_currentKeyBit -= key->GetSizeInBits();

    if(key->GetState() != QKDKey::RESERVED)
        m_currentReadyKeyBit -= key->GetSizeInBits();

    if(std::find(m_targetSizeSet.begin(), m_targetSizeSet.end(), key->GetSizeInBits()) != m_targetSizeSet.end()
        && key->GetState() != QKDKey::RESERVED)
        m_currentTargetKeyBit -= key->GetSizeInBits();

    m_currentKeyBitChangeTrace(m_currentKeyBit);
    m_currentKeyBitDecreaseTrace(key->GetSizeInBits());
    m_bitsUsedInTimePeriod -= key->GetSize();
    m_keyServedTrace(key);

    //calculate average duration between key consumption requests (milliseconds)
    int64_t currentTime = Simulator::Now ().GetSeconds();
    if(m_consumptionTimePeriods.size())
    {  
        double sum = 0;
        for(uint32_t i=0; i<m_consumptionTimePeriods.size(); i++)
            sum += currentTime-m_consumptionTimePeriods[i];

        m_averageKeyConsumptionTimePeriod = sum / m_consumptionTimePeriods.size();
    }else{
      m_averageKeyConsumptionTimePeriod = 0;
    }
    NS_LOG_DEBUG(this << " m_averageKeyConsumptionTimePeriod (micro seconds): " << m_averageKeyConsumptionTimePeriod );
    NS_LOG_DEBUG(this << " m_consumptionTimePeriods.size(): " << m_consumptionTimePeriods.size() );
    while( m_consumptionTimePeriods.size () > m_maxNumberOfRecordedKeyConsumptionTimePeriods ) m_consumptionTimePeriods.pop_back();
    m_consumptionTimePeriods.insert( m_consumptionTimePeriods.begin(), currentTime );

    int64_t tempPeriod = (m_consumptionTimePeriods.size() > 0) ? (currentTime - m_lastKeyConsumptionTimeStamp) : 1;    
    m_lastKeyConsumptionTimeDuration = tempPeriod;
    /*
    for(uint32_t i=0; i<m_consumptionTimePeriods.size(); i++){
        NS_LOG_FUNCTION(this << "m_consumptionTimePeriods["<<i<<"]:" << m_consumptionTimePeriods[i]);
    }
    */
    //calculate average consumption key size (bits)
    if(m_chargingTimePeriods.size())
    {
      m_averageKeyConsumptionSize = accumulate( 
        m_lastConsumedKeySizes.begin(), 
        m_lastConsumedKeySizes.end(), 0.0 
      ) / m_lastConsumedKeySizes.size();
    }else{
      m_averageKeyConsumptionSize = 0;
    }
    NS_LOG_DEBUG(this << " m_averageKeyConsumptionSize: " << m_averageKeyConsumptionSize );
    NS_LOG_DEBUG(this << " m_lastConsumedKeySizes.size(): " << m_lastConsumedKeySizes.size() );
    while( m_lastConsumedKeySizes.size () > m_maxNumberOfRecordedKeyConsumptionTimePeriods ) m_lastConsumedKeySizes.pop_back();
    m_lastConsumedKeySizes.insert( m_lastConsumedKeySizes.begin(), key->GetSizeInBits() );

    //calculate average key generation rate (bits per seconds)
    if(m_averageKeyConsumptionSize && m_averageKeyConsumptionTimePeriod){
        m_averageKeyConsumptionRate = ((double) m_averageKeyConsumptionSize / (double) (m_averageKeyConsumptionTimePeriod));
        m_averageKeyConsumptionRateTrace (m_averageKeyConsumptionRate);

        NS_LOG_DEBUG (this << " m_averageKeyConsumptionRate (bps): " << m_averageKeyConsumptionRate);
        NS_LOG_DEBUG (this << " m_averageKeyConsumptionSize (bits): " << m_averageKeyConsumptionSize );
        NS_LOG_DEBUG (this << " m_averageKeyConsumptionTimePeriod (seconds): " << m_averageKeyConsumptionTimePeriod );
    }

    m_lastKeyConsumptionTimeStamp = currentTime;
}

void
QKDBuffer::UpdateKeyGenerationStatistics(Ptr<QKDKey> key){

    NS_LOG_FUNCTION(this << key->GetId());

    //calculate average duration of key generation process (milliseconds)
    if(m_chargingTimePeriods.size())
    {
      m_averageKeyChargingTimePeriod = accumulate( 
        m_chargingTimePeriods.begin(), 
        m_chargingTimePeriods.end(), 0.0 
      ) / m_chargingTimePeriods.size();
    }else{
      m_averageKeyChargingTimePeriod = 0;
    }
    NS_LOG_DEBUG(this << " m_averageKeyChargingTimePeriod: " << m_averageKeyChargingTimePeriod );
    NS_LOG_DEBUG(this << " m_chargingTimePeriods.size(): " << m_chargingTimePeriods.size() );
    while( m_chargingTimePeriods.size () > m_maxNumberOfRecordedKeyChargingTimePeriods ) m_chargingTimePeriods.pop_back();
    int64_t currentTime = Simulator::Now ().GetSeconds();
    int64_t tempPeriod = (m_chargingTimePeriods.size() > 0) ? (currentTime - m_lastKeyChargingTimeStamp) : 1;
    m_chargingTimePeriods.insert( m_chargingTimePeriods.begin(), tempPeriod );
    m_lastKeyChargingTimeDuration = tempPeriod;
    m_lastKeyChargingTimeStamp = currentTime;

    //calculate average generated key size (bits)
    if(m_chargingTimePeriods.size())
    {
      m_averageKeyChargingSize = accumulate( 
        m_lastChargedKeySizes.begin(), 
        m_lastChargedKeySizes.end(), 0.0 
      ) / m_lastChargedKeySizes.size();
    }else{
      m_averageKeyChargingSize = 0;
    }
    NS_LOG_DEBUG(this << " m_averageKeyChargingSize: " << m_averageKeyChargingSize );
    NS_LOG_DEBUG(this << " m_lastChargedKeySizes.size(): " << m_lastChargedKeySizes.size() );
    while( m_lastChargedKeySizes.size () > m_maxNumberOfRecordedKeyChargingTimePeriods ) m_lastChargedKeySizes.pop_back();
    m_lastChargedKeySizes.insert( m_lastChargedKeySizes.begin(), key->GetSizeInBits() );

    //calculate average key generation rate (bits per seconds)
    if(m_averageKeyChargingSize && m_averageKeyChargingTimePeriod){
        m_averageKeyGenerationRate = ((double) m_averageKeyChargingSize / (double) (m_averageKeyChargingTimePeriod));
        m_averageKeyGenerationRateTrace (m_averageKeyGenerationRate);
    }
    NS_ASSERT(m_averageKeyGenerationRate >= 0);

    NS_LOG_DEBUG (this << " m_averageKeyGenerationRate (bps): " << m_averageKeyGenerationRate);
    NS_LOG_DEBUG (this << " m_averageKeyChargingSize (bits): " << m_averageKeyChargingSize );
    NS_LOG_DEBUG (this << " m_averageKeyChargingTimePeriod (Seconds): " << m_averageKeyChargingTimePeriod );

    m_period = m_noEntry - m_noAddNewValue;
    m_noAddNewValue = m_noEntry;

    NS_LOG_FUNCTION  (this << "New key material added");
}



/*
 Transform
 */
void  
QKDBuffer::ReserveKey (std::string keyId)
{   
    NS_LOG_FUNCTION(this << "Reserving key " << keyId << " ...");
    std::map<std::string, Ptr<QKDKey> >::iterator it = m_keys.find(keyId);

    if(it != m_keys.end()){

        NS_LOG_FUNCTION(this << "Reserving key " << keyId << " of size " << it->second->GetSizeInBits());
 
        if(it->second->GetState() == QKDKey::READY){
            it->second->MarkReserved(); //@toDo include reservation_type!

            NS_LOG_FUNCTION(this << m_currentReadyKeyBit << it->second->GetSizeInBits());
            m_currentReadyKeyBit -= it->second->GetSizeInBits();

            if(std::find(m_targetSizeSet.begin(), m_targetSizeSet.end(), it->second->GetSizeInBits()) != m_targetSizeSet.end())
                m_currentTargetKeyBit -= it->second->GetSizeInBits();

            NS_LOG_FUNCTION(this << m_currentReadyKeyBit);

            m_keyReservedTrace(it->second);

        }else
            NS_FATAL_ERROR(this << "Key reservation failed ... Error message: Key " 
                                << keyId << " has been already reserved or served for another purpose.");
    }else{
        NS_FATAL_ERROR(this << "Key reservation failed ... Error message: Key "
                            << keyId << "cannot be found in the QKDBuffer.");
    }
}

void
QKDBuffer::ReleaseReservation (std::string keyId)
{
    NS_LOG_FUNCTION(this << "Releasing reservation of the key" << keyId << " ...");
    std::map<std::string, Ptr<QKDKey> >::iterator it = m_keys.find(keyId);
    if(it != m_keys.end()){
        if(it->second->GetState() == QKDKey::RESERVED){
            it->second->MarkReady();
            m_currentReadyKeyBit += it->second->GetSizeInBits();
            NS_LOG_FUNCTION(this << "Reservation sucessfully released.");
        }else
            NS_FATAL_ERROR(this << "Release reservation failed ... Error message: Key "
                                << keyId << "has not been in the RESRVED state.");
    }else{
        NS_FATAL_ERROR(this << "Release reservation failed ... Error message: Key "
                            << keyId << "cannot be found in the QKDBuffer.");
    }
}

Ptr<QKDKey>
QKDBuffer::SearchOptimalKeyToTransform (uint32_t targetSize)
{   
    //@toDo optimal key should be a random key from a set of best matched keys <= 100 large, to improve on avoidance of collisions
    NS_LOG_FUNCTION( this << "Searching optimal key to tranform " << targetSize << m_keys.size());

    Ptr<QKDKey> optimalKey {}, optimalKeySecond {};
    std::map<std::string, Ptr<QKDKey> >::iterator it = m_keys.begin();
    while(it != m_keys.end()){

        NS_LOG_FUNCTION (this << it->second->GetId() << it->second->GetSize() << it->second->GetSizeInBits() << it->second->GetState());

        if(
            it->second->GetSizeInBits() >= targetSize &&
            std::find(m_targetSizeSet.begin(), m_targetSizeSet.end(), it->second->GetSizeInBits()) == m_targetSizeSet.end() &&
            it->second->GetState() == QKDKey::READY &&
            !optimalKey
        ){
            optimalKey = it->second; //The first match for optimal key
            NS_LOG_FUNCTION(this << "Starting optimal key " << optimalKey->GetId());
        }
        else if(
            it->second->GetSizeInBits() >= targetSize &&
            std::find(m_targetSizeSet.begin(), m_targetSizeSet.end(), it->second->GetSizeInBits()) == m_targetSizeSet.end() &&
            it->second->GetState() == QKDKey::READY &&
            it->second->GetSizeInBits() < optimalKey->GetSizeInBits()
        )
            optimalKey = it->second;
        if(
            !optimalKeySecond &&
            std::find(m_targetSizeSet.begin(), m_targetSizeSet.end(), it->second->GetSizeInBits()) == m_targetSizeSet.end() &&
            it->second->GetState() == QKDKey::READY
        )
            optimalKeySecond = it->second;
        else if(
            optimalKeySecond &&
            optimalKeySecond->GetSizeInBits() < it->second->GetSizeInBits() &&
            std::find(m_targetSizeSet.begin(), m_targetSizeSet.end(), it->second->GetSizeInBits()) == m_targetSizeSet.end() &&
            it->second->GetState() == QKDKey::READY
        )
            optimalKeySecond = it->second; //Results in largest key in QKD Buffer
        
        ++it;
    }

    if(!optimalKey){
        NS_ASSERT(optimalKeySecond);   
        return optimalKeySecond;
    }

    return optimalKey;
}

void
QKDBuffer::RecordTargetSize (uint32_t size)
{
    NS_LOG_FUNCTION( this << size );
    std::vector<uint32_t>::iterator it = std::find(m_targetSizeSet.begin(), m_targetSizeSet.end(), size);
    if(it == m_targetSizeSet.end())
        m_targetSizeSet.push_back(size);
}

void 
QKDBuffer::CheckState(void)
{
    NS_LOG_FUNCTION  (this << m_minKeyBit << m_currentKeyBit << m_currentKeyBitPrevious << m_thresholdKeyBit << m_maxKeyBit << m_status << m_previousStatus );

	if(m_currentKeyBit >= m_thresholdKeyBit){ 
         NS_LOG_FUNCTION  ("case 1");
		 m_status = QKDBuffer::QKDSTATUS_READY;

	}else if(m_currentKeyBit < m_thresholdKeyBit && m_currentKeyBit > m_minKeyBit && 
        ((m_isRisingCurve == true && m_previousStatus != QKDBuffer::QKDSTATUS_READY) || m_previousStatus == QKDBuffer::QKDSTATUS_EMPTY )
    ){
         NS_LOG_FUNCTION  ("case 2");
		 m_status = QKDBuffer::QKDSTATUS_CHARGING;

	}else if(m_currentKeyBit < m_thresholdKeyBit && m_currentKeyBit > m_minKeyBit && 
        (m_previousStatus != QKDBuffer::QKDSTATUS_CHARGING)
    ){ 
         NS_LOG_FUNCTION  ("case 3");
		 m_status = QKDBuffer::QKDSTATUS_WARNING;

	}else if(m_currentKeyBit <= m_minKeyBit){ 
        NS_LOG_FUNCTION  ("case 4");
		 m_status  = QKDBuffer::QKDSTATUS_EMPTY; 
	}else{ 
         NS_LOG_FUNCTION  ("case UNDEFINED"     << m_minKeyBit << m_currentKeyBit << m_currentKeyBitPrevious << m_thresholdKeyBit << m_maxKeyBit << m_status << m_previousStatus ); 
    } 

    if(m_previousStatus != m_status){
        NS_LOG_FUNCTION  (this << "STATUS IS NOT EQUAL TO PREVIOUS STATUS" << m_previousStatus << m_status);
        NS_LOG_FUNCTION  (this << m_minKeyBit << m_currentKeyBit << m_currentKeyBitPrevious << m_thresholdKeyBit << m_maxKeyBit << m_status << m_previousStatus );
 
        m_StatusChangeTrace(m_previousStatus);
        m_StatusChangeTrace(m_status);
        m_previousStatus = m_status;
    } 
}

bool
QKDBuffer::operator== (QKDBuffer const & o) const
{ 
    return (this->m_bufferID == o.m_bufferID);
}
 

uint32_t
QKDBuffer::GetId() const{
    NS_LOG_FUNCTION  (this << this->m_bufferID); 
    return this->m_bufferID ;
}

void
QKDBuffer::InitTotalGraph() const{

  NS_LOG_FUNCTION  (this);  

  m_currentKeyBitIncreaseTrace (m_currentKeyBit);
  m_thresholdKeyBitIncreaseTrace(m_thresholdKeyBit); 
  
}

/**
*   Return time value about the time duration of last key charging process
*/
int64_t
QKDBuffer::FetchLastKeyChargingTimeDuration(){

  NS_LOG_FUNCTION  (this);
  return m_lastKeyChargingTimeDuration;
}

/*
*   Return time difference between the current time and time at which 
*   last key charging process finished
*/
int64_t
QKDBuffer::FetchDeltaTime(){

  NS_LOG_FUNCTION  (this); 
  int64_t currentTime = Simulator::Now ().GetMilliSeconds();
  return currentTime - m_lastKeyChargingTimeStamp; 
}

double
QKDBuffer::FetchAverageKeyChargingTimePeriod(){
  NS_LOG_FUNCTION  (this << m_averageKeyChargingTimePeriod); 
  return m_averageKeyChargingTimePeriod;
}

uint32_t
QKDBuffer::FetchState(void)
{
    NS_LOG_FUNCTION  (this << m_status); 
    return m_status;
}

uint32_t
QKDBuffer::FetchPreviousState(void)
{
    NS_LOG_FUNCTION  (this << m_previousStatus); 
    return m_previousStatus;
}

uint32_t 
QKDBuffer::GetMCurrentPrevious (void) const
{
    NS_LOG_FUNCTION  (this << m_currentKeyBitPrevious); 
    return m_currentKeyBitPrevious;
}

uint32_t 
QKDBuffer::GetMthr (void) const
{
    NS_LOG_FUNCTION  (this << m_thresholdKeyBit); 
    return m_thresholdKeyBit;
}
void
QKDBuffer::SetMthr (uint32_t thr)
{
    NS_LOG_FUNCTION  (this << thr); 

    if(thr > m_thresholdKeyBit){
      m_thresholdKeyBitIncreaseTrace (thr - m_thresholdKeyBit);
    }else{
      m_thresholdKeyBitDecreaseTrace (m_thresholdKeyBit - thr);
    }

    m_thresholdKeyBit = thr;
    m_thresholdKeyBitChangeTrace(m_thresholdKeyBit);
}
 
void 
QKDBuffer::SetSrcNode (Ptr<Node> node){
  m_srcNode = node;
}
Ptr<Node> 
QKDBuffer::GetSrcNode (){
  return m_srcNode;
}

void 
QKDBuffer::SetDstNode (Ptr<Node> node){
  m_dstNode = node;
}
Ptr<Node> 
QKDBuffer::GetDstNode (){
  return m_dstNode;
}

void 
QKDBuffer::SetIndex (uint32_t index){
  m_srcNodeBufferListIndex = index;
}
uint32_t
QKDBuffer::GetIndex (){
  return m_srcNodeBufferListIndex;
}

} // namespace ns3
