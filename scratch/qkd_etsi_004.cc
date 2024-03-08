/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2022 www.tk.etf.unsa.ba
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
 * Execute using ./waf --run scratch/qkd_etsi_combined_input.cc --command-template="mpirun -np 4 %s"
 *
 * Author:  Emir Dervisevic <emir.dervisevic@etf.unsa.ba>
 *          Miralem Mehic <miralem.mehic@ieee.org>
 */
#include <stdio.h>
#include <fstream>
#include <iostream>
#include <cmath>
#include "ns3/core-module.h" 
#include "ns3/applications-module.h"
#include "ns3/internet-module.h" 
#include "ns3/flow-monitor-module.h" 
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/gnuplot.h" 
#include "ns3/internet-apps-module.h"

#include "ns3/qkd-link-helper.h" 
#include "ns3/qkd-app-helper.h"
#include "ns3/qkd-app-004.h"

#include "ns3/network-module.h" 
#include "ns3/internet-apps-module.h"
#include "ns3/netanim-module.h" 
#include "ns3/mpi-module.h"
#include "ns3/dsdv-helper.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("QKD_ETSI004");

uint32_t showKeyAdded = 1;
uint32_t showKeyServed = 1;

std::string outputFileType ("json");
std::ofstream logFile;
nlohmann::json outputLogFile;

static void
PingRtt (std::string context, Time rtt)
{
  NS_LOG_UNCOND ("Received Response with RTT = " << rtt);
}

struct LinkDetails
{
    std::string title;
    std::string nodes;
    std::string linkId;
    uint32_t type; //0-PP; 1-ETSI004; 2-ETSI014

    uint32_t srcNodeId;
    uint32_t dstNodeId;

    uint32_t m_linkDistance = 0;
    uint32_t m_keyRate = 0;
    uint32_t m_keysGenerated = 0;
    uint32_t m_keysGeneratedBits = 0;
    uint32_t m_keysConsumed = 0;
    uint32_t m_keysConsumedBits = 0;
    uint32_t m_bufferCapacityBits = 0;
    double m_avgSizeOfGeneratedKeys = 0;
    double m_avgSizeOfConsumedKeys = 0;

    uint32_t m_appPacketsSent = 0;
    uint32_t m_appPacketsReceived = 0;
    uint32_t m_bytes_sent = 0;  
    uint32_t m_bytes_received = 0; 
    uint32_t m_missedSendPacketCalls = 0;

    uint32_t m_encryptionType;
    uint32_t m_authenticationType;
    uint32_t m_aesLifeTime = 0;
    uint32_t m_packetSize = 0;
    uint32_t m_trafficRate = 0;
    uint32_t m_sizeOfKeyBufferForEncryption = 0;
    uint32_t m_sizeOfKeyBufferForAuthentication = 0;
    uint32_t m_numberOfKeysToFetchFromKMS = 0;
    uint32_t m_priority = 0;
    uint32_t m_ttl = 0;

    uint32_t m_requestedChunkKeys = 0;
    uint32_t m_providedChunkKeys = 0;
    uint32_t m_availableChunkKeys = 0;

    uint32_t m_startTime = 0;
    uint32_t m_stopTime = 0;

    uint32_t m_appSigPacketsSent = 0;
    uint32_t m_appSigPacketsReceived = 0;
    uint32_t m_sig_bytes_sent = 0;  
    uint32_t m_sig_bytes_received = 0;

    uint32_t m_kmsPacketsSent = 0;
    uint32_t m_kmsPacketsReceived = 0;
    uint32_t m_bytes_sent_to_kms = 0;  
    uint32_t m_bytes_received_from_kms = 0; 
    
    uint32_t m_keysGeneratedKMS = 0;
    uint32_t m_keysGeneratedKMSBits = 0;
    uint32_t m_keysConsumedKMS = 0;
    uint32_t m_keysConsumedKMSBits = 0;
    double m_keysAvgSizeConsumedKMSBits = 0;
         
    uint32_t m_printed = 0;

    std::map<std::string, uint32_t> m_keyIDGeneratedInBuffers;
    std::map<std::string, uint32_t> m_keyIDConsumedInBuffers;
    std::map<std::string, uint32_t> m_keyIDConsumedByKMS;
};

std::map<std::string, LinkDetails*> m_connectionPairs;

void 
write_csv(std::string filename, std::vector<std::pair<std::string, std::vector<uint32_t>>> dataset)
{
    // Make a CSV file with one or more columns of integer values
    // Each column of data is represented by the pair <column name, column data>
    //   as std::pair<std::string, std::vector<int>>
    // The dataset is represented as a vector of these columns
    // Note that all columns should be the same size
    
    // Create an output filestream object
    std::ofstream myFile(filename);
    
    // Send column names to the stream
    for(uint32_t j = 0; j < dataset.size(); ++j)
    {
        myFile << dataset.at(j).first;
        if(j != dataset.size() - 1) myFile << ","; // No comma at end of line
    }
    myFile << "\n";
    
    // Send data to the stream
    for(uint32_t i = 0; i < dataset.at(0).second.size(); ++i)
    {
        for(uint32_t j = 0; j < dataset.size(); ++j)
        {
            myFile << dataset.at(j).second.at(i);
            if(j != dataset.size() - 1) myFile << ","; // No comma at end of line
        }
        myFile << "\n";
    }
    
    // Close the file
    myFile.close();
}


std::vector<std::pair<std::string, std::vector<uint32_t>>> 
read_csv(std::string filename){
    // Reads a CSV file into a vector of <string, vector<uint32_t>> pairs where
    // each pair represents <column name, column values>

    // Create a vector of <string, uint32_t vector> pairs to store the result
    std::vector<std::pair<std::string, std::vector<uint32_t> > > result;

    // Create an input filestream
    std::ifstream myFile(filename);

    // Make sure the file is open
    if(!myFile.is_open()) throw std::runtime_error("Could not open file");

    // Helper vars
    std::string line, colname;
    uint32_t val;

    // Read the column names
    if(myFile.good())
    {
        // Extract the first line in the file
        std::getline(myFile, line);

        // Create a stringstream from line
        std::stringstream ss(line);

        // Extract each column name
        while(std::getline(ss, colname, ',')){
            
            // Initialize and add <colname, uint32_t vector> pairs to result
            result.push_back({colname, std::vector<uint32_t> {}});
        }
    }

    // Read data, line by line
    while(std::getline(myFile, line))
    {
        // Create a stringstream of the current line
        std::stringstream ss(line);
        
        // Keep track of the current column index
        uint32_t colIdx = 0;
        
        // Extract each integer
        while(ss >> val){
            
            // Add the current integer to the 'colIdx' column's values vector
            result.at(colIdx).second.push_back(val);
            
            // If the next token is a comma, ignore it and move on
            if(ss.peek() == ',') ss.ignore();
            
            // Increment the column index
            colIdx++;
        }
    }

    // Close file
    myFile.close();

    return result;
}

std::map<std::string, LinkDetails* >::iterator
FindByContext(std::string context, std::string ksid = "")
{   
    std::map<std::string, LinkDetails* >::iterator it = m_connectionPairs.find ( ksid );
    if (ksid.empty() || it == m_connectionPairs.end ()){

        std::string nodeLocated = std::regex_replace(
            context,
            std::regex("[^0-9]*([0-9]+).*"),
            std::string("$1")
        );
        uint32_t nodeId = std::stoi(nodeLocated);

        for (std::map<std::string, LinkDetails* >::iterator it2 = m_connectionPairs.begin(); it2 != m_connectionPairs.end(); ++it2) 
        {
            if(it2->second->srcNodeId == nodeId || it2->second->dstNodeId == nodeId) return it2;
        }
        
        NS_FATAL_ERROR ( "No link defined for ksid " << ksid);
    }
    return it;
}

void
KeyServedKMSEtsi014(
    std::string           context, 
    const std::string   & ksid, 
    Ptr<QKDKey>           key
){

    std::map<std::string, LinkDetails* >::iterator it = m_connectionPairs.find ( ksid );
    if (it == m_connectionPairs.end ()) NS_FATAL_ERROR ( "No link defined for ksid " << ksid);
    std::string linkId = it->second->nodes;

    std::map<std::string, uint32_t>::iterator it2 = it->second->m_keyIDConsumedByKMS.find ( key->GetId() );
    if (it2 == it->second->m_keyIDConsumedByKMS.end ()){ 
        it->second->m_keyIDConsumedByKMS.insert( std::make_pair( key->GetId(), key->GetSizeInBits()) );
    }else{
        
        it->second->m_keysConsumedKMSBits += key->GetSizeInBits();   
        it->second->m_keysConsumedKMS++;
 
        if(showKeyServed){
            if(outputFileType == "csv"){
                logFile << (double)Simulator::Now().GetSeconds() << ",-," << linkId << "," << key->GetSizeInBits();
                logFile << std::endl;
            }else if(outputFileType == "json"){
                if(outputLogFile.size() > 0){
                    logFile << ',';
                }
                nlohmann::json jsonRecord;
                jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
                jsonRecord["id"] = linkId;
                jsonRecord["action"] = "kms-";
                jsonRecord["keysize"] = key->GetSizeInBits();     
                outputLogFile.push_back(jsonRecord);
                logFile << jsonRecord.dump();;
                logFile << std::endl;
            }
        }
    }    
}

void
KeyServedKMSEtsi004(
    std::string context, 
    const std::string & ksid, 
    const uint32_t & chunkKeyIndex, 
    const uint32_t & chunkKeySize
){

    std::map<std::string, LinkDetails* >::iterator it = m_connectionPairs.find ( ksid );
    if (it == m_connectionPairs.end ()) NS_FATAL_ERROR ( "No link defined for ksid " << ksid);
    std::string linkId = it->second->linkId;
    
    std::string uniqueId = ksid + '-' +  std::to_string(chunkKeyIndex) + '-' +  std::to_string(chunkKeySize);
    std::map<std::string, uint32_t>::iterator it2 = it->second->m_keyIDConsumedByKMS.find ( uniqueId );

    //we need to monitor key-pair consumption
    //therefore here we store uniqueId of the key when it appears for the first time (primary KMS)
    //when it appears on the slave KMS, we detect consumption of key-pair
    if (it2 == it->second->m_keyIDConsumedByKMS.end ()){ 
        it->second->m_keyIDConsumedByKMS.insert( std::make_pair( uniqueId, chunkKeySize ) );
    }else{
        
        it->second->m_keysConsumedKMSBits += chunkKeySize;   
        it->second->m_keysConsumedKMS++;

        //std::cout << context << "\t" << linkId << "\t" << it->second->m_keysConsumedKMS << "\t" << it->second->m_keysConsumedKMSBits << "\n";

        if(showKeyServed){ 
            if(outputFileType == "csv"){
                logFile << (double)Simulator::Now().GetSeconds() << ",-," << linkId << "," << chunkKeySize;
                logFile << std::endl;
            }else if(outputFileType == "json"){
                if(outputLogFile.size() > 0){
                    logFile << ',';
                }
                nlohmann::json jsonRecord;
                jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
                jsonRecord["id"] = linkId;
                jsonRecord["action"] = "kms-";
                jsonRecord["keysize"] = chunkKeySize;     
                outputLogFile.push_back(jsonRecord);
                logFile << jsonRecord.dump();;
                logFile << std::endl;
            }
        }
    }
} 

void
ProvidedQoSResponse(
    std::string context, 
    const std::string & appConnectionId, 
    const std::string & keyAssociationId, 
    const uint32_t & requestedNumberOfChunkKeys, 
    const uint32_t & supportedNumberOfChunkKeys,
    const uint32_t & providedNumberOfChunkKeys,
    const uint32_t & priorityThreshold,
    const uint32_t & priority
){
    
    std::map<std::string, LinkDetails* >::iterator it = FindByContext(context, appConnectionId);
    std::string linkId = it->second->nodes;

    it->second->m_requestedChunkKeys    += requestedNumberOfChunkKeys;
    it->second->m_availableChunkKeys    += supportedNumberOfChunkKeys;
    it->second->m_providedChunkKeys     += providedNumberOfChunkKeys;
    
} 

void
NewQKDKeyAddedToBuffer(std::string context, Ptr<QKDKey> key)
{
    std::map<std::string, LinkDetails* >::iterator it = FindByContext(context);
    std::string linkId = it->second->nodes;

    std::map<std::string, uint32_t>::iterator it2 = it->second->m_keyIDGeneratedInBuffers.find ( key->GetId() );
    if (it2 == it->second->m_keyIDGeneratedInBuffers.end ()){ 
        it->second->m_keyIDGeneratedInBuffers.insert( std::make_pair( key->GetId(), key->GetSizeInBits()));
    }else{
        it->second->m_keysGeneratedBits += key->GetSizeInBits();  
        it->second->m_keysGenerated++;

        if(showKeyAdded){ 
            if(outputFileType == "csv"){
                logFile << (double)Simulator::Now().GetSeconds() << ",+," << linkId << "," << key->GetSizeInBits();
                logFile << std::endl;
            }else if(outputFileType == "json"){
                if(outputLogFile.size() > 0){ 
                    logFile << ',';
                }
                nlohmann::json jsonRecord;
                jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
                jsonRecord["id"] = linkId;
                jsonRecord["action"] = "+";
                jsonRecord["keysize"] = key->GetSizeInBits();     
                outputLogFile.push_back(jsonRecord);
                logFile << jsonRecord.dump();;
                logFile << std::endl;
            }
        }
    }
}


void
QKDKeyServedFromBuffer(std::string context, Ptr<QKDKey> key)
{
    std::map<std::string, LinkDetails* >::iterator it = FindByContext(context);
    std::string linkId = it->second->nodes;

    std::map<std::string, uint32_t>::iterator it2 = it->second->m_keyIDConsumedInBuffers.find ( key->GetId() );
    if (it2 == it->second->m_keyIDConsumedInBuffers.end ()){ 
        it->second->m_keyIDConsumedInBuffers.insert( std::make_pair( key->GetId(), key->GetSizeInBits()) );
    }else{
        it->second->m_keysConsumedBits += key->GetSizeInBits();   
        it->second->m_keysConsumed++;

        if(showKeyServed){ 
            if(outputFileType == "csv"){
                logFile << (double)Simulator::Now().GetSeconds() << ",-," << linkId << "," << key->GetSizeInBits();
                logFile << std::endl;
            }else if(outputFileType == "json"){
                if(outputLogFile.size() > 0){
                    logFile << ',';
                }
                nlohmann::json jsonRecord;
                jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
                jsonRecord["id"] = linkId;
                jsonRecord["action"] = "-";
                jsonRecord["keysize"] = key->GetSizeInBits();     
                outputLogFile.push_back(jsonRecord);
                logFile << jsonRecord.dump();;
                logFile << std::endl;
            }
        }
    }
}

void
SentPacket(std::string context, Ptr<const Packet> p, std::string ksid)
{   
    std::map<std::string, LinkDetails* >::iterator it = FindByContext(context, ksid);
    std::string linkId = it->second->nodes;

    it->second->m_bytes_sent += p->GetSize();  
    it->second->m_appPacketsSent++;

    if(outputFileType == "csv"){
        logFile << (double)Simulator::Now().GetSeconds() << ",app2app_data," << linkId << "," << p->GetSize();
        logFile << std::endl;
    }else if(outputFileType == "json"){
        if(outputLogFile.size() > 0){
            logFile << ',';
        }
        nlohmann::json jsonRecord;
        jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
        jsonRecord["id"] = linkId;
        jsonRecord["action"] = "app2app_data";
        jsonRecord["keysize"] = p->GetSize();     
        outputLogFile.push_back(jsonRecord);
        logFile << jsonRecord.dump();;
        logFile << std::endl;
    } 
}

void MissedSendPacketCall (std::string context, Ptr<const Packet> p, std::string ksid)
{
    std::map<std::string, LinkDetails* >::iterator it = FindByContext(context, ksid);
    it->second->m_missedSendPacketCalls++;
}

void
ReceivedPacket(std::string context, Ptr<const Packet> p, std::string ksid)
{
    std::map<std::string, LinkDetails* >::iterator it = FindByContext(context, ksid);
    it->second->m_bytes_received += p->GetSize();   
    it->second->m_appPacketsReceived++;
}

void
SentPacketSig(std::string context, Ptr<const Packet> p)
{
    std::map<std::string, LinkDetails* >::iterator it = FindByContext(context);
    it->second->m_sig_bytes_sent += p->GetSize();  
    it->second->m_appSigPacketsSent++;
    std::string linkId = it->second->nodes;
 
    if(outputFileType == "csv"){
        logFile << (double)Simulator::Now().GetSeconds() << ",app2app_sig," << linkId << "," << p->GetSize();
        logFile << std::endl;
    }else if(outputFileType == "json"){
        if(outputLogFile.size() > 0){
            logFile << ',';
        }
        nlohmann::json jsonRecord;
        jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
        jsonRecord["id"] = linkId;
        jsonRecord["action"] = "app2app_sig";
        jsonRecord["keysize"] = p->GetSize();     
        outputLogFile.push_back(jsonRecord);
        logFile << jsonRecord.dump();;
        logFile << std::endl;
    } 
}

void
ReceivedPacketSig(std::string context, Ptr<const Packet> p)
{
    std::map<std::string, LinkDetails* >::iterator it = FindByContext(context);
    it->second->m_sig_bytes_received += p->GetSize();   
    it->second->m_appSigPacketsReceived++;
}

void
SentPacketToKMS(std::string context, Ptr<const Packet> p)
{ 
    std::map<std::string, LinkDetails* >::iterator it = FindByContext(context);
    it->second->m_bytes_sent_to_kms += p->GetSize();
    it->second->m_kmsPacketsSent++; 
    std::string linkId = it->second->nodes;

    if(showKeyAdded){ 
        if(outputFileType == "csv"){
            logFile << (double)Simulator::Now().GetSeconds() << ",app2kms," << linkId << "," << p->GetSize();
            logFile << std::endl;
        }else if(outputFileType == "json"){
            if(outputLogFile.size() > 0){
                logFile << ',';
            }
            nlohmann::json jsonRecord;
            jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
            jsonRecord["id"] = linkId;
            jsonRecord["action"] = "app2kms";
            jsonRecord["keysize"] = p->GetSize();     
            outputLogFile.push_back(jsonRecord);
            logFile << jsonRecord.dump();;
            logFile << std::endl;
        }
    }
}

void
ReceivedPacketFromKMS(std::string context, Ptr<const Packet> p)
{     
    std::map<std::string, LinkDetails* >::iterator it = FindByContext(context);
    it->second->m_bytes_received_from_kms += p->GetSize();   
    it->second->m_kmsPacketsReceived++;
    std::string linkId = it->second->nodes;

    if(showKeyServed){ 
        if(outputFileType == "csv"){
            logFile << (double)Simulator::Now().GetSeconds() << ",kms2app," << linkId << "," << p->GetSize();
            logFile << std::endl;
        }else if(outputFileType == "json"){
            if(outputLogFile.size() > 0){
                logFile << ',';
            }
            nlohmann::json jsonRecord;
            jsonRecord["time"] = (double)Simulator::Now().GetSeconds();
            jsonRecord["id"] = linkId;
            jsonRecord["action"] = "kms2app";
            jsonRecord["keysize"] = p->GetSize();     
            outputLogFile.push_back(jsonRecord);
            logFile << jsonRecord.dump();;
            logFile << std::endl;
        }
    }
}

void 
CreateOutputForCPU(std::string outputStatsName)
{
    std::vector<std::pair<std::string, std::vector<uint32_t> > > output;

    for (std::map<std::string, LinkDetails* >::iterator it = m_connectionPairs.begin(); it != m_connectionPairs.end(); ++it) {

        //if(it->second->m_printed)continue;

        std::vector<uint32_t> temp(50,0);
        temp[0] = it->second->type;
        
        if(it->second->type == 0){
            double avgSizeOfConsumedKeys = 0;
            for (std::map<std::string, uint32_t>::iterator it2 = it->second->m_keyIDConsumedInBuffers.begin(); 
                it2 != it->second->m_keyIDConsumedInBuffers.end(); ++it2) {
                avgSizeOfConsumedKeys += it2->second;
            }
            avgSizeOfConsumedKeys = avgSizeOfConsumedKeys/it->second->m_keyIDConsumedInBuffers.size();
            it->second->m_avgSizeOfConsumedKeys = avgSizeOfConsumedKeys;

            double avgSizeOfGeneratedKeys = 0;
            for (std::map<std::string, uint32_t>::iterator it2 = it->second->m_keyIDGeneratedInBuffers.begin(); 
                it2 != it->second->m_keyIDGeneratedInBuffers.end(); ++it2) {
                avgSizeOfGeneratedKeys += it2->second;
            }
            avgSizeOfGeneratedKeys = avgSizeOfGeneratedKeys/it->second->m_keyIDGeneratedInBuffers.size();
            it->second->m_avgSizeOfGeneratedKeys = avgSizeOfGeneratedKeys;
            
            temp[1] = it->second->m_linkDistance;
            temp[2] = it->second->m_keyRate;
            temp[3] = it->second->m_keysGenerated;
            temp[4] = it->second->m_keysGeneratedBits;
            temp[5] = it->second->m_keysConsumed;
            temp[6] = it->second->m_keysConsumedBits;
            temp[7] = it->second->m_avgSizeOfGeneratedKeys;
            temp[8] = it->second->m_avgSizeOfConsumedKeys;
            temp[9] = it->second->m_bufferCapacityBits;
            temp[23] = it->second->m_startTime;
            temp[24] = it->second->m_stopTime;
        }else{
            double avgSizeOfConsumedKeys = 0;
            for (std::map<std::string, uint32_t>::iterator it2 = it->second->m_keyIDConsumedByKMS.begin(); 
                it2 != it->second->m_keyIDConsumedByKMS.end(); ++it2) {
                avgSizeOfConsumedKeys += it2->second;
            }
            avgSizeOfConsumedKeys = avgSizeOfConsumedKeys/it->second->m_keyIDConsumedByKMS.size();
            it->second->m_keysAvgSizeConsumedKMSBits = avgSizeOfConsumedKeys;
              
            temp[10] = it->second->m_bytes_sent;
            temp[11] = it->second->m_bytes_received;
            temp[12] = it->second->m_appPacketsSent;
            temp[13] = it->second->m_appPacketsReceived;
            temp[14] = it->second->m_missedSendPacketCalls;
            temp[15] = it->second->m_encryptionType;
            temp[16] = it->second->m_authenticationType;
            temp[17] = it->second->m_aesLifeTime;
            temp[18] = it->second->m_packetSize;
            temp[19] = it->second->m_trafficRate;
            temp[20] = it->second->m_sizeOfKeyBufferForEncryption;
            temp[21] = it->second->m_sizeOfKeyBufferForAuthentication;
            temp[22] = it->second->m_numberOfKeysToFetchFromKMS;
            temp[23] = it->second->m_startTime;
            temp[24] = it->second->m_stopTime;
            temp[25] = it->second->m_priority;
            temp[26] = it->second->m_ttl;
            temp[27] = it->second->m_requestedChunkKeys;
            temp[28] = it->second->m_availableChunkKeys;
            temp[29] = it->second->m_providedChunkKeys;
            temp[31] = 0;
            temp[32] = 0;
            temp[33] = 0;
            temp[34] = 0;
            temp[35] = it->second->m_sig_bytes_sent;
            temp[36] = it->second->m_sig_bytes_received;
            temp[37] = it->second->m_appSigPacketsSent;
            temp[38] = it->second->m_appSigPacketsReceived;
            temp[39] = it->second->m_bytes_sent_to_kms;
            temp[40] = it->second->m_bytes_received_from_kms;
            temp[41] = it->second->m_kmsPacketsSent;
            temp[42] = it->second->m_kmsPacketsReceived;
            temp[43] = it->second->m_keysConsumedKMS;
            temp[44] = it->second->m_keysConsumedKMSBits;
            temp[45] = it->second->m_keysAvgSizeConsumedKMSBits;
        } 

        output.push_back( std::make_pair( it->second->linkId, temp) );
        it->second->m_printed = 1;
    }

    write_csv( outputStatsName, output );
}

void
Ratio(std::string outputStatsName, uint32_t cpuCounter){

    // prepare a JSON file
    nlohmann::json output;

    //Initialize JSON file
    for (std::map<std::string, LinkDetails* >::iterator it = m_connectionPairs.begin(); it != m_connectionPairs.end(); ++it) {

        if(it->second->m_printed)continue;
        std::string nodes = it->second->linkId;

        if(it->second->type == 0){
            output["qkd_links"][nodes]["Link distance (meters)"] = 0;
            output["qkd_links"][nodes]["Key rate (bit/sec)"] = 0;
            output["qkd_links"][nodes]["Key-pairs generated"] = 0;
            output["qkd_links"][nodes]["Key-pairs generated (bits)"] = 0;
            output["qkd_links"][nodes]["Key-pairs consumed"] = 0;
            output["qkd_links"][nodes]["Key-pairs consumed (bits)"] = 0;
            output["qkd_links"][nodes]["Average size of generated key-pairs (bits)"] = 0;
            output["qkd_links"][nodes]["Average size of consumed key-pairs (bits)"] = 0;
            output["qkd_links"][nodes]["Start Time (sec)"] = 0;
            output["qkd_links"][nodes]["Stop Time (sec)"] = 0;
            output["qkd_links"][nodes]["QKDBuffer Capacity (bits)"] = 0;
        }else{         
            std::string type = (it->second->type == 1) ? "etsi_004": "etsi_014";
            output[type][nodes]["QKDApps Statistics"]["Link Application ID"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Bytes Sent"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Bytes Received"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Packets Sent"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Packets Received"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Missed send packet calls"] = 0; 
            output[type][nodes]["QKDApps Statistics"]["Key/Data utilization (%)"] = 0; 

            output[type][nodes]["QKDApps Statistics"]["Encryption"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Authentication"] = 0;
            output[type][nodes]["QKDApps Statistics"]["AES Key Lifetime (bytes)"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Size of Key Buffer for Encryption"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Size of Key Buffer for Authentication"] = 0;            
            output[type][nodes]["QKDApps Statistics"]["Number of Keys to Fetch From KMS"] = 0;    
            output[type][nodes]["QKDApps Statistics"]["Packet Size (bytes)"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Traffic Rate (bit/sec)"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Priority"] = 0;
            output[type][nodes]["QKDApps Statistics"]["TTL"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Start Time (sec)"] = 0;
            output[type][nodes]["QKDApps Statistics"]["Stop Time (sec)"] = 0;
 
            output[type][nodes]["Signaling Statistics"]["Bytes Sent"] = 0;
            output[type][nodes]["Signaling Statistics"]["Bytes Received"] = 0;
            output[type][nodes]["Signaling Statistics"]["Packets Sent"] = 0;
            output[type][nodes]["Signaling Statistics"]["Packets Received"] = 0;
  
            output[type][nodes]["QKDApps-KMS Statistics"]["Bytes Sent"] = 0;
            output[type][nodes]["QKDApps-KMS Statistics"]["Bytes Received"] = 0;
            output[type][nodes]["QKDApps-KMS Statistics"]["Packets Sent"] = 0;
            output[type][nodes]["QKDApps-KMS Statistics"]["Packets Received"] = 0;

            output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed"] = 0;
            output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed (bits)"] = 0;
            output[type][nodes]["Key Consumption Statistics"]["Average size of consumed key-pairs (bits)"] = 0;
        }  
    }
    
    //merge values from CPU results
    std::vector<std::vector<std::pair<std::string, std::vector<uint32_t>>>> cpuValues;
    for(uint32_t i = 0; i<cpuCounter; i++){
        std::string tempStatsFile = "temp_stats_" + std::to_string(i);
        std::vector<std::pair<std::string, std::vector<uint32_t>>>  temp = read_csv(tempStatsFile);
        cpuValues.push_back(temp);
        //remove(tempStatsFile.c_str());
    }
 

    //write merged values to JSON file
    //for each cpu value
    for(uint32_t i = 0; i<cpuValues.size(); i++)
    {
        //for each column in cpu value file
        for(uint32_t j=0; j<cpuValues.at(i).size(); j++ )
        {   
            if(i>0){
                //for each value in column
                for(uint32_t k=1; k<cpuValues.at(i).at(j).second.size(); k++ ){
                    if(k<12 || k>34)
                    cpuValues.at(0).at(j).second.at(k) += cpuValues.at(i).at(j).second.at(k);
                }
            }

            if(i+1 == cpuValues.size()){
                std::string type = "qkd_links";
                std::string linkId = cpuValues.at(i).at(j).first;
                std::string nodes = linkId;
                std::string nodesText = "";

                std::map<std::string, LinkDetails* >::iterator it = m_connectionPairs.find ( linkId );
                if (it != m_connectionPairs.end ()){
                    nodesText = it->second->nodes;
                }

                if(cpuValues.at(i).at(j).second.at(0) == 1) {
                    type = "etsi_004";
                }else if(cpuValues.at(i).at(j).second.at(0) == 2){
                    type = "etsi_014";
                }

                std::cout << "********************************** \n\n";

                if(type == "qkd_links"){ 
                    output[type][nodes]["Nodes"]                                    = nodesText;
                    output[type][nodes]["Link distance (meters)"]                   = cpuValues.at(0).at(j).second.at(1);
                    output[type][nodes]["Key rate (bit/sec)"]                       = cpuValues.at(0).at(j).second.at(2);
                    output[type][nodes]["Key-pairs generated"]                      = cpuValues.at(0).at(j).second.at(3);
                    output[type][nodes]["Key-pairs generated (bits)"]               = cpuValues.at(0).at(j).second.at(4);
                    output[type][nodes]["Key-pairs consumed"]                       = cpuValues.at(0).at(j).second.at(5);
                    output[type][nodes]["Key-pairs consumed (bits)"]                = cpuValues.at(0).at(j).second.at(6); 
                    output[type][nodes]["Average size of generated key-pairs (bits)"]    = cpuValues.at(0).at(j).second.at(7); 
                    output[type][nodes]["Average size of consumed key-pairs (bits)"]     = cpuValues.at(0).at(j).second.at(8);
                    output[type][nodes]["QKDBuffer Capacity (bits)"]                = cpuValues.at(0).at(j).second.at(9);
                    output[type][nodes]["Start Time (sec)"]                         = cpuValues.at(0).at(j).second.at(23); 
                    output[type][nodes]["Stop Time (sec)"]                          = cpuValues.at(0).at(j).second.at(24); 

                    std::cout << "QKD key association link entry: " << nodes
                    << "\nNodes: \t" << nodesText
                    << "\nQKDBuffer Capacity (bits):\t" << output[type][nodes]["QKDBuffer Capacity (bits)"]
                    << "\nLink distance (meters):\t\t" << output[type][nodes]["Link distance (meters)"]
                    << "\nKey rate (bit/sec):\t\t" << output[type][nodes]["Key rate (bit/sec)"]
                    << "\nKey-pairs generated:\t" << output[type][nodes]["Key-pairs generated"]
                    << "\tKey-pairs generated (bits):\t" << output[type][nodes]["Key-pairs generated (bits)"]
                    << "\nKey-pairs consumed:\t"  << output[type][nodes]["Key-pairs consumed"]
                    << "\tKey-pairs consumed (bits):\t" << output[type][nodes]["Key-pairs consumed (bits)"] 
                    << "\nAvg size of generated keys (bits):\t" << output[type][nodes]["Average size of generated key-pairs (bits)"]
                    << "\nAvg size of consumed keys (bits):\t" << output[type][nodes]["Average size of consumed key-pairs (bits)"]
                    << "\nStart Time (sec):\t\t" << output[type][nodes]["Start Time (sec)"]
                    << "\nStop Time (sec):\t\t" << output[type][nodes]["Stop Time (sec)"]
                    << "\n\n";

                }else{ 
                    output[type][nodes]["QKDApps Statistics"]["Nodes"]               = nodesText;
                    output[type][nodes]["QKDApps Statistics"]["Bytes Sent"]          = cpuValues.at(0).at(j).second.at(10);
                    output[type][nodes]["QKDApps Statistics"]["Bytes Received"]      = cpuValues.at(0).at(j).second.at(11);
                    output[type][nodes]["QKDApps Statistics"]["Packets Sent"]        = cpuValues.at(0).at(j).second.at(12);
                    output[type][nodes]["QKDApps Statistics"]["Packets Received"]    = cpuValues.at(0).at(j).second.at(13);
                    output[type][nodes]["QKDApps Statistics"]["Missed send packet calls"] = cpuValues.at(0).at(j).second.at(14);

                    double utilization = 0;
                    if(cpuValues.at(0).at(j).second.at(12) && cpuValues.at(0).at(j).second.at(14)){
                        utilization = (double) cpuValues.at(0).at(j).second.at(12) / (double) (
                            cpuValues.at(0).at(j).second.at(12) + cpuValues.at(0).at(j).second.at(14)
                        );
                        utilization *= 100;
                        utilization = std::ceil(utilization * 100.0) / 100.0;
                    }
                    
                    output[type][nodes]["QKDApps Statistics"]["Key/Data utilization (%)"] = utilization;

                    output[type][nodes]["QKDApps Statistics"]["Encryption"]        = cpuValues.at(0).at(j).second.at(15);
                    if(output[type][nodes]["QKDApps Statistics"]["Encryption"] == 0){
                        output[type][nodes]["QKDApps Statistics"]["Encryption"] = "Unencrypted";
                    }else if(output[type][nodes]["QKDApps Statistics"]["Encryption"] == 1){
                        output[type][nodes]["QKDApps Statistics"]["Encryption"] = "OTP";
                    }else if(output[type][nodes]["QKDApps Statistics"]["Encryption"] == 2){
                        output[type][nodes]["QKDApps Statistics"]["Encryption"] = "AES-256";
                        output[type][nodes]["QKDApps Statistics"]["AES Key Lifetime (bytes)"] = cpuValues.at(0).at(j).second.at(17);
                    }

                    output[type][nodes]["QKDApps Statistics"]["Authentication"]    = cpuValues.at(0).at(j).second.at(16);
                    if(output[type][nodes]["QKDApps Statistics"]["Authentication"] == 0){
                        output[type][nodes]["QKDApps Statistics"]["Authentication"] = "Unauthenticated";
                    }else if(output[type][nodes]["QKDApps Statistics"]["Authentication"] == 1){
                        output[type][nodes]["QKDApps Statistics"]["Authentication"] = "VMAC";
                    }else{
                        output[type][nodes]["QKDApps Statistics"]["Authentication"] = "SHA-1";
                    }

                    output[type][nodes]["QKDApps Statistics"]["Packet Size (bytes)"] = cpuValues.at(0).at(j).second.at(18);
                    output[type][nodes]["QKDApps Statistics"]["Traffic Rate (bit/sec)"] = cpuValues.at(0).at(j).second.at(19);

                    if(type == "etsi_004"){
                        output[type][nodes]["QKDApps Statistics"]["Size of Key Buffer for Encryption"] = cpuValues.at(0).at(j).second.at(20);
                        output[type][nodes]["QKDApps Statistics"]["Size of Key Buffer for Authentication"] = cpuValues.at(0).at(j).second.at(21);
                    }else{
                        output[type][nodes]["QKDApps Statistics"]["Number of Keys to Fetch From KMS"] = cpuValues.at(0).at(j).second.at(22);
                    }

                    output[type][nodes]["QKDApps Statistics"]["Start Time (sec)"]     = cpuValues.at(0).at(j).second.at(23);
                    output[type][nodes]["QKDApps Statistics"]["Stop Time (sec)"]      = cpuValues.at(0).at(j).second.at(24);

                    output[type][nodes]["QKDApps Statistics"]["QoS Priority"]               = cpuValues.at(0).at(j).second.at(25);
                    output[type][nodes]["QKDApps Statistics"]["QoS TTL"]                    = cpuValues.at(0).at(j).second.at(26);
                    output[type][nodes]["QKDApps Statistics"]["QoS ChunkSize"]              = cpuValues.at(0).at(j).second.at(18);
                    output[type][nodes]["QKDApps Statistics"]["QoS Requested ChunkKeys"]    = cpuValues.at(0).at(j).second.at(27);
                    output[type][nodes]["QKDApps Statistics"]["QoS Available ChunkKeys"]    = cpuValues.at(0).at(j).second.at(28);
                    output[type][nodes]["QKDApps Statistics"]["QoS Provided ChunkKeys"]     = cpuValues.at(0).at(j).second.at(29);

                    output[type][nodes]["Signaling Statistics"]["Bytes Sent"]         = cpuValues.at(0).at(j).second.at(35);
                    output[type][nodes]["Signaling Statistics"]["Bytes Received"]     = cpuValues.at(0).at(j).second.at(36);
                    output[type][nodes]["Signaling Statistics"]["Packets Sent"]       = cpuValues.at(0).at(j).second.at(37);
                    output[type][nodes]["Signaling Statistics"]["Packets Received"]   = cpuValues.at(0).at(j).second.at(38);
          
                    output[type][nodes]["QKDApps-KMS Statistics"]["Bytes Sent"]       = cpuValues.at(0).at(j).second.at(39);
                    output[type][nodes]["QKDApps-KMS Statistics"]["Bytes Received"]   = cpuValues.at(0).at(j).second.at(40);
                    output[type][nodes]["QKDApps-KMS Statistics"]["Packets Sent"]     = cpuValues.at(0).at(j).second.at(41);
                    output[type][nodes]["QKDApps-KMS Statistics"]["Packets Received"] = cpuValues.at(0).at(j).second.at(42);

                    output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed"] = cpuValues.at(0).at(j).second.at(43);
                    output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed (bits)"]  = cpuValues.at(0).at(j).second.at(44);
                    output[type][nodes]["Key Consumption Statistics"]["Average size of consumed key-pairs (bits)"] = cpuValues.at(0).at(j).second.at(45); 

                    std::cout << "QKD Application Entry  (" << type << "): " << nodes << "\nNodes: \t" << nodesText << "\n";

                    std::cout << "Encryption:\t" << output[type][nodes]["QKDApps Statistics"]["Encryption"];
                    if(output[type][nodes]["QKDApps Statistics"]["Encryption"] == "AES-256"){
                        std::cout << "\nAES Key Lifetime (bytes):\t" << output[type][nodes]["QKDApps Statistics"]["AES Key Lifetime (bytes)"];
                    }
                    std::cout 
                    << "\nAuthentication:\t" << output[type][nodes]["QKDApps Statistics"]["Authentication"]
                    << "\nPacket Size (bytes):\t" << output[type][nodes]["QKDApps Statistics"]["Packet Size (bytes)"]
                    << "\nTraffic Rate (bit/sec):\t" << output[type][nodes]["QKDApps Statistics"]["Traffic Rate (bit/sec)"]
                    << "\nQoS Priority:\t" << output[type][nodes]["QKDApps Statistics"]["QoS Priority"]
                    << "\nQoS TTL:\t" << output[type][nodes]["QKDApps Statistics"]["QoS TTL"]
                    << "\nQoS ChunkSize:\t" << output[type][nodes]["QKDApps Statistics"]["QoS ChunkSize"]
                    << "\nQoS Requested ChunkKeys:\t" << output[type][nodes]["QKDApps Statistics"]["QoS Requested ChunkKeys"]
                    << "\nQoS Available ChunkKeys:\t" << output[type][nodes]["QKDApps Statistics"]["QoS Available ChunkKeys"]
                    << "\nQoS Provided ChunkKeys:\t" << output[type][nodes]["QKDApps Statistics"]["QoS Provided ChunkKeys"];
 
                    if(type == "etsi_004"){
                        std::cout 
                        << "\nSize of Key Buffer for Encryption:\t" << output[type][nodes]["QKDApps Statistics"]["Size of Key Buffer for Encryption"]
                        << "\nSize of Key Buffer for Authentication:\t" << output[type][nodes]["QKDApps Statistics"]["Size of Key Buffer for Authentication"];
                    }else{
                        std::cout 
                        << "\nNumber of Keys to Fetch From KMS:\t" << output[type][nodes]["QKDApps Statistics"]["Number of Keys to Fetch From KMS"];
                    }

                    std::cout
                    << "\nMissed send packet calls:\t" << output[type][nodes]["QKDApps Statistics"]["Missed send packet calls"]
                    << "\nSent (bytes):\t" <<  output[type][nodes]["QKDApps Statistics"]["Bytes Sent"]
                    << "\tReceived (bytes):\t" << output[type][nodes]["QKDApps Statistics"]["Bytes Received"]
                    << "\nSent (Packets):\t" <<  output[type][nodes]["QKDApps Statistics"]["Packets Sent"]
                    << "\tReceived (Packets):\t" << output[type][nodes]["QKDApps Statistics"]["Packets Received"]
                    << "\nKey/Data utilization (%):\t" << output[type][nodes]["QKDApps Statistics"]["Key/Data utilization (%)"]
                    
                    << "\nRatio (bytes):\t" << (float)output[type][nodes]["QKDApps Statistics"]["Bytes Received"]/(float)output[type][nodes]["QKDApps Statistics"]["Bytes Sent"]
                    << "\tRatio (packets):\t" << (float)output[type][nodes]["QKDApps Statistics"]["Packets Received"]/(float)output[type][nodes]["QKDApps Statistics"]["Packets Sent"]
                    << "\nStart Time (sec):\t" << output[type][nodes]["QKDApps Statistics"]["Start Time (sec)"]
                    << "\nStop Time (sec):\t" << output[type][nodes]["QKDApps Statistics"]["Stop Time (sec)"]
                    << "\n"

                    << "\n- Signaling stats:"
                    << "\nSent (bytes):\t" <<  output[type][nodes]["Signaling Statistics"]["Bytes Sent"]
                    << "\tReceived (bytes):\t" << output[type][nodes]["Signaling Statistics"]["Bytes Received"]
                    << "\nSent (Packets):\t" <<  output[type][nodes]["Signaling Statistics"]["Packets Sent"]
                    << "\tReceived (Packets):\t" << output[type][nodes]["Signaling Statistics"]["Packets Received"] 
                    << "\n";

                    std::cout << "\n- QKDApps to KMS stats:"
                    << "\nSent (bytes):\t" <<  output[type][nodes]["QKDApps-KMS Statistics"]["Bytes Sent"]
                    << "\tReceived (bytes):\t" << output[type][nodes]["QKDApps-KMS Statistics"]["Bytes Received"]
                    << "\nSent (Packet):\t" <<  output[type][nodes]["QKDApps-KMS Statistics"]["Packets Sent"]
                    << "\tReceived (Packet):\t" << output[type][nodes]["QKDApps-KMS Statistics"]["Packets Received"] 
                    << "\n";

                    std::cout << "\n- KMS to QKDApp stats:"
                    << "\nKey-pairs consumed:\t" <<  output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed"]
                    << "\nKey-pairs consumed (bits):\t" << output[type][nodes]["Key Consumption Statistics"]["Key-pairs consumed (bits)"] 
                    << "\nAverage size of consumed key-pairs (bits):\t" << output[type][nodes]["Key Consumption Statistics"]["Average size of consumed key-pairs (bits)"] 
                    << "\n\n";
                }
            }
        }
    } 
        
    std::ofstream statFile; 
    statFile.open(outputStatsName, std::ofstream::out | std::ofstream::trunc);
    statFile << output.dump(); 
}

std::string
CalculateAverageDelayBasedOnDistance(uint32_t distanceInMeters){

    //distance in meter
    double distance = distanceInMeters;
    //distance in kilometer
    distance = distance / 1000;
    //apply ITU-T Rec. M.2301 (07/2002) - Table 6 (page 15)
    if(distance < 1000) {
        distance *= 1.5;
    }else if(distance > 1000 && distance < 1200) {
        distance = 1500;
    }else{
        distance *= 1.2;
    }
    uint32_t avgDelay = 1;
    if(distance > 5){
      avgDelay = ceil((double)distance/5.0);
    }
    std::string delayString = std::to_string(avgDelay) + "us";
    return delayString;
}
 
 
int main (int argc, char *argv[])
{
    uint64_t execTime;
    struct timespec tick, tock;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tick);

    // Sequential fallback values
    uint32_t systemId = 0;
    uint32_t systemCount = 1;

    MpiInterface::Enable (&argc, &argv);
    systemId = MpiInterface::GetSystemId ();
    systemCount = MpiInterface::GetSize ();

    Packet::EnablePrinting(); 
    PacketMetadata::Enable ();

    std::cout << "SystemId: " << systemId << std::endl;
    GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::DistributedSimulatorImpl"));

    NS_LOG_INFO ("Create nodes.");
    NodeContainer n;
    double  appHoldTime = 0.5;
    uint16_t simulationTime = 50;
    uint16_t appStartTime = 30;
    uint16_t appStopTime = 155;  
    uint16_t qkdStartTime = 10;
    uint16_t qkdStopTime = 155;  
    uint32_t encryptionType = 1; //0-unencrypted, 1-OTP, 2-AES256
    uint32_t numberOfKeyToFetchFromKMS = 3;
    uint32_t aesLifetime = 300000; //In bytes! 64GB = 68719476736B
    uint32_t keyBufferLengthEncryption = 3;
    uint32_t authenticationType = 1; //0-unauthenticated, 1-VMAC, 2,3-MD5,SHA1
    uint32_t keyBufferLengthAuthentication = 6;
    uint32_t appPacketLimit = 0;
    uint32_t useCrypto = 1;
    double   attackIntensity = 0.1; //Seconds

    uint32_t appRate = 100000; //In bps
    uint32_t appPacketSize =  800; //In bytes
    uint32_t ppKeyRate = 10000; //In bps
    uint32_t ppKeySize = 8192; //In bits
    uint32_t ppPacketSize = 100; //In bytes
    uint32_t ppRate = 1000;
    uint32_t randInt = 0;

    std::string outputFileName ("output.json");
    std::string outputStatsName("stats.json"); 

    bool trace = false; 

    uint32_t numberOfNodes = 0;
    uint32_t numberOfQKDLinks = 1;
    uint32_t numberOfETSI004ApplicationLinks = 1; 
    uint32_t seedValue = 1;
    double startTime = 0;
    double stopTime = 0;

    // Configure command line parameters
    CommandLine cmd;

    cmd.AddValue ("appPacketLimit", "The number of application packets to exchange. Used to limit the communication if needed.", appPacketLimit); 
    cmd.AddValue ("appPacketSize", "The traffic rate of application that consumes keys", appPacketSize); 
    cmd.AddValue ("appRate", "The traffic rate of application that consumes keys", appRate); 
    
    cmd.AddValue ("keyRate", "QKD Key rate", ppKeyRate); 
    cmd.AddValue ("keySize", "The size of generated keys in bits", ppKeySize); 

    cmd.AddValue ("showKeyServed", "Show trace when a key is served from KMS", showKeyServed); 
    cmd.AddValue ("showKeyAdded", "Show trace when a key is generated", showKeyAdded);  

    cmd.AddValue ("ppPacketSize", "QKD Post-processing packet size", ppPacketSize);
    cmd.AddValue ("ppRate", "QKD Post-processing traffic rate", ppRate);

    cmd.AddValue ("simTime", "Simulation time (seconds)", simulationTime); 
    cmd.AddValue ("appStartTime", "Application start time (seconds)", appStartTime); 
    cmd.AddValue ("appStopTime", "Application stop time (seconds)", appStopTime); 
    cmd.AddValue ("qkdStartTime", "QKD start time (seconds)", qkdStartTime); 
    cmd.AddValue ("qkdStopTime", "QKD stop time (seconds)", qkdStopTime); 

    cmd.AddValue ("encryptionType", "Type of encryption to be used", encryptionType); 
    cmd.AddValue ("authenticationType", "Type of authentication to be used", authenticationType);  
    cmd.AddValue ("numberOfKeyToFetchFromKMS", "How may key to fetch from KMS?", numberOfKeyToFetchFromKMS); 
    cmd.AddValue ("aesLifetime", "How many packets to encrypt with the same AES key?", aesLifetime);
    cmd.AddValue ("useCrypto", "Perform crypto functions?", useCrypto);
    cmd.AddValue ("trace", "Enable datapath stats and pcap traces", trace);
    cmd.AddValue ("outputFile", "Name of the output file", outputFileName);
    cmd.AddValue ("outputType", "Type of the output file", outputFileType); 
    cmd.AddValue ("statsFile", "Name of the output json stats file", outputStatsName); 

    cmd.AddValue ("appHoldTime", "How long (seconds) should QKDApp004 wait to close socket to KMS after receiving REST response?", appHoldTime); 
    cmd.AddValue ("keyBufferLengthEncryption", "How many keys to store in local buffer of QKDApp004 for encryption?", keyBufferLengthEncryption);
    cmd.AddValue ("keyBufferLengthAuthentication", "How many keys to store in local buffer of QKDApp004 for authentication?", keyBufferLengthAuthentication);
    cmd.AddValue ("numberOfQKDLinks", "Number of QKD Links", numberOfQKDLinks); 
    cmd.AddValue ("numberOfETSI004ApplicationLinks", "Number of ETSI 004 Application Links", numberOfETSI004ApplicationLinks);  
    cmd.AddValue ("seed", "Random Seed Value", seedValue); 
 
    cmd.AddValue ("attackIntensity", "DoS attackIntensity", attackIntensity);

    cmd.Parse (argc, argv);

    GlobalValue::Bind ("SimulatorImplementationType", StringValue ("ns3::DistributedSimulatorImpl")); 
    uint32_t systemID0 = 0;
    uint32_t systemID1 = 1;
    uint32_t systemID2 = 2;
    uint32_t systemID3 = 3;

    startTime = appStartTime;
    stopTime =appStopTime;

    if(systemCount == 1){
        systemID0 = 0;
        systemID1 = 0;
        systemID2 = 0;
        systemID3 = 0;
    }else if(systemCount == 2){
        systemID0 = 0;
        systemID1 = 1;
        systemID2 = 0;
        systemID3 = 1;
    }else if(systemCount == 4){
        systemID0 = 0;
        systemID1 = 1;
        systemID2 = 2;
        systemID3 = 3;
    }

    logFile.open(outputFileName, std::ofstream::out | std::ofstream::trunc);
    if(outputFileType == "json" && (showKeyAdded || showKeyServed)) logFile << '[';

    ns3::RngSeedManager::SetSeed(100);
    RngSeedManager::SetRun (seedValue); 
    srand( seedValue ); //seeding for the first time only!

    numberOfNodes = (numberOfQKDLinks + numberOfETSI004ApplicationLinks)*2 + 4; //extra 2 for KMSs + 1 Control

    n.Create (numberOfNodes); 

    Ptr<Node> n0 = CreateObject<Node> (systemID0);
    Ptr<Node> n1 = CreateObject<Node> (systemID0);
    Ptr<Node> n2 = CreateObject<Node> (systemID1);
    Ptr<Node> n3 = CreateObject<Node> (systemID1);
    
    for(uint32_t i=0; i<numberOfQKDLinks; i++){
        Ptr<Node> node1 = CreateObject<Node> (systemID0);
        n.Add (node1);
        Ptr<Node> node2 = CreateObject<Node> (systemID1);
        n.Add (node2);
    } 
    for(uint32_t i=0; i<numberOfETSI004ApplicationLinks; i++){
        Ptr<Node> node1 = CreateObject<Node> (systemID2);
        n.Add (node1);
        Ptr<Node> node2 = CreateObject<Node> (systemID3);
        n.Add (node2);
    }  

    if(systemId == systemID0) {
        std::cout << "Number of CPUs:\t" << systemCount << "\n";
        std::cout << "Number of QKD Links:\t" << numberOfQKDLinks << "\n";
        std::cout << "Number of ETSI 004 Application Links:\t" << numberOfETSI004ApplicationLinks << "\n"; 
        std::cout << "Number of Nodes:\t" << numberOfNodes << "\n\n";
    }

    int randomNumber;
    std::vector<int> randomNumbers;
    for(uint32_t i=0; i<numberOfNodes+10; i++){
        randomNumbers.push_back(round(rand()));
    }
    Ptr<UniformRandomVariable> m_random = CreateObject<UniformRandomVariable> (); 
    
    //install QKD Control the node 0
    QKDAppHelper QAHelper; 
    QKDLinkHelper QLinkHelper;  
    Ptr<QKDControl> control = QLinkHelper.InstallQKDControl ( n.Get(0) ); 
    
    InternetStackHelper internet;
    //DsdvHelper routingProtocol;
    //internet.SetRoutingHelper (routingProtocol);
    internet.Install (n);

    // Set Mobility for all nodes  
    MobilityHelper mobility;
    mobility.SetPositionAllocator ("ns3::RandomRectanglePositionAllocator",
                                  "X", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"),
                                  "Y", StringValue ("ns3::UniformRandomVariable[Min=0.0|Max=1000.0]"));
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(n);

    // We create the channels first without any IP addressing information
    NS_LOG_INFO ("Create channels.");
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue ("50Mbps"));
    p2p.SetChannelAttribute ("Delay", StringValue ("2ms")); 

    //QKD Control - KMS
    NodeContainer n0n1 = NodeContainer (n.Get(0), n.Get (1));
    NodeContainer n0n2 = NodeContainer (n.Get(0), n.Get (2));
    NodeContainer n0n3 = NodeContainer (n.Get(0), n.Get (3));
    NetDeviceContainer d0d1 = p2p.Install (n0n1);
    NetDeviceContainer d0d2 = p2p.Install (n0n2); 
    NetDeviceContainer d0d3 = p2p.Install (n0n3);
     
    //
    // We've got the "hardware" in place.  Now we need to add IP addresses.
    // 
    NS_LOG_INFO ("Assign IP Addresses.");
    Ipv4AddressHelper ipv4;
 
    // install KMSs on nodes 1 and 2
    NodeContainer n1n2 = NodeContainer (n.Get(1), n.Get (2));
    NetDeviceContainer d1d2 = p2p.Install (n1n2);    
    ipv4.SetBase ("10.1.0.0", "255.255.255.0");
    Ipv4InterfaceContainer i1i2 = ipv4.Assign (d1d2);
    
    Ptr<QKDKeyManagerSystemApplication> kmsA = QAHelper.InstallKMS(n.Get(1), i1i2.GetAddress(0), 80);
    Ptr<QKDKeyManagerSystemApplication> kmsB = QAHelper.InstallKMS(n.Get(2), i1i2.GetAddress(1), 80);

    if(systemId == systemID0) {
        std::cout << "SrcKMSNode: " << n.Get(1)->GetId() << " Source KMS IP address: " << i1i2.GetAddress(0) << std::endl;
        std::cout << "DstKMSNode: " << n.Get(2)->GetId() << " Destination KMS IP address: " << i1i2.GetAddress(1) << std::endl;
    }

    kmsA->SetStartTime (Seconds (qkdStartTime ));
    kmsA->SetStopTime (Seconds (qkdStopTime));

    kmsB->SetStartTime (Seconds (qkdStartTime ));
    kmsB->SetStopTime (Seconds (qkdStopTime));


    //////////////////////////////////////
    //  QKD LINKS
    //////////////////////////////////////

    if(systemId == systemID0) {
        std::cout << "\n*********\n*** Post-Processing Configuration\n*********\n";
    }

    std::vector<uint32_t> keySizes = {1024, 2048, 4096, 8192}; //, 16384};
    std::vector<uint32_t> keyRates = { 150000}; //, 20000};
    std::vector<uint32_t> ppPacketSizes = {100,150,200,250,300,350};
    std::vector<uint32_t> ppRates = {1000, 1500, 2000, 2500, 3000};    
    std::vector<NodeContainer> qkdLinksNodes;
    uint32_t maxBufferCapacity = 1000000;
    for(uint32_t a=0; a<numberOfQKDLinks;a++)
    {   
        int i=a*2+4;
        int j=i+1;

        std::string ipV4BaseKMSAlice = "10." + std::to_string(i+1) + ".1.0";
        Ipv4Address addressBaseKMSAlice;
        addressBaseKMSAlice.Set(ipV4BaseKMSAlice.c_str());        
        NodeContainer nodesToKMSAlice = NodeContainer (n.Get(i), n.Get (1));
        NetDeviceContainer devicesToKMSAlice = p2p.Install (nodesToKMSAlice);
        ipv4.SetBase (addressBaseKMSAlice, "255.255.255.0");
        Ipv4InterfaceContainer interfacesToKMSAlice = ipv4.Assign (devicesToKMSAlice);

        std::string ipV4BaseKMSBob = "10." + std::to_string(i+1) + ".2.0";
        Ipv4Address addressBaseKMSBob;
        addressBaseKMSBob.Set(ipV4BaseKMSBob.c_str());
        NodeContainer nodesToKMSBob = NodeContainer (n.Get(j), n.Get (2));
        NetDeviceContainer devicesToKMSBob = p2p.Install (nodesToKMSBob);
        ipv4.SetBase (addressBaseKMSBob, "255.255.255.0");
        Ipv4InterfaceContainer interfacesToKMSBob = ipv4.Assign (devicesToKMSBob);

        //  install QKD Buffers on the node 0 and 2
        std::string keyAssociationId = QLinkHelper.CreateQKDLink ( 
            control,
            n.Get(i),
            n.Get(j),
            n.Get(1),       //srcKMS
            n.Get(2),       //dstKMS
            100000,      //min (bits)
            150000,      //thr (bits)
            maxBufferCapacity,      //max (bits)
            0               //current
        );     
        //Create graph to monitor buffer changes
        QLinkHelper.AddGraph(n.Get(i), n.Get(j)); //srcNode, dstNode, BufferTitle
        
        std::string ipV4Base = "10.1." + std::to_string(i+1) + ".0";
        Ipv4Address addressBase;
        addressBase.Set(ipV4Base.c_str());
        NodeContainer nodes = NodeContainer (n.Get(i), n.Get (j));
        qkdLinksNodes.push_back(nodes);
        NetDeviceContainer devices = p2p.Install (nodes);
        ipv4.SetBase (addressBase, "255.255.255.0");
        Ipv4InterfaceContainer interfaces = ipv4.Assign (devices);

        randomNumber = randomNumbers[i];
        if(systemId == systemID0) {
            std::cout << "randomNumber: " << randomNumber << "\n";
        }
        randInt = randomNumber % keySizes.size(); //Key in bytes!!!
        ppKeySize = keySizes[randInt];

        randInt = randomNumber % keyRates.size();
        ppKeyRate = keyRates[randInt];

        randInt = randomNumber % ppPacketSizes.size();
        ppPacketSize = ppPacketSizes[randInt];

        randInt = randomNumber % ppRates.size();
        ppRate = ppRates[randInt];

        LinkDetails* linkD = new LinkDetails;
        linkD->nodes = std::to_string(n.Get(i)->GetId()) + "-" + std::to_string(n.Get(j)->GetId());
        //linkD->nodes = srcNodeId + "-" + dstNodeId;
        linkD->title = "QKD link: " + linkD->nodes; 
        linkD->type = 0; 
        linkD->linkId = keyAssociationId; 
        linkD->m_avgSizeOfGeneratedKeys = 0; 
        linkD->m_avgSizeOfConsumedKeys = 0; 
        linkD->m_keyRate = ppKeyRate;
        linkD->m_linkDistance = 0;
        linkD->m_startTime = startTime;
        linkD->m_stopTime = stopTime;
        linkD->m_bufferCapacityBits = maxBufferCapacity;

        if(systemId == systemID0) {
            std::cout << linkD->title << std::endl;
            std::cout << "SrcNode: " << n.Get(i)->GetId() << " Source IP address: " << interfaces.GetAddress(0) << std::endl;
            std::cout << "DstNode: " << n.Get(j)->GetId() << " Destination IP address: " << interfaces.GetAddress(1) << std::endl;
            std::cout << "SrcKMSNode: " << n.Get(1)->GetId() << " Interface to Alice KMS IP address: " << interfacesToKMSAlice.GetAddress(0) << std::endl;
            std::cout << "DstKMSNode: " << n.Get(2)->GetId() << " Interface to Bob KMS IP address: " << interfacesToKMSBob.GetAddress(0) << std::endl;
            std::cout << "ppKeySize: " << ppKeySize << std::endl; 
            std::cout << "ppKeyRate: " << ppKeyRate << std::endl; 
            std::cout << "ppPacketSize: " << ppPacketSize << std::endl; 
            std::cout << "ppRate: " << ppRate << std::endl; 
        }

        linkD->srcNodeId = n.Get(i)->GetId();
        linkD->dstNodeId = n.Get(j)->GetId();

        m_connectionPairs.insert( std::make_pair( keyAssociationId,  linkD) ); 
        
        //Create APP to generate keys
        ApplicationContainer postprocessingApplications;
        postprocessingApplications.Add( 
            QAHelper.InstallPostProcessing(
                n.Get(i), 
                n.Get(j),
                InetSocketAddress (interfaces.GetAddress(0), 102),
                InetSocketAddress (interfaces.GetAddress(1), 102),
                InetSocketAddress (i1i2.GetAddress(0), 80),  //alice KMS
                InetSocketAddress (i1i2.GetAddress(1), 80),  //bob KMS
                ppKeySize,   //size of key to be added to QKD buffer (bits)
                DataRate (ppKeyRate), //average QKD key rate
                ppPacketSize,    //average data packet size
                DataRate (ppRate) //average data traffic rate
            )
        ); 

        postprocessingApplications.Start (Seconds (qkdStartTime));
        postprocessingApplications.Stop (Seconds (qkdStopTime)); 
        std::cout << "\n";
    }
 
    std::cout << "\n";


    //Set default values for applications created below
    Config::SetDefault ("ns3::QKDApp004::UseCrypto", UintegerValue (useCrypto));
 
    std::vector<uint32_t> keyBufferLengthEncryptionValues = {1,3,5,10,15,20};
    std::vector<uint32_t> keyBufferLengthAuthenticationValues = {6,10,15,20,50}; 

    std::vector<uint32_t> AuthenticationTypes = {1}; //{0,1,2};
    std::vector<uint32_t> EncryptionTypes = {1};// {1,2}; //0,1,2};
    std::vector<uint32_t> AESLifetimes = {10000,20000,100000,200000,300000,400000,500000};

    std::vector<uint32_t> appPacketSizes = {100,300,500,800,1100};
    //std::vector<uint32_t> appRates = {1000,5000,10000,20000,30000}; //, 50000, 100000, 150000}; //, 200000, 250000, 500000};
    //std::vector<uint32_t> appRates = {50000, 100000, 150000, 200000, 250000, 500000};
    std::vector<uint32_t> appRates = {500000};
    std::vector<double> appHoldTimeValues = {0.5, 1, 3, 5}; 
    std::vector<uint32_t> TTLS = {5, 10, 20, 30, 50, 100, 150, 200}; 
    std::vector<uint32_t> priorities = {0,1}; 
    uint32_t priority = 0;
    uint32_t ttl = 0;

    //////////////////////////////////////
    //  QKD APP ETSI 004
    //////////////////////////////////////

    if(numberOfETSI004ApplicationLinks && systemId == systemID0){
        std::cout << "\n*********\n*** ETSI 004 Configuration\n*********\n";
    }

    for(uint32_t a=0; a<numberOfETSI004ApplicationLinks ;a++)
    {   
        int i=(a+numberOfQKDLinks)*2+4;
        int j=i+1;

        randomNumber = randomNumbers[i];
        if(systemId == systemID0) {
            std::cout << "randomNumber: " << randomNumber << "\n";
        }

        randInt = randomNumber % appRates.size();
        appRate = appRates[randInt];

        randInt = randomNumber % appPacketSizes.size();
        appPacketSize = appPacketSizes[randInt];

        randInt = randomNumber % AuthenticationTypes.size();
        authenticationType = AuthenticationTypes[randInt];

        randInt = randomNumber % EncryptionTypes.size();
        encryptionType = EncryptionTypes[randInt];

        randInt = randomNumber % AESLifetimes.size();
        aesLifetime = AESLifetimes[randInt];

        randInt = randomNumber % keyBufferLengthEncryptionValues.size();
        keyBufferLengthEncryption = keyBufferLengthEncryptionValues[randInt];

        randInt = randomNumber % keyBufferLengthAuthenticationValues.size();
        keyBufferLengthAuthentication = keyBufferLengthAuthenticationValues[randInt];

        randInt = randomNumber % appHoldTimeValues.size();
        appHoldTime = appHoldTimeValues[randInt];

        randInt = randomNumber % TTLS.size();
        ttl = TTLS[randInt];

        randInt = randomNumber % priorities.size();
        priority = priorities[randInt];
        priority = 1;

        //Set default values for applications created below 
        Config::SetDefault ("ns3::QKDApp004::LengthOfKeyBufferForEncryption", UintegerValue (keyBufferLengthEncryption));
        Config::SetDefault ("ns3::QKDApp004::LengthOfKeyBufferForAuthentication", UintegerValue (keyBufferLengthAuthentication));
        Config::SetDefault ("ns3::QKDApp004::SocketToKMSHoldTime", TimeValue (Seconds (appHoldTime)));

        Config::SetDefault ("ns3::QKDApp004::AuthenticationType", UintegerValue (authenticationType)); //(0-unauthenticated, 1-VMAC, 2-MD5, 3-SHA1)
        Config::SetDefault ("ns3::QKDApp004::EncryptionType", UintegerValue (encryptionType)); //(0-unencrypted, 1-OTP, 2-AES)
        Config::SetDefault ("ns3::QKDApp004::AESLifetime", UintegerValue (aesLifetime));
           
        std::string ipV4BaseKMSAlice = "10." + std::to_string(i+1) + ".1.0";
        Ipv4Address addressBaseKMSAlice;
        addressBaseKMSAlice.Set(ipV4BaseKMSAlice.c_str());
        NodeContainer nodesToKMSAlice = NodeContainer (n.Get(i), n.Get (1));
        NetDeviceContainer devicesToKMSAlice = p2p.Install (nodesToKMSAlice);
        ipv4.SetBase (addressBaseKMSAlice, "255.255.255.0");
        Ipv4InterfaceContainer interfacesToKMSAlice = ipv4.Assign (devicesToKMSAlice);

        std::string ipV4BaseKMSBob = "10." + std::to_string(i+1) + ".2.0";
        Ipv4Address addressBaseKMSBob;
        addressBaseKMSBob.Set(ipV4BaseKMSBob.c_str());
        NodeContainer nodesToKMSBob = NodeContainer (n.Get(j), n.Get (2));
        NetDeviceContainer devicesToKMSBob = p2p.Install (nodesToKMSBob);
        ipv4.SetBase (addressBaseKMSBob, "255.255.255.0");
        Ipv4InterfaceContainer interfacesToKMSBob = ipv4.Assign (devicesToKMSBob);

        std::string ipV4BaseApp = "10.1." + std::to_string(i+1) + ".0";
        Ipv4Address addressBaseApp;
        addressBaseApp.Set(ipV4BaseApp.c_str());
        NodeContainer nodesToApp = NodeContainer (n.Get(i), n.Get (j));
        NetDeviceContainer devicesToApp = p2p.Install (nodesToApp);
        ipv4.SetBase (addressBaseApp, "255.255.255.0");
        Ipv4InterfaceContainer interfacesToApp = ipv4.Assign (devicesToApp);

        double startTimeTemp = appStartTime + m_random->GetValue (0.5, 5);

        LinkDetails* linkD = new LinkDetails;
        linkD->nodes = std::to_string(n.Get(i)->GetId()) + "-" + std::to_string(n.Get(j)->GetId());
        //linkD->nodes = srcNodeId + "-" + dstNodeId;
        linkD->title = "ETSI 004 Connection: " + linkD->nodes; 
        linkD->type = 1;
        linkD->m_encryptionType = encryptionType;
        linkD->m_authenticationType = authenticationType;
        linkD->m_aesLifeTime = aesLifetime;
        linkD->m_packetSize = appPacketSize;
        linkD->m_trafficRate = appRate;
        linkD->m_sizeOfKeyBufferForEncryption = keyBufferLengthEncryption;
        linkD->m_sizeOfKeyBufferForAuthentication = keyBufferLengthAuthentication;
        linkD->m_priority = priority;
        linkD->m_ttl = ttl;
        linkD->m_startTime = startTimeTemp;
        linkD->m_stopTime = appStopTime;

        if(systemId == systemID0) {
            std::cout << linkD->title << "\n";
            std::cout << "Alice NodeId: " << n.Get(i)->GetId() << " Alice App IP: " << interfacesToApp.GetAddress(0) << std::endl;
            std::cout << "Bob NodeId: " << n.Get(j)->GetId() << " Bob App IP: " << interfacesToApp.GetAddress(1) << std::endl;
            std::cout << "SrcKMSNode: " << n.Get(1)->GetId() << " Interface to Alice KMS IP address: " << interfacesToKMSAlice.GetAddress(0) << std::endl;
            std::cout << "DstKMSNode: " << n.Get(2)->GetId() << " Interface to Bob KMS IP address: " << interfacesToKMSBob.GetAddress(0) << std::endl;
            std::cout << "EncryptionType: " << encryptionType << std::endl;
            std::cout << "AuthenticationType: " << authenticationType << std::endl;
            std::cout << "AESLifetime: " << aesLifetime << std::endl; 
            std::cout << "AppRate: " << appRate << std::endl; 
            std::cout << "AppPacketSize: " << appPacketSize << std::endl; 
            std::cout << "LengthOfKeyBufferForEncryption: " << keyBufferLengthEncryption << std::endl;
            std::cout << "LengthOfKeyBufferForAuthentication: " << keyBufferLengthAuthentication << std::endl;
            std::cout << "AppHoldTime: " << appHoldTime << std::endl;
            std::cout << "QoS priority: " << priority << std::endl;
            std::cout << "QoS ttl: " << ttl << std::endl;
        }

        //Create APP to consume keys
        //ALICE sends user's data
        uint16_t communicationPort = 8081+a;  
        Ptr<QKDApp004> appAlice = CreateObject<QKDApp004> (); 
        appAlice->SetAttribute("LengthOfKeyBufferForEncryption", UintegerValue (keyBufferLengthEncryption));
        appAlice->SetAttribute("LengthOfKeyBufferForAuthentication", UintegerValue (keyBufferLengthAuthentication));
        appAlice->SetAttribute("AuthenticationType", UintegerValue (authenticationType)); //(0-unauthenticated, 1-VMAC, 2-MD5, 3-SHA1)
        appAlice->SetAttribute("EncryptionType", UintegerValue (encryptionType)); //(0-unencrypted, 1-OTP, 2-AES)
        appAlice->SetAttribute("AESLifetime", UintegerValue (aesLifetime));
        appAlice->SetAttribute("Priority", UintegerValue (priority));
        appAlice->SetAttribute("TTL", UintegerValue (ttl));

        Ptr<QKDApp004> appBob = CreateObject<QKDApp004> (); 
        appBob->SetAttribute("LengthOfKeyBufferForEncryption", UintegerValue (keyBufferLengthEncryption));
        appBob->SetAttribute("LengthOfKeyBufferForAuthentication", UintegerValue (keyBufferLengthAuthentication));
        appBob->SetAttribute("AuthenticationType", UintegerValue (authenticationType)); //(0-unauthenticated, 1-VMAC, 2-MD5, 3-SHA1)
        appBob->SetAttribute("EncryptionType", UintegerValue (encryptionType)); //(0-unencrypted, 1-OTP, 2-AES)
        appBob->SetAttribute("AESLifetime", UintegerValue (aesLifetime));
        appBob->SetAttribute("Priority", UintegerValue (priority));
        appBob->SetAttribute("TTL", UintegerValue (ttl));

        appAlice->Setup(
            "tcp", //connection type
            InetSocketAddress (interfacesToApp.GetAddress(0), communicationPort), //from address
            InetSocketAddress (interfacesToApp.GetAddress(1), communicationPort), //to address
            InetSocketAddress (i1i2.GetAddress(0), 80),                //alice KMS
            appBob->GetId(), //alice's location
            appPacketSize, //1000 //payload size   //NOTE: 1000*8 = 8000, key for OTP 8000, and VMAC +128  > 8092
            appPacketLimit, //number of packets (to limit transfer - if needed)
            DataRate (appRate), //packetRate,
            "alice" //connection role
        );
        n.Get (i)->AddApplication (appAlice);
        appAlice->SetStartTime (Seconds (startTimeTemp));
        appAlice->SetStopTime (Seconds (appStopTime));

        //BOB receives user's data
        appBob->Setup(
            "tcp", //connection type
            InetSocketAddress (interfacesToApp.GetAddress(1), communicationPort), //from address
            InetSocketAddress (interfacesToApp.GetAddress(0), communicationPort), //to address 
            InetSocketAddress (i1i2.GetAddress(1), 80),                //bob KMS
            appAlice->GetId(), //alice's location
            appPacketSize, //1000 //payload size   //NOTE: 1000*8 = 8000, key for OTP 8000, and VMAC +128  > 8092
            appPacketLimit, //number of packets (to limit transfer - if needed)
            DataRate (appRate), //packetRate,
            "bob" //connection role
        );
        n.Get (j)->AddApplication (appBob);
        appBob->SetStartTime (Seconds (startTimeTemp));
        appBob->SetStopTime (Seconds (appStopTime)); 

        int randNumber = randomNumber % qkdLinksNodes.size();
        NodeContainer QKDSystemNodes = qkdLinksNodes[randNumber];

        if(systemId == systemID0) {
            std::cout << "Start time: " << startTimeTemp << std::endl;
            std::cout << "Stop time: " << appStopTime << std::endl;
            std::cout << "AliceQKDSystemOnNode:" << QKDSystemNodes.Get(0)->GetId() << "\n";
            std::cout << "BobQKDSystemOnNode:" << QKDSystemNodes.Get(1)->GetId() << "\n";
        }

        std::vector<std::string> connectionIDs = control->RegisterQKDApplications(
            appAlice, 
            appBob,
            kmsA,
            kmsB
        );
 
        NS_LOG_INFO ("Connections:" << connectionIDs.size()); 

        linkD->srcNodeId = appBob->GetNode()->GetId();
        linkD->dstNodeId = appAlice->GetNode()->GetId();
        linkD->linkId = connectionIDs[0];
        m_connectionPairs.insert( std::make_pair( connectionIDs[0],  linkD) );

        if(connectionIDs.size() > 1){
            //authentication

            LinkDetails* linkD2 = new LinkDetails; 
            linkD2->nodes = linkD->nodes;
            linkD2->title = linkD->title;
            linkD2->type = linkD->type; 
            linkD2->m_encryptionType = 0;
            linkD2->m_authenticationType = linkD->m_authenticationType;
            linkD2->m_aesLifeTime = linkD->m_aesLifeTime;
            linkD2->m_packetSize = linkD->m_packetSize;
            linkD2->m_trafficRate = linkD->m_trafficRate;
            linkD2->m_sizeOfKeyBufferForEncryption = linkD->m_sizeOfKeyBufferForEncryption;
            linkD2->m_sizeOfKeyBufferForAuthentication = linkD->m_sizeOfKeyBufferForAuthentication;
            linkD2->m_priority = linkD->m_priority;
            linkD2->m_ttl = linkD->m_ttl;
            linkD2->m_startTime = linkD->m_startTime;
            linkD2->m_stopTime = linkD->m_stopTime;
            linkD2->srcNodeId = linkD->srcNodeId;
            linkD2->dstNodeId = linkD->dstNodeId;

            linkD->m_authenticationType = 0;

            linkD2->linkId = connectionIDs[1];
            m_connectionPairs.insert( std::make_pair( connectionIDs[1],  linkD2) ); 
        }
    }
 

    Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

    if(systemId == systemID0) {
        std::cout << "\n";
    }


    //////////////////////////////////////
    ////         STATISTICS
    //////////////////////////////////////

    if(numberOfETSI004ApplicationLinks){
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/Tx", MakeCallback(&SentPacket));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/Rx", MakeCallback(&ReceivedPacket));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/TxSig", MakeCallback(&SentPacketSig));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/RxSig", MakeCallback(&ReceivedPacketSig));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/TxKMS", MakeCallback(&SentPacketToKMS));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/RxKMS", MakeCallback(&ReceivedPacketFromKMS));
        Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp004/Mx", MakeCallback(&MissedSendPacketCall)); 
    }
 
    Config::Connect("/NodeList/*/$ns3::QKDControl/BufferList/*/$ns3::QKDBuffer/NewKeyAdded", MakeCallback(&NewQKDKeyAddedToBuffer));
    Config::Connect("/NodeList/*/$ns3::QKDControl/BufferList/*/$ns3::QKDBuffer/TransformedKeyAdded", MakeCallback(&NewQKDKeyAddedToBuffer));
    Config::Connect("/NodeList/*/$ns3::QKDControl/BufferList/*/$ns3::QKDBuffer/KeyServed", MakeCallback(&QKDKeyServedFromBuffer)); 
    
    //Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/NewKeyGenerated", MakeCallback(&KeyGeneratedKMS));
    //Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/KeyServed", MakeCallback(&KeyServedKMS));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/KeyServedEtsi014", MakeCallback(&KeyServedKMSEtsi014));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/KeyServedEtsi004", MakeCallback(&KeyServedKMSEtsi004));
    Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDKeyManagerSystemApplication/ProvidedQoSResponse", MakeCallback(&ProvidedQoSResponse));

    if(trace){
        //if we need we can create pcap files
        AsciiTraceHelper ascii;
        p2p.EnableAsciiAll (ascii.CreateFileStream ("qkd_etsi_004.tr"));
        p2p.EnablePcapAll ("qkd_etsi_004");  
        AnimationInterface anim ("qkd_etsi_004.xml");  // where "animation.xml" is any arbitrary filename
    }

 
    Simulator::Stop (Seconds (simulationTime));
    Simulator::Run ();
  
    if(systemId == systemID0) {
        std::cout << "simTime:\t" << simulationTime << "\n"; 
        std::cout << "appStartTime:\t" << appStartTime << "\n"; 
        std::cout << "appStopTime:\t" << appStopTime << "\n"; 
        std::cout << "qkdStartTime:\t" << qkdStartTime << "\n"; 
        std::cout << "qkdStopTime:\t" << qkdStopTime << "\n"; 
        std::cout << "useCrypto:\t" << useCrypto << "\n";
        std::cout << "trace:\t" << trace << "\n";
    }

    //Finally print the graphs
    QLinkHelper.PrintGraphs();

    if(systemId == systemID0){
        if(showKeyAdded || showKeyServed) {
            if(outputFileType == "json") logFile << ']';
        }
    }        

    std::string tempStatsFile = "temp_stats_" + std::to_string(systemId);
    CreateOutputForCPU(tempStatsFile);

    if(systemId == systemID0){
       Ratio(outputStatsName, systemCount);
    }

    Simulator::Destroy ();
    MpiInterface::Disable (); 


    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tock);

    execTime = 1000000000 * (tock.tv_sec - tick.tv_sec) + tock.tv_nsec - tick.tv_nsec;
    printf("elapsed process CPU time = %llu nanoseconds\n", (long long unsigned int) execTime);  
}