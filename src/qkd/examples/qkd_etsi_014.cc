/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2015 LIPTEL.ieee.org
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


// Network topology
//  
//       n0 ---p2p-- n1 --p2p-- n2
//        |<--------qkd-------->|
//              
//        ^                     ^
//        |-----n3(QKDControl)--|
//
// - udp flows from n0 to n2

#include <fstream>
#include "ns3/core-module.h" 
#include "ns3/applications-module.h"
#include "ns3/internet-module.h" 
#include "ns3/flow-monitor-module.h" 
#include "ns3/mobility-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/gnuplot.h" 

#include "ns3/qkd-link-helper.h" 
#include "ns3/qkd-app-helper.h"
#include "ns3/qkd-app.h"

#include "ns3/olsr-module.h"
#include "ns3/dsdv-module.h"
 
#include "ns3/network-module.h"
#include "ns3/fd-net-device-module.h"
#include "ns3/internet-apps-module.h"

#include "ns3/netanim-module.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE ("QKD_CHANNEL_TEST");
   
uint32_t m_bytes_total = 0; 
uint32_t m_bytes_received = 0; 
uint32_t m_bytes_sent = 0; 
uint32_t m_packets_received = 0; 
double m_time = 0;

void
SentPacket(std::string context, Ptr<const Packet> p){

    m_bytes_sent += p->GetSize();  
}

void
ReceivedPacket(std::string context, Ptr<const Packet> p, const Address& addr){
     
    m_bytes_received += p->GetSize(); 
    m_bytes_total += p->GetSize(); 
    m_packets_received++;

}

void
Ratio(uint32_t m_bytes_sent, uint32_t m_packets_sent ){
    std::cout << "Sent (bytes):\t" <<  m_bytes_sent
    << "\tReceived (bytes):\t" << m_bytes_received 
    << "\nSent (Packets):\t" <<  m_packets_sent
    << "\tReceived (Packets):\t" << m_packets_received 
    
    << "\nRatio (bytes):\t" << (float)m_bytes_received/(float)m_bytes_sent
    << "\tRatio (packets):\t" << (float)m_packets_received/(float)m_packets_sent << "\n";
}

 
int main (int argc, char *argv[])
{
    Packet::EnablePrinting(); 
    PacketMetadata::Enable ();
    //
    // Explicitly create the nodes required by the topology (shown above).
    //
    NS_LOG_INFO ("Create nodes.");
    NodeContainer n;
    n.Create (4); 

    NodeContainer n0n1 = NodeContainer (n.Get(0), n.Get (1));
    NodeContainer n1n2 = NodeContainer (n.Get(1), n.Get (2)); 

    //DsdvHelper routingProtocol;
    //OlsrHelper routingProtocol;  
      
    InternetStackHelper internet;
    //internet.SetRoutingHelper (routingProtocol);
    internet.Install (n);

    // Set Mobility for all nodes
    MobilityHelper mobility;
    Ptr<ListPositionAllocator> positionAlloc = CreateObject <ListPositionAllocator>();
    positionAlloc ->Add(Vector(0, 200, 0)); // node0 
    positionAlloc ->Add(Vector(200, 200, 0)); // node1
    positionAlloc ->Add(Vector(400, 200, 0)); // node2 
    mobility.SetPositionAllocator(positionAlloc);
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(n);
       
    // We create the channels first without any IP addressing information
    NS_LOG_INFO ("Create channels.");
    PointToPointHelper p2p;
    p2p.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
    p2p.SetChannelAttribute ("Delay", StringValue ("2ms")); 

    NetDeviceContainer d0d1 = p2p.Install (n0n1); 
    NetDeviceContainer d1d2 = p2p.Install (n1n2);
 
    //
    // We've got the "hardware" in place.  Now we need to add IP addresses.
    // 
    NS_LOG_INFO ("Assign IP Addresses.");
    Ipv4AddressHelper ipv4;

    ipv4.SetBase ("10.1.1.0", "255.255.255.0");
    Ipv4InterfaceContainer i0i1 = ipv4.Assign (d0d1);

    ipv4.SetBase ("10.1.2.0", "255.255.255.0");
    Ipv4InterfaceContainer i1i2 = ipv4.Assign (d1d2);
    
    //  install LKMS on nodes 0 and 2
    QKDAppHelper QAHelper; 
    QKDLinkHelper QLinkHelper;  
    
    ApplicationContainer lkmsApplications;
    lkmsApplications.Add( QAHelper.InstallKMS(n.Get(0)) );
    lkmsApplications.Add( QAHelper.InstallKMS(n.Get(2)) );

    //  install QKD Control the node 3
    Ptr<QKDControl> control = QLinkHelper.InstallQKDControl ( n.Get(3) ); 
    //  install QKD Buffers on the node 0 and 2
    QLinkHelper.CreateQKDLink ( 
        control,
        n.Get(0),
        n.Get(2),
        1000000,        //min
        1500000,       //thr
        5000000,       //ma
        0        //current
    );     
    //Create graph to monitor buffer changes
    QLinkHelper.AddGraph(control, n.Get(0), n.Get(2)); //srcNode, destinationAddress, BufferTitle
    QLinkHelper.AddGraph(control, n.Get(2), n.Get(0)); //srcNode, destinationAddress, BufferTitle
    
    NS_LOG_INFO ("Create Applications.");

    //Create APP to generate keys
    ApplicationContainer postprocessingApplications;
    postprocessingApplications.Add( 
        QAHelper.InstallPostProcessing(
            n.Get(0), 
            n.Get(2),
            InetSocketAddress (i0i1.GetAddress(0), 102),
            InetSocketAddress (i1i2.GetAddress(1), 102),
            8092,   //size of key to be added to QKD buffer
            DataRate ("100kbps"), //average QKD key rate
            100,    //average data packet size
            DataRate ("1Mbps") //average data traffic rate
        )
    ); 

    postprocessingApplications.Start (Seconds (5.)); //500
    postprocessingApplications.Stop (Seconds (19.)); 

    //Create APP to consume keys
    //ALICE sends user's data
    uint16_t communicationPort = 8081;  
    Ptr<QKDApp> appAlice = CreateObject<QKDApp> (); 
    appAlice->Setup(
        "tcp", //connection type
        InetSocketAddress (i0i1.GetAddress(0), communicationPort), //from address
        InetSocketAddress (i1i2.GetAddress(1), communicationPort), //to address
        n.Get(2),//bob's location
        800, //1000 //payload size   //NOTE: 1000*8 = 8000, key for OTP 8000, and VMAC +128  > 8092
        50, //number of packets (to limit transfer - if needed)
        DataRate ("100Mbps"), //packetRate,
        "alice" //connection role
    );
    n.Get (0)->AddApplication (appAlice);
    appAlice->SetStartTime (Seconds (20.));
    appAlice->SetStopTime (Seconds (300.));

    appAlice->SetAttribute("NumberOfKeyToFetchFromKMS", UintegerValue (3)); //Number of keys to obtain per request!

    //schedule some actions in advance (GetStatusFromKMS, GetKeysFromKMS or ExchangeInfoMessages)
    //uint32_t eventId1 = appAlice->ScheduleAction(Seconds(25.), "GetStatusFromKMS");
    //NS_LOG_INFO(eventId1); //just log the eventId 
    //appAlice->CancelScheduledAction(eventId1);
 
    //uint32_t eventId2 = appAlice->ScheduleAction(Seconds(27.), "ExchangeInfoMessages");
    //NS_LOG_INFO(eventId2); //just log the eventId 
    //appAlice->CancelScheduledAction(eventId2);

    
    //uint32_t eventId3 = appAlice->ScheduleAction(Seconds(30.), "GetKeysFromKMS");
    //NS_LOG_INFO(eventId3); //just log the eventId 
    //appAlice->CancelScheduledAction(eventId3);


    //BOB receives user's data
    Ptr<QKDApp> appBob = CreateObject<QKDApp> (); 
    appBob->Setup(
        "tcp", //connection type
        InetSocketAddress (i1i2.GetAddress(1), communicationPort), //from address
        InetSocketAddress (i0i1.GetAddress(0), communicationPort), //to address
        n.Get(0),//alice's location
        "bob" //connection role
    );
    n.Get (2)->AddApplication (appBob);
    appBob->SetStartTime (Seconds (18.)); //150
    appBob->SetStopTime (Seconds (300.));
    
    // DEFINE SIMULATION TIME
    lkmsApplications.Start (Seconds (20.));
    lkmsApplications.Stop (Seconds (300.));
 
    std::cout << "\t SrcNode: " << n.Get(0)->GetId() << " Source IP address: " << i0i1.GetAddress(0) << std::endl;
    std::cout << "\t DstNode: " << n.Get(2)->GetId() << " Destination IP address: " << i1i2.GetAddress(1) << std::endl;
 
    Ipv4GlobalRoutingHelper::PopulateRoutingTables ();

    //////////////////////////////////////
    ////         STATISTICS
    //////////////////////////////////////

    //if we need we can create pcap files
    AsciiTraceHelper ascii;
    p2p.EnableAsciiAll (ascii.CreateFileStream ("qkd_channel_test.tr"));
    p2p.EnablePcapAll ("qkd_channel_test");  
    AnimationInterface anim ("qkd_channel_test.xml");  // where "animation.xml" is any arbitrary filename

    //Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp/Tx", MakeCallback(&SentPacket));
    //Config::Connect("/NodeList/*/ApplicationList/*/$ns3::QKDApp/Rx", MakeCallback(&ReceivedPacket));
 
    Simulator::Stop (Seconds (31));
    Simulator::Run ();

    //Ratio(app->sendDataStats(), app->sendPacketStats());
 
    //Finally print the graphs
    QLinkHelper.PrintGraphs();
    Simulator::Destroy ();
}