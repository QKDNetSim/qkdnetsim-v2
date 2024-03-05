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

#include "ns3/core-module.h"  
#include "ns3/inet-socket-address.h"
#include "ns3/packet-socket-address.h"
#include "ns3/socket.h"
#include "ns3/string.h"
#include "ns3/names.h" 
#include "ns3/uinteger.h" 
#include "ns3/qkd-app-helper.h" 
#include "ns3/qkd-key-manager-system-application.h"
#include "ns3/qkd-sdn-controller.h"
#include "ns3/qkd-connection-register.h"

namespace ns3 {

uint32_t QKDAppHelper::appCounter = 0;

QKDAppHelper::QKDAppHelper ()
{
    m_factory_qkd_app.SetTypeId ("ns3::QKDApp014"); 

    Address sinkAddress (InetSocketAddress (Ipv4Address::GetAny (), 80));
    m_factory_kms_app.SetTypeId ("ns3::QKDKeyManagerSystemApplication");
    m_factory_lr_app.SetTypeId ("ns3::QKDConnectionRegister"); 
    m_factory_postprocessing_app.SetTypeId ("ns3::QKDPostprocessingApplication"); 
    m_factory_sdn_app.SetTypeId ("ns3::QKDSDNController");
}

QKDAppHelper::QKDAppHelper (std::string protocol, Ipv4Address master, Ipv4Address slave, uint32_t keyRate)
{
    SetSettings(protocol, master, slave, keyRate);
}
 
void 
QKDAppHelper::SetSettings ( std::string protocol, Ipv4Address master, Ipv4Address slave, uint32_t keyRate)
{
    uint16_t port;

    /*************************
    //      MASTER
    **************************/
    port = 80; 
    Address sinkAddress (InetSocketAddress (Ipv4Address::GetAny (), port));
    Address masterAppRemoteAddress (InetSocketAddress (master, port));
    Address slaveAppRemoteAddress (InetSocketAddress (slave, port));
    m_factory_kms_app.SetTypeId ("ns3::QKDKeyManagerSystemApplication");
     
    m_protocol = protocol;

}


void
QKDAppHelper::SetAttribute ( std::string mFactoryName, std::string name, const AttributeValue &value)
{ 
    if(mFactoryName == "kms") {
        m_factory_kms_app.Set (name, value); 
    } else if(mFactoryName == "postprocessing") {
        m_factory_postprocessing_app.Set (name, value);  
    } else if(mFactoryName == "app") {
        m_factory_qkd_app.Set (name, value);  
    }
}

ApplicationContainer
QKDAppHelper::InstallQKDApp (Ptr<Node> node) const
{   
    ApplicationContainer apps;
    Ptr<Application> app = m_factory_qkd_app.Create<Application> (); 
    node->AddApplication (app);
    apps.Add(app);
    return apps;
}

Ptr<QKDKeyManagerSystemApplication>
QKDAppHelper::InstallKMS (Ptr<Node> node, Ipv4Address kmsAddress) const
{ 
    return InstallKMS(node, kmsAddress, 80);
}

Ptr<QKDKeyManagerSystemApplication>
QKDAppHelper::InstallKMS (Ptr<Node> node, Ipv4Address kmsAddress, uint32_t port) const
{    
    Ptr<Application> appKMS = m_factory_kms_app.Create <Application> (); 
    node->AddApplication (appKMS);

    Ptr<QKDKeyManagerSystemApplication> kms = appKMS->GetObject<QKDKeyManagerSystemApplication> ();
    kms->SetNode(node);
    kms->SetAddress(kmsAddress);
    kms->SetPort(port);

    Ptr<QKDConnectionRegister> lr = node->GetObject<QKDConnectionRegister> ();
    if(!lr) 
    {
        Ptr<Object> lra = m_factory_lr_app.Create <Object> (); 
        node->AggregateObject (lra);  
    }
    return kms;
}

void
QKDAppHelper::InstallSDN (Ptr<Node> node, Ipv4Address sdnAddress) const
{ 
    InstallSDN(node, sdnAddress, 3060);
}
void
QKDAppHelper::InstallSDN (Ptr<Node> node, Ipv4Address sdnAddress, uint32_t port) const
{    
    Ptr<Application> appSDN = m_factory_sdn_app.Create <Application> (); 
    node->AddApplication (appSDN);

    Ptr<QKDSDNController> sdn = appSDN->GetObject<QKDSDNController> ();
    sdn->SetNode(node);
    sdn->SetAddress(sdnAddress);
    sdn->SetPort(port);
    
    Ptr<QKDConnectionRegister> lr = node->GetObject<QKDConnectionRegister> ();
    if(!lr) 
    {
        Ptr<Object> lra = m_factory_lr_app.Create <Object> (); 
        node->AggregateObject (lra);  
    }
}

void
QKDAppHelper::ConnectKMSToSDN(Ptr<Node> kmsNode, Ipv4Address sdnAddress, uint32_t port){

    Ptr<QKDKeyManagerSystemApplication> kms = kmsNode->GetObject<QKDKeyManagerSystemApplication> ();
    //if(kms != 0) 
        //kms->ConnectToSDNController(sdnAddress, port);
}



ApplicationContainer
QKDAppHelper::InstallPostProcessing (
    Ptr<Node>   node1, 
    Ptr<Node>   node2,
    Address     masterAddress, 
    Address     slaveAddress, 
    Address     masterKMSAddress, 
    Address     slaveKMSAddress, 
    uint32_t    keySizeInBits, 
    DataRate    keyRate,
    uint32_t    packetSize,
    DataRate    dataRate
)
{ 
    /**
    *   UDP Protocol is used for sifting (implementation detail)
    */ 
    TypeId m_tid    = TypeId::LookupByName ("ns3::TcpSocketFactory"); 
    TypeId udp_tid  = TypeId::LookupByName ("ns3::UdpSocketFactory");
 
    /**************
    //MASTER
    ***************/
    m_factory_postprocessing_app.Set ("Local", AddressValue (masterAddress)); 
    m_factory_postprocessing_app.Set ("Local_Sifting", AddressValue (masterAddress)); 
    m_factory_postprocessing_app.Set ("Local_KMS", AddressValue (masterKMSAddress));
    m_factory_postprocessing_app.Set ("Remote", AddressValue (slaveAddress));
    m_factory_postprocessing_app.Set ("Remote_Sifting", AddressValue (slaveAddress));    
    m_factory_postprocessing_app.Set ("KeySizeInBits", UintegerValue (keySizeInBits));    
    m_factory_postprocessing_app.Set ("KeyRate", DataRateValue (keyRate)); 
    m_factory_postprocessing_app.Set ("PacketSize", UintegerValue (packetSize)); 
    m_factory_postprocessing_app.Set ("DataRate", DataRateValue (dataRate));

    Ptr<Application> appMaster = m_factory_postprocessing_app.Create<Application> ();
    appMaster->SetAttribute ("Local", AddressValue (masterAddress)); 
    appMaster->SetAttribute ("Local_Sifting", AddressValue (masterAddress)); 
    appMaster->SetAttribute ("Local_KMS", AddressValue (masterKMSAddress));
    appMaster->SetAttribute ("Remote", AddressValue (slaveAddress));
    appMaster->SetAttribute ("Remote_Sifting", AddressValue (slaveAddress));        
    appMaster->SetAttribute ("KeySizeInBits", UintegerValue (keySizeInBits));    
    appMaster->SetAttribute ("KeyRate", DataRateValue (keyRate)); 
    appMaster->SetAttribute ("PacketSize", UintegerValue (packetSize)); 
    appMaster->SetAttribute ("DataRate", DataRateValue (dataRate));
 

    node1->AddApplication (appMaster);

    DynamicCast<QKDPostprocessingApplication> (appMaster)->SetSrc (node1);
    DynamicCast<QKDPostprocessingApplication> (appMaster)->SetDst (node2);

    //POST-processing sockets
    Ptr<Socket> sckt1 = Socket::CreateSocket (node1, m_tid);
    Ptr<Socket> sckt2 = Socket::CreateSocket (node1, m_tid);
    DynamicCast<QKDPostprocessingApplication> (appMaster)->SetSocket ("send", sckt1, true);
    DynamicCast<QKDPostprocessingApplication> (appMaster)->SetSocket ("sink", sckt2, true);
    //SIFTING
    Ptr<Socket> sckt1_sifting = Socket::CreateSocket (node1, udp_tid);
    Ptr<Socket> sckt2_sifting = Socket::CreateSocket (node1, udp_tid);   
    DynamicCast<QKDPostprocessingApplication> (appMaster)->SetSiftingSocket ("send", sckt1_sifting);
    DynamicCast<QKDPostprocessingApplication> (appMaster)->SetSiftingSocket ("sink", sckt2_sifting);

    /**************
    //SLAVE
    ***************/
    m_factory_postprocessing_app.Set ("Local", AddressValue (slaveAddress)); 
    m_factory_postprocessing_app.Set ("Local_Sifting", AddressValue (slaveAddress));
    m_factory_postprocessing_app.Set ("Local_KMS", AddressValue (slaveKMSAddress));
    m_factory_postprocessing_app.Set ("Remote", AddressValue (masterAddress));
    m_factory_postprocessing_app.Set ("Remote_Sifting", AddressValue (masterAddress));     
    m_factory_postprocessing_app.Set ("KeySizeInBits", UintegerValue (keySizeInBits));    
    m_factory_postprocessing_app.Set ("KeyRate", DataRateValue (keyRate)); 
    m_factory_postprocessing_app.Set ("PacketSize", UintegerValue (packetSize)); 
    m_factory_postprocessing_app.Set ("DataRate", DataRateValue (dataRate));

    Ptr<Application> appSlave = m_factory_postprocessing_app.Create<Application> (); 
    appSlave->SetAttribute("Local", AddressValue (slaveAddress)); 
    appSlave->SetAttribute("Local_Sifting", AddressValue (slaveAddress));
    appSlave->SetAttribute("Local_KMS", AddressValue (slaveKMSAddress));
    appSlave->SetAttribute("Remote", AddressValue (masterAddress));
    appSlave->SetAttribute("Remote_Sifting", AddressValue (masterAddress));        
    appSlave->SetAttribute("KeySizeInBits", UintegerValue (keySizeInBits));    
    appSlave->SetAttribute("KeyRate", DataRateValue (keyRate)); 
    appSlave->SetAttribute("PacketSize", UintegerValue (packetSize)); 
    appSlave->SetAttribute("DataRate", DataRateValue (dataRate));
    node2->AddApplication (appSlave);

    DynamicCast<QKDPostprocessingApplication> (appSlave)->SetSrc (node2);
    DynamicCast<QKDPostprocessingApplication> (appSlave)->SetDst (node1);

    //POST-processing sockets
    Ptr<Socket> sckt3 = Socket::CreateSocket (node2, m_tid);
    Ptr<Socket> sckt4 = Socket::CreateSocket (node2, m_tid);
    DynamicCast<QKDPostprocessingApplication> (appSlave)->SetSocket ("send", sckt3, false);
    DynamicCast<QKDPostprocessingApplication> (appSlave)->SetSocket ("sink", sckt4, false);
    //SIFTING
    Ptr<Socket> sckt3_sifting = Socket::CreateSocket (node2, udp_tid);
    Ptr<Socket> sckt4_sifting = Socket::CreateSocket (node2, udp_tid);   
    DynamicCast<QKDPostprocessingApplication> (appSlave)->SetSiftingSocket ("send", sckt3_sifting);
    DynamicCast<QKDPostprocessingApplication> (appSlave)->SetSiftingSocket ("sink", sckt4_sifting);
  
    ApplicationContainer apps;
    apps.Add(appMaster);
    apps.Add(appSlave); 
    
    return apps;
}

} // namespace ns3

