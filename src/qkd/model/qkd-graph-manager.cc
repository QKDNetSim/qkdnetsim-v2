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
 *
 * QKDGraphManager is a singleton class!
 */

#include "ns3/qkd-graph-manager.h" 
 
namespace ns3 {
 
NS_LOG_COMPONENT_DEFINE ("QKDGraphManager");

NS_OBJECT_ENSURE_REGISTERED (QKDGraphManager);

TypeId QKDGraphManager::GetTypeId (void) 
{
  static TypeId tid = TypeId ("ns3::QKDGraphManager")
    .SetParent<Object> () 
    ; 
  return tid;
}

bool QKDGraphManager::instanceFlag = false;
Ptr<QKDTotalGraph> QKDGraphManager::m_totalGraph = 0;
QKDGraphManager* QKDGraphManager::single = NULL;
QKDGraphManager* QKDGraphManager::getInstance()
{
    if(!instanceFlag){
		m_totalGraph = CreateObject<QKDTotalGraph> ("QKD\_Total\_Graph", "png");
		single = new QKDGraphManager();
		instanceFlag = true;
    }
    return single;
}

QKDGraphManager::~QKDGraphManager(){
	instanceFlag = false;
	delete single;

}

Ptr<QKDTotalGraph> 
QKDGraphManager::GetTotalGraph(){
	return m_totalGraph;
}

void
QKDGraphManager::PrintGraphs(){ 

    NS_LOG_FUNCTION (this);
	m_totalGraph->PrintGraph();
	for (std::vector<std::vector<QKDGraph *> >::iterator i = m_graphs.begin();i != m_graphs.end(); ++i)
	{   
		for (std::vector<QKDGraph *>::iterator j = i->begin(); j != i->end(); ++j)
        { 
            if((*j)!=0)
            {
		        (*j)->PrintGraph();
		        delete *j;
            }
        }
	}  
}
 
 
void
QKDGraphManager::SendCurrentChangeValueToGraph(const uint32_t& nodeID,const uint32_t& bufferPosition,const uint32_t& value){

    NS_LOG_FUNCTION (this << nodeID << bufferPosition << value);
	m_graphs[nodeID][bufferPosition]->ProcessMCurrent(value);
}

void
QKDGraphManager::SendStatusValueToGraph(const uint32_t& nodeID, const uint32_t& bufferPosition,const uint32_t& value){

    NS_LOG_FUNCTION (this << nodeID << bufferPosition << value);
	m_graphs[nodeID][bufferPosition]->ProcessMStatus(value);
}

void
QKDGraphManager::SendThresholdValueToGraph(const uint32_t& nodeID, const uint32_t& bufferPosition, const uint32_t& value){

    NS_LOG_FUNCTION (this << nodeID << bufferPosition << value);
	m_graphs[nodeID][bufferPosition]->ProcessMThrStatus(value);
}

void 
QKDGraphManager::ProcessCurrentChange(std::string context, uint32_t value)
{ 
	//std::cout << Simulator::Now() << "\t" << context << value << "\t\n" ;
	int nodeId=0; 
	int bufferPosition=0;
	std::sscanf(context.c_str(), "/NodeList/%d/$ns3::QKDControl/BufferList/%d/*", &nodeId, &bufferPosition);
 
	QKDGraphManager::single->SendCurrentChangeValueToGraph (nodeId, bufferPosition, value);  
}

void 
QKDGraphManager::ProcessStatusChange(std::string context, uint32_t value)
{
	//NodeList/0/$ns3::QKDControl/BufferList/0/CurrentChange
	int nodeId=0;
	int bufferPosition=0;
	std::sscanf(context.c_str(), "/NodeList/%d/$ns3::QKDControl/BufferList/%d/*", &nodeId, &bufferPosition);

	QKDGraphManager::single->SendStatusValueToGraph (nodeId, bufferPosition, value);  
}

void 
QKDGraphManager::ProcessThresholdChange(std::string context, uint32_t value)
{
	//NodeList/0/$ns3::QKDControl/BufferList/0/ThresholdChange
	int nodeId=0; 
	int bufferPosition=0;
	std::sscanf(context.c_str(), "/NodeList/%d/$ns3::QKDControl/BufferList/%d/*", &nodeId, &bufferPosition);
 
	QKDGraphManager::single->SendThresholdValueToGraph (nodeId, bufferPosition, value);  
}


// FOR QKD TOTAL GRAPH 
void 
QKDGraphManager::ProcessCurrentIncrease(std::string context, uint32_t value)
{
 	m_totalGraph->ProcessMCurrent(value, '+');
}

// FOR QKD TOTAL GRAPH 
void 
QKDGraphManager::ProcessCurrentDecrease(std::string context, uint32_t value)
{ 
	m_totalGraph->ProcessMCurrent(value, '-');
}

// FOR QKD TOTAL GRAPH 
void 
QKDGraphManager::ProcessThresholdIncrease(std::string context, uint32_t value)
{
	m_totalGraph->ProcessMThr(value, '+');
}

// FOR QKD TOTAL GRAPH 
void 
QKDGraphManager::ProcessThresholdDecrease(std::string context, uint32_t value)
{ 
	m_totalGraph->ProcessMThr(value, '-');
}
 
void 
QKDGraphManager::AddQKDBuffer (
	Ptr<QKDControl> c, 
	Ptr<Node> src, 
	Ptr<Node> dst, 
	uint32_t bufferPosition, 
	std::string graphName, 
	std::string graphType
) { 	    
    NS_LOG_FUNCTION (this << src->GetId() << bufferPosition << graphName);
	  
  	uint32_t nodeID = c->GetNode()->GetId();
  	uint32_t nodeMax = nodeID;
  	if(nodeMax < src->GetId()){
  		nodeMax = src->GetId();
  	}
  	if(nodeMax < dst->GetId()){
  		nodeMax = dst->GetId();
  	}

	if(m_graphs.size() <= nodeMax){
		m_graphs.resize( nodeMax + 1 );
	}
	
	if(m_graphs.size() == 0){
		m_graphs[nodeID] = std::vector<QKDGraph *> ();
	}

	if(m_graphs[nodeID].size() <= bufferPosition){
		m_graphs[nodeID].resize(bufferPosition+1);
	}

	//only svg,png and tex graph file are allowd for now
	std::string graphTypeFilter = (graphType=="svg" || graphType=="png" || graphType=="tex") ? graphType : "png";	
	m_graphs[nodeID][bufferPosition] = new QKDGraph (c, src, dst, bufferPosition, graphName, graphTypeFilter);

	std::ostringstream currentPath;
	currentPath << "/NodeList/" << nodeID << "/$ns3::QKDControl/BufferList/" << bufferPosition << "/CurrentChange"; 
 	
	std::string query(currentPath.str());
    Config::Connect(query, MakeCallback (&QKDGraphManager::ProcessCurrentChange));
    NS_LOG_FUNCTION (this << query);

	std::ostringstream statusPath; 
	statusPath << "/NodeList/" << nodeID << "/$ns3::QKDControl/BufferList/" << bufferPosition << "/StatusChange";
	std::string query2(statusPath.str());
    Config::Connect(query2, MakeCallback (&QKDGraphManager::ProcessStatusChange)); 
    NS_LOG_FUNCTION (this << query2);

	std::ostringstream MthrPath; 
	MthrPath << "/NodeList/" << nodeID << "/$ns3::QKDControl/BufferList/" << bufferPosition << "/ThresholdChange";
	std::string query3 (MthrPath.str());
    Config::Connect (query3, MakeCallback (&QKDGraphManager::ProcessThresholdChange)); 
    NS_LOG_FUNCTION (this << query3);

    //FOR QKD TOTAL GRAPH

	std::ostringstream currentPathIncrease;
	currentPathIncrease << "/NodeList/" << nodeID << "/$ns3::QKDControl/BufferList/" << bufferPosition << "/CurrentIncrease"; 
	std::string query4(currentPathIncrease.str());
    Config::Connect(query4, MakeCallback (&QKDGraphManager::ProcessCurrentIncrease));
    NS_LOG_FUNCTION (this << query4);

	std::ostringstream currentPathDecrease;
	currentPathDecrease << "/NodeList/" << nodeID << "/$ns3::QKDControl/BufferList/" << bufferPosition << "/CurrentDecrease"; 
	std::string query5(currentPathDecrease.str());
    Config::Connect(query5, MakeCallback (&QKDGraphManager::ProcessCurrentDecrease));
    NS_LOG_FUNCTION (this << query5);

	std::ostringstream currentPathMthrIncrease;
	currentPathMthrIncrease << "/NodeList/" << nodeID << "/$ns3::QKDControl/BufferList/" << bufferPosition << "/ThresholdIncrease"; 
	std::string query6(currentPathMthrIncrease.str());
    Config::Connect(query6, MakeCallback (&QKDGraphManager::ProcessThresholdIncrease));
    NS_LOG_FUNCTION (this << query6);

	std::ostringstream currentPathMthrDecrease;
	currentPathMthrDecrease << "/NodeList/" << nodeID << "/$ns3::QKDControl/BufferList/" << bufferPosition << "/ThresholdDecrease"; 
	std::string query7(currentPathMthrDecrease.str());
    Config::Connect(query7, MakeCallback (&QKDGraphManager::ProcessThresholdDecrease));
    NS_LOG_FUNCTION (this << query7);

    m_graphs[nodeID][bufferPosition]->InitTotalGraph();
}
}

