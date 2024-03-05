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

#ifndef QKD_GRAPH_MANAGER_H
#define QKD_GRAPH_MANAGER_H

#include <fstream>
#include <sstream>
#include <vector>
#include "ns3/object.h"
#include "ns3/gnuplot.h"
#include "ns3/core-module.h"
#include "ns3/node-list.h" 
#include "qkd-graph.h" 
#include "qkd-control.h" 
#include "qkd-total-graph.h" 

namespace ns3 {
 
/**
 * \ingroup qkd
 * \class QKDGraphManager
 * \brief QKDGraphManager. 
 *
 *  \brief QKDGraphManager is a signleton class used to connect QKDGraphs and 
 *  QKDTotalGraph. It uses TraceSources to make connection and make printing 
 *  of graphs easier, all graphs are printed using a single function "PrintGraphs".
 */

class QKDGraph;

class QKDGraphManager : public Object 
{
public:
   
    /**
    * \brief Get the type ID.
    * \return the object TypeId
    */
    static TypeId GetTypeId (void);

    /**
    * 	\brief Destructor 
    */
	virtual ~QKDGraphManager(); 

    /**
    * 	\brief Signelton getInstance function 
    */
	static QKDGraphManager* getInstance();

    /**
    * 	\brief Print graphs 
    */
	void 	PrintGraphs(); 
  
    /**
    *   \brief Connect new QKDBuffer to QKDTotalGraph
    *   @param Ptr<QKDControl>    c 
    *   @param Ptr<Node>    src 
    *   @param Ptr<Node>    dst 
    *   @param uint32_t     bufferID 
    *   @param std::string  graphTitle
    *   @param std::string  graphType
    */
    void AddQKDBuffer(
        Ptr<QKDControl> c, 
        Ptr<Node> src, 
        Ptr<Node> dst, 
        uint32_t bufferID, 
        std::string graphName, 
        std::string graphType
    );

    /**
    * \brief Mcur value changed, so plot it on the graph
    *	@param std::string context
    *	@param uint32_t value
    */
	static void ProcessCurrentChange(std::string context, uint32_t value);

    /**
    * \brief Status changed, so plot it on the graph
    *	@param std::string context
    *	@param uint32_t value
    */
	static void ProcessStatusChange(std::string context, uint32_t value);

    /**
    * \brief Mthr value changed, so plot it on the graph
    *	@param std::string context
    *	@param uint32_t value
    */
	static void ProcessThresholdChange(std::string context, uint32_t value);

	// FOR QKD TOTAL GRAPH

    /**
    * \brief Mcur value increase, so plot it on the graph
    *	@param std::string context
    *	@param uint32_t value
    */
	static void ProcessCurrentIncrease(std::string context, uint32_t value);

    /**
    * \brief Mcur value decreased, so plot it on the graph
    *	@param std::string context
    *	@param uint32_t value
    */
	static void ProcessCurrentDecrease(std::string context, uint32_t value);

    /**
    * \brief Mthr value increased, so plot it on the graph
    *	@param std::string context
    *	@param uint32_t value
    */
	static void ProcessThresholdIncrease(std::string context, uint32_t value);

    /**
    * \brief Mthr value decreased, so plot it on the graph
    *	@param std::string context
    *	@param uint32_t value
    */
	static void ProcessThresholdDecrease(std::string context, uint32_t value);
	
    /**
    * \brief Temp function, forward value form trace source to the graph in the list
    *	@param uint32_t& nodeID
    *	@param uint32_t& bufferID
    *	@param uint32_t& value
    */
	void SendStatusValueToGraph(const uint32_t& nodeID, const uint32_t& bufferID, const uint32_t& value);

    /**
    * \brief Temp function, forward value form trace source to the graph in the list
    *	@param uint32_t& nodeID
    *	@param uint32_t& bufferID
    *	@param uint32_t& value
    */
	void SendCurrentChangeValueToGraph(const uint32_t& nodeID, const uint32_t& bufferID, const uint32_t& value);

    /**
    * \brief Temp function, forward value form trace source to the graph in the list
    *	@param uint32_t& nodeID
    *	@param uint32_t& bufferID
    *	@param uint32_t& value
    */
	void SendThresholdValueToGraph(const uint32_t& nodeID, const uint32_t& bufferID, const uint32_t& value);

    /**
    * 	\brief Return Ptr to QKDTotalGraph 
    *	@return Ptr<QKDTotalGraph>
    */
	Ptr<QKDTotalGraph> GetTotalGraph(); 
	
private:  

	QKDGraphManager (){};

	static bool instanceFlag; //!< check whether object exists

	static QKDGraphManager *single; 

	static Ptr<QKDTotalGraph> m_totalGraph; //!< Ptr to QKDTotalGraph
	
	std::vector<std::vector<QKDGraph *> > m_graphs; //vector of nodes-device-channels 
};
}
#endif /* QKD_GRAPH_MANAGER */
