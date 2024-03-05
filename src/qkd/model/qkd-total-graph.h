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

#ifndef QKD_TOTAL_GRAPH_H
#define QKD_TOTAL_GRAPH_H

#include <fstream>
#include "ns3/object.h"
#include "ns3/gnuplot.h"
#include "ns3/core-module.h"
#include "ns3/node-list.h" 
#include <sstream>

namespace ns3 {

/**
 * \ingroup qkd
 * \class QKDTotalGraph
 * \brief QKDTotalGraph is implemented to allow easier access to the state of 
 *  ALL QKD buffers and easier monitoring of the overall key material consumption. 
 *
 * \note QKDTotalGraph is used to show the overall consumption of key material in QKD Network. 
 *	QKD Total Graph is updated each time when key material is generated or consumed on a 
 *	network link. Only one QKDTotalGraph in the whole simulation is allowed!
 */
class QKDTotalGraph : public Object 
{
public:
    
    /**
    * \brief Get the type ID.
    * \return the object TypeId
    */
    static TypeId GetTypeId (void);

    /**
    * 	\brief Constructor 
    */
	QKDTotalGraph (); 

    /**
    * 	\brief Constructor 
    *	@param std::string graphTitle
    *	@param std::string graphType
    */
	QKDTotalGraph (
		std::string graphName,
		std::string graphType
	);

    /**
    * \brief Initialized function used in constructor
    */
	void Init (
		std::string graphName,
		std::string graphType
	);

    /**
    * \brief Destructor
    */
	virtual ~QKDTotalGraph(); 

    /**
    * \brief Print the graph
    */
	void PrintGraph (); 

    /**
    * \brief Mthr value of the QKDBuffer changed, so plot it on the graph
    *	@param uint32_t value
    *	@param char signToBePloted
    */
	void ProcessMThr (uint32_t value, char sign);

    /**
    * \brief MCurrent value of the QKDBuffer changed, so plot it on the graph
    *	@param uint32_t value
    *	@param char signToBePloted
    */
	void ProcessMCurrent (uint32_t value, char sign);
 
private: 
 	
	uint32_t     		m_keymCurrent; //!< get some boundaries for the graph
	uint32_t     		m_keymThreshold;  //!< get some boundaries for the graph

	std::string			m_plotFileName; //!< output filename
	std::string			m_plotFileType; //png or svg
	double				m_simulationTime; //!< time value, x-axis 

	Gnuplot				m_gnuplot;
    Gnuplot2dDataset 	m_dataset; 
    Gnuplot2dDataset 	m_datasetThreshold; 
};
}

#endif /* QKDTotalGraph */
