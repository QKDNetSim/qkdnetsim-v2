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

#ifndef QKD_GRAPH_H
#define QKD_GRAPH_H

#include <fstream>
#include "ns3/object.h"
#include "ns3/gnuplot.h"
#include "ns3/core-module.h"
#include "ns3/node-list.h"
#include "ns3/qkd-control.h"
#include <sstream>

namespace ns3 {

  /**
   * \ingroup qkd
   * \class QKDGraph
   * \brief QKD graphs are implemented to allow straightforward access to QKD buffers' 
   * state and convenient monitoring of key material consumption. 
   *
   * \note QKD graph is associated with QKD buffer which allows plotting of graphs on each node with 
   * associated QKD link and QKD buffer. QKD Graph creates separate PLT and DAT files which are 
   * suitable for plotting using popular Gnuplot tool in PNG (default), SVG or EPSLATEX format. 
   * QKDNetSim supports plotting of QKD Total Graph which is used to show the overall consumption
   * of key material in QKD Network. QKD Total Graph is updated each time when key material is 
   * generated or consumed on a network link.
   */
  class QKDGraph: public Object {
    public:

      /**
       * \brief Get the type ID.
       * \return the object TypeId
       */
      static TypeId GetTypeId(void);

    /**
     *  \brief Constructor
     *   @param Ptr<QKDControl> control
     *  @param Ptr<Node> src
     *   @param Ptr<Node> dst
     *  @param uint32_t bufferID
     *  @param std::string graphTitle
     *  @param std::string graphType
     */
    QKDGraph(
      Ptr < QKDControl > control,
      Ptr < Node > src,
      Ptr < Node > dst,
      uint32_t bufferID,
      std::string graphTitle,
      std::string graphType
    );

    /**
     * \brief Destructor
     */
    virtual~QKDGraph();

    /**
     * \brief Initialized function for total graph
     */
    void InitTotalGraph() const;

    /**
     * \brief Print the graph
     */
    void PrintGraph();

    /**
     * \brief MCurrent value of the QKDBuffer changed, so plot it on the graph
     */
    void ProcessMCurrent(uint32_t value);

    /**
     * \brief The status of the QKDBuffer changed, so plot it on the graph
     */
    void ProcessMStatus(uint32_t value);

    /**
     * \brief The Mthr value of the QKDBuffer changed, so plot it on the graph
     */
    void ProcessMThrStatus(uint32_t value);

    /**
     * \brief Help function for detection of status change value
     */
    void ProcessMStatusHelpFunction(double time, uint32_t newValue);

    private:

    Ptr < QKDBuffer > m_buffer; //!< QKDBuffer associated with the QKDGraph
    Ptr < Node > m_src; //!< source node, info required for graph title
    Ptr < Node > m_dst; //!< destination node, info required for graph title 

    uint32_t m_keymMin; //!< get some boundaries for the graph
    uint32_t m_keymCurrent; //!< get some boundaries for the graph
    uint32_t m_keymMax; //!< get some boundaries for the graph
    uint32_t m_tempMax; //!< get some boundaries for the graph
    uint32_t m_keymThreshold; //!< get some boundaries for the graph

    std::string m_plotFileName; //!< output filename
    std::string m_plotFileType; //png or svg
    double m_simulationTime; //!< time value, x-axis
    uint32_t m_graphStatusEntry; //!< temp variable

    Gnuplot m_gnuplot; //!< Gluplot object settings
    Gnuplot2dDataset m_dataset;
    Gnuplot2dDataset m_datasetWorkingState_Mthr;
    Gnuplot2dDataset m_datasetWorkingState_0;
    Gnuplot2dDataset m_datasetWorkingState_1;
    Gnuplot2dDataset m_datasetWorkingState_2;
    Gnuplot2dDataset m_datasetWorkingState_3;
    Gnuplot2dDataset m_datasetThreshold;
    Gnuplot2dDataset m_datasetMinimum;
    Gnuplot2dDataset m_datasetMaximum;
  };
}

#endif /* QKDGRAPH */