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

#include "qkd-graph.h"  

namespace ns3 {
 
NS_LOG_COMPONENT_DEFINE ("QKDGraph");

NS_OBJECT_ENSURE_REGISTERED (QKDGraph);

TypeId QKDGraph::GetTypeId (void) 
{
  static TypeId tid = TypeId ("ns3::QKDGraph")
    .SetParent<Object> () 
    ; 
  return tid;
}
 
QKDGraph::~QKDGraph(){}

QKDGraph::QKDGraph (
	Ptr<QKDControl> control,
	Ptr<Node> src,
	Ptr<Node> dst,
	uint32_t bufferPosition,
	std::string graphTitle,
	std::string graphType
)
{ 	 
    NS_LOG_FUNCTION (this << src->GetId() << dst->GetId() << bufferPosition << graphTitle);

	Ptr<Node> node = src; 
	m_buffer = control->GetBufferByDestinationNode (dst); 
	m_src = src;
	m_dst = dst;
 
	m_keymCurrent = 	m_buffer->GetKeyCountBit();
	m_keymMin = 		m_buffer->GetMinKeySizeBit();
	m_keymMax = 		m_buffer->GetMaxKeySizeBit(); 
	m_keymThreshold = 	m_buffer->GetMthr(); 
	m_tempMax = m_keymMax * 1.1; //just to plot arrows on the graph
	m_graphStatusEntry = 0; 
   
	m_plotFileName = (graphTitle.empty()) ? "QKD_key_material" : graphTitle;
	m_plotFileType = (graphType.empty()) ? "png" : graphType;; 

	if(graphTitle.empty()){
		std::ostringstream temp1;
		temp1 << m_src->GetId() << m_dst->GetId();
		m_plotFileName = m_plotFileName + "_" + temp1.str();
	}

	m_gnuplot.SetOutputFilename (m_plotFileName + "." + m_plotFileType);

	m_dataset.SetTitle ("Amount of key material");
	m_dataset.SetStyle (Gnuplot2dDataset::LINES_POINTS);
	m_dataset.SetExtra(" ls 1"); 
	m_dataset.Add( 0, m_keymCurrent); 

	m_datasetThreshold.SetTitle ("Threshold");
	m_datasetThreshold.SetStyle (Gnuplot2dDataset::LINES_POINTS);
	m_datasetThreshold.SetExtra(" ls 4"); 
	m_datasetThreshold.Add( 0, m_keymThreshold); 

	m_datasetMinimum.SetTitle ("Minimum");
	m_datasetMinimum.SetStyle (Gnuplot2dDataset::LINES_POINTS);
	m_datasetMinimum.SetExtra(" ls 5"); 
	m_datasetMinimum.Add( 0, m_keymMin); 

	m_datasetMaximum.SetTitle ("Maximum");
	m_datasetMaximum.SetStyle (Gnuplot2dDataset::LINES_POINTS);
	m_datasetMaximum.SetExtra(" ls 6"); 
	m_datasetMaximum.Add( 0, m_keymMax); 
  
	m_datasetWorkingState_0.SetStyle (Gnuplot2dDataset::FILLEDCURVE);
	m_datasetWorkingState_0.SetTitle ("Status: READY");
	m_datasetWorkingState_0.SetExtra (" y1=0 lc rgb '#b0fbb4'"); 
 
	m_datasetWorkingState_1.SetStyle (Gnuplot2dDataset::FILLEDCURVE);
	m_datasetWorkingState_1.SetTitle ("Status: WARNING"); 
	m_datasetWorkingState_1.SetExtra (" y1=0 lc rgb '#f7ea50'"); 

	m_datasetWorkingState_2.SetStyle (Gnuplot2dDataset::FILLEDCURVE);
	m_datasetWorkingState_2.SetTitle ("Status: CHARGING"); 
	m_datasetWorkingState_2.SetExtra (" y1=0 lc rgb '#fbc4ca'"); 
 
	m_datasetWorkingState_3.SetStyle (Gnuplot2dDataset::FILLEDCURVE);
	m_datasetWorkingState_3.SetTitle ("Status: EMPTY"); 
	m_datasetWorkingState_3.SetExtra (" y1=0 lc rgb '#e6e4e4'");  
 	
	m_buffer->CheckState(); 
	ProcessMStatusHelpFunction(0.0, m_buffer->FetchState()); 
 	
	std::string outputTerminalCommand;

	if (m_plotFileType=="png") {
		outputTerminalCommand = "pngcair";
	} else if (m_plotFileType=="tex") {
		outputTerminalCommand = "epslatex";
	} else {
		outputTerminalCommand = m_plotFileType;
	}

	std::ostringstream yrange;
	yrange << "set yrange[1:" << m_tempMax << "];";

	m_gnuplot.AppendExtra ("set border linewidth 2"); 

	if (m_plotFileType=="tex") {
		m_gnuplot.AppendExtra ("set terminal " + outputTerminalCommand); 
	} else {
		m_gnuplot.AppendExtra ("set terminal " + outputTerminalCommand + " size 1524,768 enhanced font 'Helvetica,18'"); 
	}

	m_gnuplot.AppendExtra (yrange.str());

	m_gnuplot.AppendExtra ("set style line 1 linecolor rgb 'red' linetype 1 linewidth 1");  
	m_gnuplot.AppendExtra ("set style line 3 linecolor rgb 'black' linetype 1 linewidth 1"); 

	m_gnuplot.AppendExtra ("set style line 4 linecolor rgb \"#8A2BE2\" linetype 1 linewidth 1"); 
	m_gnuplot.AppendExtra ("set style line 5 linecolor rgb 'blue' linetype 8 linewidth 1"); 
	m_gnuplot.AppendExtra ("set style line 6 linecolor rgb 'blue' linetype 10 linewidth 1"); 
	m_gnuplot.AppendExtra ("set style line 7 linecolor rgb 'gray' linetype 0 linewidth 1"); 
	m_gnuplot.AppendExtra ("set style line 8 linecolor rgb 'gray' linetype 0 linewidth 1 ");  

	m_gnuplot.AppendExtra ("set grid ytics lt 0 lw 1 lc rgb \"#ccc\""); 
	m_gnuplot.AppendExtra ("set grid xtics lt 0 lw 1 lc rgb \"#ccc\""); 

	m_gnuplot.AppendExtra ("set mxtics 5"); 
	m_gnuplot.AppendExtra ("set grid mxtics xtics ls 7, ls 8"); 

	m_gnuplot.AppendExtra ("set arrow from graph 1,0 to graph 1.03,0 size screen 0.025,15,60 filled ls 3"); 
	m_gnuplot.AppendExtra ("set arrow from graph 0,1 to graph 0,1.03 size screen 0.025,15,60 filled ls 3");

	m_gnuplot.AppendExtra ("set style fill transparent solid 0.4 noborder");  
	//m_gnuplot.AppendExtra ("set logscale y 2");  

	if (m_plotFileType=="tex") {
		m_gnuplot.AppendExtra ("set key outside");  
		m_gnuplot.AppendExtra ("set key center top");   
	}else{
		m_gnuplot.AppendExtra ("set key outside");  
		m_gnuplot.AppendExtra ("set key right bottom"); 
	}

 	std::string plotTitle;

	if(graphTitle.empty()){
		plotTitle = "QKD Key Buffer on node "; 
		if(m_src && m_dst){
		
			std::ostringstream tempSource;
			tempSource << m_src->GetId();

			std::ostringstream tempDestination;
			tempDestination << m_dst->GetId();

			plotTitle = plotTitle + tempSource.str() + "\\n QKD link between nodes " + tempSource.str() + " and " + tempDestination.str();
		} 
	}else{
		 plotTitle = graphTitle; 
	}

	m_gnuplot.SetTitle (plotTitle); 
	//m_gnuplot.SetTerminal ("png");
	// Set the labels for each axis.
	m_gnuplot.SetLegend ("Time (seconds)", "Key material (bits)");

}


void
QKDGraph::PrintGraph(){

    NS_LOG_FUNCTION (this << m_src->GetId() << m_dst->GetId() << m_plotFileName);
  
	std::string tempPlotFileName1 = m_plotFileName;
	tempPlotFileName1 += "_data.dat"; 
	std::ofstream tempPlotFile1 (tempPlotFileName1.c_str());
	
	for(uint i=1;i<=30;i++){
		m_datasetMinimum.Add( i*(m_simulationTime/30), m_keymMin);  
		m_datasetMaximum.Add( i*(m_simulationTime/30), m_keymMax);
	}
	m_datasetThreshold.Add( m_simulationTime , m_buffer->GetMthr());  
	
	m_buffer->CheckState(); 
	ProcessMStatusHelpFunction(m_simulationTime, m_buffer->FetchState()); 

	m_gnuplot.AddDataset (m_dataset);
	m_gnuplot.AddDataset (m_datasetThreshold);
	m_gnuplot.AddDataset (m_datasetMinimum);
	m_gnuplot.AddDataset (m_datasetMaximum);
	m_gnuplot.AddDataset (m_datasetWorkingState_0);
	m_gnuplot.AddDataset (m_datasetWorkingState_1);
	m_gnuplot.AddDataset (m_datasetWorkingState_2);
	m_gnuplot.AddDataset (m_datasetWorkingState_3);

	m_plotFileName += ".plt"; 
	// Open the plot file.
	std::ofstream plotFile (m_plotFileName.c_str());

	// Write the plot file.
	m_gnuplot.GenerateOutput (plotFile, tempPlotFile1, tempPlotFileName1);

	// Close the plot file.
	plotFile.close ();  
}

void
QKDGraph::InitTotalGraph() const{
	m_buffer->InitTotalGraph();
}
 
 
void
QKDGraph::ProcessMCurrent(uint32_t newValue){ 
	
    NS_LOG_FUNCTION (this << newValue << m_src->GetId() << m_dst->GetId() );
	m_simulationTime = Simulator::Now().GetSeconds();  	
	m_dataset.Add( m_simulationTime, newValue);  
}
 
void
QKDGraph::ProcessMThrStatus(uint32_t newValue){ 
	
    NS_LOG_FUNCTION (this << newValue << m_src->GetId() << m_dst->GetId() );
	m_simulationTime = Simulator::Now().GetSeconds();  	
	m_datasetThreshold.Add( m_simulationTime, newValue);  
}

void
QKDGraph::ProcessMStatusHelpFunction(double time, uint32_t newValue){
	
    NS_LOG_FUNCTION (this << time << newValue << m_src->GetId() << m_dst->GetId() );
	
	switch(newValue){
		case 0:
			m_datasetWorkingState_0.Add( time, m_keymMax);
			m_datasetWorkingState_1.Add( time, 0);
			m_datasetWorkingState_2.Add( time, 0);
			m_datasetWorkingState_3.Add( time, 0);
		break;
		case 1:
			m_datasetWorkingState_0.Add( time, 0);
			m_datasetWorkingState_1.Add( time, m_keymMax);
			m_datasetWorkingState_2.Add( time, 0);
			m_datasetWorkingState_3.Add( time, 0);

		break;
		case 2:
			m_datasetWorkingState_0.Add( time, 0);
			m_datasetWorkingState_1.Add( time, 0);
			m_datasetWorkingState_2.Add( time, m_keymMax);
			m_datasetWorkingState_3.Add( time, 0);
		break;
		case 3:
			m_datasetWorkingState_0.Add( time, 0);
			m_datasetWorkingState_1.Add( time, 0);
			m_datasetWorkingState_2.Add( time, 0);
			m_datasetWorkingState_3.Add( time, m_keymMax); 
		break;
	}
	m_graphStatusEntry++;
}
 

void
QKDGraph::ProcessMStatus(uint32_t newValue){ 
	
    NS_LOG_FUNCTION (this << newValue);

	m_simulationTime = Simulator::Now().GetSeconds(); 
	ProcessMStatusHelpFunction(m_simulationTime, newValue);
}

}
