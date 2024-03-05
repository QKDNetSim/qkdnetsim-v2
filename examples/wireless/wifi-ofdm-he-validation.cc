/*
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
 * Author: Sébastien Deronne <sebastien.deronne@gmail.com>
 */

// This example is used to validate Nist, Yans and Table-based error rate models for HE rates.
//
// It outputs plots of the Frame Success Rate versus the Signal-to-noise ratio for
// Nist, Yans and Table-based error rate models and for every HE MCS value.

#include "ns3/command-line.h"
#include "ns3/gnuplot.h"
#include "ns3/nist-error-rate-model.h"
#include "ns3/table-based-error-rate-model.h"
#include "ns3/wifi-tx-vector.h"
#include "ns3/yans-error-rate-model.h"

#include <cmath>
#include <fstream>

using namespace ns3;

int
main(int argc, char* argv[])
{
    uint32_t frameSizeBytes = 1500;
    std::ofstream yansfile("yans-frame-success-rate-ax.plt");
    std::ofstream nistfile("nist-frame-success-rate-ax.plt");
    std::ofstream tablefile("table-frame-success-rate-ax.plt");

    const std::vector<std::string> modes{
        "HeMcs0",
        "HeMcs1",
        "HeMcs2",
        "HeMcs3",
        "HeMcs4",
        "HeMcs5",
        "HeMcs6",
        "HeMcs7",
        "HeMcs8",
        "HeMcs9",
        "HeMcs10",
        "HeMcs11",
    };

    CommandLine cmd(__FILE__);
    cmd.AddValue("FrameSize", "The frame size", frameSizeBytes);
    cmd.Parse(argc, argv);

    Gnuplot yansplot = Gnuplot("yans-frame-success-rate-ax.eps");
    Gnuplot nistplot = Gnuplot("nist-frame-success-rate-ax.eps");
    Gnuplot tableplot = Gnuplot("table-frame-success-rate-ax.eps");

    Ptr<YansErrorRateModel> yans = CreateObject<YansErrorRateModel>();
    Ptr<NistErrorRateModel> nist = CreateObject<NistErrorRateModel>();
    Ptr<TableBasedErrorRateModel> table = CreateObject<TableBasedErrorRateModel>();
    WifiTxVector txVector;

    uint32_t frameSizeBits = frameSizeBytes * 8;

    for (const auto& mode : modes)
    {
        std::cout << mode << std::endl;
        Gnuplot2dDataset yansdataset(mode);
        Gnuplot2dDataset nistdataset(mode);
        Gnuplot2dDataset tabledataset(mode);
        txVector.SetMode(mode);

        WifiMode wifiMode(mode);

        for (double snrDb = -5.0; snrDb <= 40.0; snrDb += 0.1)
        {
            double snr = std::pow(10.0, snrDb / 10.0);

            double ps = yans->GetChunkSuccessRate(wifiMode, txVector, snr, frameSizeBits);
            if (ps < 0.0 || ps > 1.0)
            {
                // error
                exit(1);
            }
            yansdataset.Add(snrDb, ps);

            ps = nist->GetChunkSuccessRate(wifiMode, txVector, snr, frameSizeBits);
            if (ps < 0.0 || ps > 1.0)
            {
                // error
                exit(1);
            }
            nistdataset.Add(snrDb, ps);

            ps = table->GetChunkSuccessRate(wifiMode, txVector, snr, frameSizeBits);
            if (ps < 0.0 || ps > 1.0)
            {
                // error
                exit(1);
            }
            tabledataset.Add(snrDb, ps);
        }

        yansplot.AddDataset(yansdataset);
        nistplot.AddDataset(nistdataset);
        tableplot.AddDataset(tabledataset);
    }

    yansplot.SetTerminal("postscript eps color enh \"Times-BoldItalic\"");
    yansplot.SetLegend("SNR(dB)", "Frame Success Rate");
    yansplot.SetExtra("set xrange [-5:55]\n\
set yrange [0:1]\n\
set style line 1 linewidth 5\n\
set style line 2 linewidth 5\n\
set style line 3 linewidth 5\n\
set style line 4 linewidth 5\n\
set style line 5 linewidth 5\n\
set style line 6 linewidth 5\n\
set style line 7 linewidth 5\n\
set style line 8 linewidth 5\n\
set style line 9 linewidth 5\n\
set style line 10 linewidth 5\n\
set style line 11 linewidth 5\n\
set style line 12 linewidth 5\n\
set style increment user");
    yansplot.GenerateOutput(yansfile);
    yansfile.close();

    nistplot.SetTerminal("postscript eps color enh \"Times-BoldItalic\"");
    nistplot.SetLegend("SNR(dB)", "Frame Success Rate");
    nistplot.SetExtra("set xrange [-5:55]\n\
set yrange [0:1]\n\
set style line 1 linewidth 5\n\
set style line 2 linewidth 5\n\
set style line 3 linewidth 5\n\
set style line 4 linewidth 5\n\
set style line 5 linewidth 5\n\
set style line 6 linewidth 5\n\
set style line 7 linewidth 5\n\
set style line 8 linewidth 5\n\
set style line 9 linewidth 5\n\
set style line 10 linewidth 5\n\
set style line 11 linewidth 5\n\
set style line 12 linewidth 5\n\
set style increment user");

    nistplot.GenerateOutput(nistfile);
    nistfile.close();

    tableplot.SetTerminal("postscript eps color enh \"Times-BoldItalic\"");
    tableplot.SetLegend("SNR(dB)", "Frame Success Rate");
    tableplot.SetExtra("set xrange [-5:55]\n\
set yrange [0:1]\n\
set style line 1 linewidth 5\n\
set style line 2 linewidth 5\n\
set style line 3 linewidth 5\n\
set style line 4 linewidth 5\n\
set style line 5 linewidth 5\n\
set style line 6 linewidth 5\n\
set style line 7 linewidth 5\n\
set style line 8 linewidth 5\n\
set style line 9 linewidth 5\n\
set style line 10 linewidth 5\n\
set style line 11 linewidth 5\n\
set style line 12 linewidth 5\n\
set style increment user");

    tableplot.GenerateOutput(tablefile);
    tablefile.close();

    return 0;
}
