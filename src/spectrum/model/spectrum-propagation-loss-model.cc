/*
 * Copyright (c) 2010 CTTC
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
 * Author: Nicola Baldo <nbaldo@cttc.es>
 */

#include "spectrum-propagation-loss-model.h"

#include "spectrum-signal-parameters.h"

#include <ns3/log.h>

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("SpectrumPropagationLossModel");

NS_OBJECT_ENSURE_REGISTERED(SpectrumPropagationLossModel);

SpectrumPropagationLossModel::SpectrumPropagationLossModel()
    : m_next(nullptr)
{
}

SpectrumPropagationLossModel::~SpectrumPropagationLossModel()
{
}

void
SpectrumPropagationLossModel::DoDispose()
{
    m_next = nullptr;
}

TypeId
SpectrumPropagationLossModel::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::SpectrumPropagationLossModel").SetParent<Object>().SetGroupName("Spectrum");
    return tid;
}

void
SpectrumPropagationLossModel::SetNext(Ptr<SpectrumPropagationLossModel> next)
{
    m_next = next;
}

Ptr<SpectrumPropagationLossModel>
SpectrumPropagationLossModel::GetNext() const
{
    return m_next;
}

Ptr<SpectrumValue>
SpectrumPropagationLossModel::CalcRxPowerSpectralDensity(Ptr<const SpectrumSignalParameters> params,
                                                         Ptr<const MobilityModel> a,
                                                         Ptr<const MobilityModel> b) const
{
    Ptr<SpectrumValue> rxPsd = DoCalcRxPowerSpectralDensity(params, a, b);
    if (m_next)
    {
        rxPsd = m_next->CalcRxPowerSpectralDensity(params, a, b);
    }
    return rxPsd;
}

int64_t
SpectrumPropagationLossModel::AssignStreams(int64_t stream)
{
    auto currentStream = stream;
    currentStream += DoAssignStreams(stream);
    if (m_next)
    {
        currentStream += m_next->AssignStreams(currentStream);
    }
    return (currentStream - stream);
}

} // namespace ns3
