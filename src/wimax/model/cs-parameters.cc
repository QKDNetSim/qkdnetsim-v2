/*
 *  Copyright (c) 2009 INRIA, UDcast
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
 *         Mohamed Amine Ismail <amine.ismail@sophia.inria.fr>
 *
 */
#include "cs-parameters.h"

#include "wimax-tlv.h"

namespace ns3
{
CsParameters::CsParameters()
{
    m_classifierDscAction = CsParameters::ADD;
}

CsParameters::~CsParameters()
{
}

CsParameters::CsParameters(Tlv tlv)
{
    NS_ASSERT_MSG(tlv.GetType() == SfVectorTlvValue::IPV4_CS_Parameters, "Invalid TLV");
    CsParamVectorTlvValue* param = ((CsParamVectorTlvValue*)(tlv.PeekValue()));

    for (auto iter = param->Begin(); iter != param->End(); ++iter)
    {
        switch ((*iter)->GetType())
        {
        case CsParamVectorTlvValue::Classifier_DSC_Action: {
            m_classifierDscAction =
                (CsParameters::Action)((U8TlvValue*)((*iter)->PeekValue()))->GetValue();
            break;
        }
        case CsParamVectorTlvValue::Packet_Classification_Rule: {
            m_packetClassifierRule = IpcsClassifierRecord(*(*iter));
            break;
        }
        }
    }
}

CsParameters::CsParameters(CsParameters::Action classifierDscAction,
                           IpcsClassifierRecord classifier)
{
    m_classifierDscAction = classifierDscAction;
    m_packetClassifierRule = classifier;
}

void
CsParameters::SetClassifierDscAction(CsParameters::Action action)
{
    m_classifierDscAction = action;
}

void
CsParameters::SetPacketClassifierRule(IpcsClassifierRecord packetClassifierRule)
{
    m_packetClassifierRule = packetClassifierRule;
}

CsParameters::Action
CsParameters::GetClassifierDscAction() const
{
    return m_classifierDscAction;
}

IpcsClassifierRecord
CsParameters::GetPacketClassifierRule() const
{
    return m_packetClassifierRule;
}

Tlv
CsParameters::ToTlv() const
{
    CsParamVectorTlvValue tmp;
    tmp.Add(
        Tlv(CsParamVectorTlvValue::Classifier_DSC_Action, 1, U8TlvValue(m_classifierDscAction)));
    tmp.Add(m_packetClassifierRule.ToTlv());
    return Tlv(SfVectorTlvValue::IPV4_CS_Parameters, tmp.GetSerializedSize(), tmp);
}
} // namespace ns3
