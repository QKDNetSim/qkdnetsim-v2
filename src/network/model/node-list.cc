/*
 * Copyright (c) 2007 INRIA
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
 * Authors:
 *  Mathieu Lacage <mathieu.lacage@sophia.inria.fr>,
 */

#include "node-list.h"

#include "node.h"

#include "ns3/assert.h"
#include "ns3/config.h"
#include "ns3/log.h"
#include "ns3/object-vector.h"
#include "ns3/simulator.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("NodeList");

/**
 * \ingroup network
 * \brief private implementation detail of the NodeList API.
 */
class NodeListPriv : public Object
{
  public:
    /**
     * \brief Get the type ID.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    NodeListPriv();
    ~NodeListPriv() override;

    /**
     * \param node node to add
     * \returns index of node in list.
     *
     * This method is called automatically from Node::Node so
     * the user has little reason to call it himself.
     */
    uint32_t Add(Ptr<Node> node);

    /**
     * \returns a C++ iterator located at the beginning of this
     *          list.
     */
    NodeList::Iterator Begin() const;

    /**
     * \returns a C++ iterator located at the end of this
     *          list.
     */
    NodeList::Iterator End() const;

    /**
     * \param n index of requested node.
     * \returns the Node associated to index n.
     */
    Ptr<Node> GetNode(uint32_t n);

    /**
     * \returns the number of nodes currently in the list.
     */
    uint32_t GetNNodes();

    /**
     * \brief Get the node list object
     * \returns the node list
     */
    static Ptr<NodeListPriv> Get();

  private:
    /**
     * \brief Get the node list object
     * \returns the node list
     */
    static Ptr<NodeListPriv>* DoGet();

    /**
     * \brief Delete the nodes list object
     */
    static void Delete();

    /**
     * \brief Dispose the nodes in the list
     */
    void DoDispose() override;

    std::vector<Ptr<Node>> m_nodes; //!< node objects container
};

NS_OBJECT_ENSURE_REGISTERED(NodeListPriv);

TypeId
NodeListPriv::GetTypeId()
{
    static TypeId tid = TypeId("ns3::NodeListPriv")
                            .SetParent<Object>()
                            .SetGroupName("Network")
                            .AddAttribute("NodeList",
                                          "The list of all nodes created during the simulation.",
                                          ObjectVectorValue(),
                                          MakeObjectVectorAccessor(&NodeListPriv::m_nodes),
                                          MakeObjectVectorChecker<Node>());
    return tid;
}

Ptr<NodeListPriv>
NodeListPriv::Get()
{
    NS_LOG_FUNCTION_NOARGS();
    return *DoGet();
}

Ptr<NodeListPriv>*
NodeListPriv::DoGet()
{
    NS_LOG_FUNCTION_NOARGS();
    static Ptr<NodeListPriv> ptr = nullptr;
    if (!ptr)
    {
        ptr = CreateObject<NodeListPriv>();
        Config::RegisterRootNamespaceObject(ptr);
        Simulator::ScheduleDestroy(&NodeListPriv::Delete);
    }
    return &ptr;
}

void
NodeListPriv::Delete()
{
    NS_LOG_FUNCTION_NOARGS();
    Config::UnregisterRootNamespaceObject(Get());
    (*DoGet()) = nullptr;
}

NodeListPriv::NodeListPriv()
{
    NS_LOG_FUNCTION(this);
}

NodeListPriv::~NodeListPriv()
{
    NS_LOG_FUNCTION(this);
}

void
NodeListPriv::DoDispose()
{
    NS_LOG_FUNCTION(this);
    for (auto i = m_nodes.begin(); i != m_nodes.end(); i++)
    {
        Ptr<Node> node = *i;
        node->Dispose();
        *i = nullptr;
    }
    m_nodes.erase(m_nodes.begin(), m_nodes.end());
    Object::DoDispose();
}

uint32_t
NodeListPriv::Add(Ptr<Node> node)
{
    NS_LOG_FUNCTION(this << node);
    uint32_t index = m_nodes.size();
    m_nodes.push_back(node);
    Simulator::ScheduleWithContext(index, TimeStep(0), &Node::Initialize, node);
    return index;
}

NodeList::Iterator
NodeListPriv::Begin() const
{
    NS_LOG_FUNCTION(this);
    return m_nodes.begin();
}

NodeList::Iterator
NodeListPriv::End() const
{
    NS_LOG_FUNCTION(this);
    return m_nodes.end();
}

uint32_t
NodeListPriv::GetNNodes()
{
    NS_LOG_FUNCTION(this);
    return m_nodes.size();
}

Ptr<Node>
NodeListPriv::GetNode(uint32_t n)
{
    NS_LOG_FUNCTION(this << n);
    NS_ASSERT_MSG(n < m_nodes.size(),
                  "Node index " << n << " is out of range (only have " << m_nodes.size()
                                << " nodes).");
    return m_nodes[n];
}

} // namespace ns3

/**
 * The implementation of the public static-based API
 * which calls into the private implementation through
 * the simulation singleton.
 */
namespace ns3
{

uint32_t
NodeList::Add(Ptr<Node> node)
{
    NS_LOG_FUNCTION(node);
    return NodeListPriv::Get()->Add(node);
}

NodeList::Iterator
NodeList::Begin()
{
    NS_LOG_FUNCTION_NOARGS();
    return NodeListPriv::Get()->Begin();
}

NodeList::Iterator
NodeList::End()
{
    NS_LOG_FUNCTION_NOARGS();
    return NodeListPriv::Get()->End();
}

Ptr<Node>
NodeList::GetNode(uint32_t n)
{
    NS_LOG_FUNCTION(n);
    return NodeListPriv::Get()->GetNode(n);
}

uint32_t
NodeList::GetNNodes()
{
    NS_LOG_FUNCTION_NOARGS();
    return NodeListPriv::Get()->GetNNodes();
}

} // namespace ns3
