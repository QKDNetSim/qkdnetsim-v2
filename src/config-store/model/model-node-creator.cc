/*
 *  This program is free software; you can redistribute it and/or modify
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
 * Authors: Faker Moatamri <faker.moatamri@sophia.inria.fr>
 *          Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */

#include "model-node-creator.h"

namespace ns3
{

ModelCreator::ModelCreator()
{
}

void

ModelCreator::Build(GtkTreeStore* treestore)
{
    m_treestore = treestore;
    m_iters.push_back(nullptr);
    // this function will go through all the objects and call on them
    // DoStartVisitObject, DoIterate and DoEndVisitObject
    Iterate();
    NS_ASSERT(m_iters.size() == 1);
}

void
ModelCreator::Add(ModelNode* node)
{
    GtkTreeIter* parent = m_iters.back();
    auto current = g_new(GtkTreeIter, 1);
    gtk_tree_store_append(m_treestore, current, parent);
    gtk_tree_store_set(m_treestore, current, COL_NODE, node, -1);
    m_iters.push_back(current);
}

void
ModelCreator::Remove()
{
    GtkTreeIter* iter = m_iters.back();
    g_free(iter);
    m_iters.pop_back();
}

void
ModelCreator::DoVisitAttribute(Ptr<Object> object, std::string name)
{
    auto node = new ModelNode();
    node->type = ModelNode::NODE_ATTRIBUTE;
    node->object = object;
    node->name = name;
    Add(node);
    Remove();
}

void
ModelCreator::DoStartVisitObject(Ptr<Object> object)
{
    auto node = new ModelNode();
    node->type = ModelNode::NODE_OBJECT;
    node->object = object;
    Add(node);
}

void
ModelCreator::DoEndVisitObject()
{
    Remove();
}

void
ModelCreator::DoStartVisitPointerAttribute(Ptr<Object> object, std::string name, Ptr<Object> value)
{
    auto node = new ModelNode();
    node->type = ModelNode::NODE_POINTER;
    node->object = object;
    node->name = name;
    Add(node);
}

void
ModelCreator::DoEndVisitPointerAttribute()
{
    Remove();
}

void
ModelCreator::DoStartVisitArrayAttribute(Ptr<Object> object,
                                         std::string name,
                                         const ObjectPtrContainerValue& vector)
{
    auto node = new ModelNode();
    node->type = ModelNode::NODE_VECTOR;
    node->object = object;
    node->name = name;
    Add(node);
}

void
ModelCreator::DoEndVisitArrayAttribute()
{
    Remove();
}

void
ModelCreator::DoStartVisitArrayItem(const ObjectPtrContainerValue& vector,
                                    uint32_t index,
                                    Ptr<Object> item)
{
    GtkTreeIter* parent = m_iters.back();
    auto current = g_new(GtkTreeIter, 1);
    auto node = new ModelNode();
    node->type = ModelNode::NODE_VECTOR_ITEM;
    node->object = item;
    node->index = index;
    gtk_tree_store_append(m_treestore, current, parent);
    gtk_tree_store_set(m_treestore, current, COL_NODE, node, -1);
    m_iters.push_back(current);
}

void
ModelCreator::DoEndVisitArrayItem()
{
    GtkTreeIter* iter = m_iters.back();
    g_free(iter);
    m_iters.pop_back();
}
} // end namespace ns3
