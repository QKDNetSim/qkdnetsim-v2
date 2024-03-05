/*
 * Copyright (c) 2006, 2007 INRIA
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
 * Author: Mathieu Lacage <mathieu.lacage@sophia.inria.fr>
 */
#ifndef CONSTANT_VELOCITY_MOBILITY_MODEL_H
#define CONSTANT_VELOCITY_MOBILITY_MODEL_H

#include "constant-velocity-helper.h"
#include "mobility-model.h"

#include "ns3/nstime.h"

#include <stdint.h>

namespace ns3
{

/**
 * \ingroup mobility
 *
 * \brief Mobility model for which the current speed does not change once it has been set and until
 * it is set again explicitly to a new value.
 */
class ConstantVelocityMobilityModel : public MobilityModel
{
  public:
    /**
     * Register this type with the TypeId system.
     * \return the object TypeId
     */
    static TypeId GetTypeId();
    /**
     * Create position located at coordinates (0,0,0) with
     * speed (0,0,0).
     */
    ConstantVelocityMobilityModel();
    ~ConstantVelocityMobilityModel() override;

    /**
     * \param speed the new speed to set.
     *
     * Set the current speed now to (dx,dy,dz)
     * Unit is meters/s
     */
    void SetVelocity(const Vector& speed);

  private:
    Vector DoGetPosition() const override;
    void DoSetPosition(const Vector& position) override;
    Vector DoGetVelocity() const override;
    ConstantVelocityHelper m_helper; //!< helper object for this model
};

} // namespace ns3

#endif /* CONSTANT_VELOCITY_POSITION */
