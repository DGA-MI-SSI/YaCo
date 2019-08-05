//  Copyright (C) 2017 The YaCo Authors
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include "IModelVisitor.hpp"            // Interface I implement

#include <memory>

// Exported: the Ctor
struct IModelVisitor;
std::shared_ptr<IModelVisitor> MakeExporterValidatorVisitor();


/*********************************************************************************
*************************** NON EXPORTED STUFF ***********************************
*********************************************************************************/

const offset_t UNKNOWN_ADDR = ~static_cast<offset_t>(0);

enum VisitorState_e
{
    VISIT_STARTED,
    VISIT_OBJECT_VERSION,
    VISIT_SIGNATURES,
    VISIT_OFFSETS,
    VISIT_XREFS,
    VISIT_XREF,
    VISIT_MATCHING_SYSTEMS,
    VISIT_MATCHING_SYSTEM,
};

const int MAX_VISIT_DEPTH = 256;

// Class to validate Exporter visitor
class ExporterValidatorVisitor
    : public IModelVisitor
{
public:
    ExporterValidatorVisitor();
    ~ExporterValidatorVisitor() override;

    // Interface methods
    DECLARE_VISITOR_INTERFACE_METHODS

private:
    VisitorState_e state[MAX_VISIT_DEPTH];
    int current_state_depth;
    offset_t last_offset_ea;
};