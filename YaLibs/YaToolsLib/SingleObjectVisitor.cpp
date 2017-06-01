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

#include "IObjectVisitorListener.hpp"

#include "YaToolObjectId.hpp"
#include "MemoryModelVisitor.hpp"
#include "YaToolObjectVersion.hpp"
#include "YaToolReferencedObject.hpp"
#include "Yatools.h"
#include "Logger.h"

#ifdef DEBUG
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("object_visitor", (FMT), ## __VA_ARGS__)
#else
#define LOG(...)
#endif

namespace
{
struct SingleObjectVisitor
    : public MemoryModelVisitor
{
    SingleObjectVisitor(IObjectVisitorListener& listener);

    void visit_end_object_version();
    void visit_end_deleted_object();
    void visit_end_default_object();
    void visit_end_reference_object();

private:
    IObjectVisitorListener&                             listener_;
    std::vector<std::shared_ptr<YaToolObjectVersion>>   versions_;
};
}

std::shared_ptr<IModelVisitor> MakeSingleObjectVisitor(IObjectVisitorListener& listener)
{
    return std::make_shared<SingleObjectVisitor>(listener);
}

SingleObjectVisitor::SingleObjectVisitor(IObjectVisitorListener& listener)
    : listener_(listener)
{
}

void SingleObjectVisitor::visit_end_object_version()
{
    current_object_version_->set_referenced_object(current_referenced_object_);
    current_referenced_object_->putVersion(current_object_version_);

    LOG(INFO, "Object version visit_end : %s\n", TO_STRING(YaToolObjectId_To_StdString(current_referenced_object_->getId())));
    LOG(INFO, "visiting listener %s object_version : %s\n", TO_STRING(&listener_), TO_STRING(YaToolObjectId_To_StdString(current_object_version_->get_id())) );
    listener_.object_version_visited(current_referenced_object_->getId(), current_object_version_);
    versions_.push_back(current_object_version_);
    current_object_version_.reset();
    LOG(INFO, "Object version visited : %s\n", TO_STRING(YaToolObjectId_To_StdString(current_referenced_object_->getId())));

}

void SingleObjectVisitor::visit_end_deleted_object()
{
    LOG(INFO, "Object version visited(deleted) : %s\n", TO_STRING(YaToolObjectId_To_StdString(current_referenced_object_->getId())));
    listener_.deleted_object_version_visited(current_referenced_object_->getId());
    current_referenced_object_.reset();
    versions_.clear();
}

void SingleObjectVisitor::visit_end_default_object()
{
    LOG(INFO, "Object version visited(default) : %s\n", TO_STRING(YaToolObjectId_To_StdString(current_referenced_object_->getId())));
    listener_.default_object_version_visited(current_referenced_object_->getId());
    current_referenced_object_.reset();
    versions_.clear();
}

void SingleObjectVisitor::visit_end_reference_object()
{
    current_referenced_object_.reset();
    versions_.clear();
}
