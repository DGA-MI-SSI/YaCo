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

#include "DependencyResolverVisitor.hpp"

#include "YaToolReferencedObject.hpp"
#include "YaToolObjectVersion.hpp"
#include "ExporterValidatorVisitor.hpp"
#include "PathDebuggerVisitor.hpp"
#include "MultiplexerDelegatingVisitor.hpp"
#include "PrototypeParser.hpp"
#include "DelegatingVisitor.hpp"
#include "IObjectVisitorListener.hpp"
#include "YaToolObjectId.hpp"
#include "Logger.h"
#include "Yatools.h"
#include "../Helpers.h"

#include <deque>
#include <functional>
#include <sstream>
#include <assert.h>
#include <unordered_map>
#include <unordered_set>

#if 0
#define LOG(LEVEL, FMT, ...) CONCAT(YALOG_, LEVEL)("dependency_resolver", (FMT), ## __VA_ARGS__)
#else
#define LOG(...)
#endif

namespace
{
typedef uint32_t resolver_object_idx_t;
static const uint32_t InvalidResolverObjectIdx = ~0u;

// order is critical
enum ObjectState_e
{
    OBJECT_STATE_UNSET,
    OBJECT_STATE_INVALIDATED,
    OBJECT_STATE_UNFLUSHED,
    OBJECT_STATE_TYPE_UNKNOWN,
    OBJECT_STATE_TYPE_KNOWN,
    OBJECT_STATE_VISITED,
    OBJECT_STATE_ORPHANED,
    OBJECT_STATE_WAITING_FOR_PARENT_ADDRESS,
    OBJECT_STATE_ADDRESS_RESOLVED,
    OBJECT_STATE_COMMIT,
    OBJECT_STATE_END,
    OBJECT_STATE_FLUSHED,
    OBJECT_STATE_UNREACHABLE,
    OBJECT_STATE_COUNT,
};

const struct { ObjectState_e State; char Name[32]; } gObjectStateStrings[] =
{
    {   OBJECT_STATE_UNSET,                     "TYPE_UNSET"                },
    {   OBJECT_STATE_INVALIDATED,               "INVALIDATED"               },
    {   OBJECT_STATE_UNFLUSHED,                 "UNFLUSHED"                 },
    {   OBJECT_STATE_TYPE_UNKNOWN,              "TYPE_UNKNOWN"              },
    {   OBJECT_STATE_TYPE_KNOWN,                "TYPE_KNOWN"                },
    {   OBJECT_STATE_VISITED,                   "VISITED"                   },
    {   OBJECT_STATE_ORPHANED,                  "ORPHANED"                  },
    {   OBJECT_STATE_WAITING_FOR_PARENT_ADDRESS,"WAITING_FOR_PARENT_ADDRESS"},
    {   OBJECT_STATE_ADDRESS_RESOLVED,          "ADDRESS_RESOLVED"          },
    {   OBJECT_STATE_COMMIT,                    "COMMIT"                    },
    {   OBJECT_STATE_END,                       "END"                       },
    {   OBJECT_STATE_FLUSHED,                   "FLUSHED"                   },
    {   OBJECT_STATE_UNREACHABLE,               "UNREACHABLE"               },
};
static_assert(COUNT_OF(gObjectStateStrings) == OBJECT_STATE_COUNT, "invalid number of states");

inline const char* resolver_object_state_to_str(ObjectState_e state)
{
    assert(state >= 0 && state < OBJECT_STATE_COUNT);
    assert(gObjectStateStrings[state].State == state);
    return gObjectStateStrings[state].Name;
}

inline std::ostream & operator<<(std::ostream& oss, ObjectState_e state)
{
    return oss << resolver_object_state_to_str(state);
}

struct DependencyResolverObject
{
    DependencyResolverObject(YaToolObjectId id, resolver_object_idx_t idx);

    std::shared_ptr<YaToolObjectVersion>                        object;
    std::unordered_map<resolver_object_idx_t, ObjectState_e>    dependencies;
    std::unordered_map<resolver_object_idx_t, ObjectState_e>    dependent_objects;
    std::unordered_map<resolver_object_idx_t, ObjectState_e>    flushed_dependent_objects;
    resolver_object_idx_t                                       idx;
    YaToolObjectId                                              id;
    YaToolObjectType_e                                          type;
    ObjectState_e                                               state;
    offset_t                                                    address;
    resolver_object_idx_t                                       parent_idx;
    bool                                                        is_flushed;
};

inline std::ostream & operator<<(std::ostream& oss, const DependencyResolverObject* object)
{
    return oss << "id=" << YaToolObjectId_To_StdString(object->id) << ", @=" << (void*) object->address << ", type=" << object->type << ", state=" << object->state;
}

inline std::ostream & operator<<(std::ostream& oss, const DependencyResolverObject& object)
{
    return oss << &object;
}

class DependencyResolverVisitor
    : public DelegatingVisitor
    , public IObjectVisitorListener
    , public IDeleter
{
public:
    DependencyResolverVisitor(const std::shared_ptr<IModelVisitor>& next_visitor);

    // IObjectVisitorListener
    void                        object_version_visited(YaToolObjectId object_id, const std::shared_ptr<YaToolObjectVersion>& object) override;
    void                        deleted_object_version_visited(YaToolObjectId object_id) override;
    void                        default_object_version_visited(YaToolObjectId object_id) override;

    // IDeleter
    void                        delete_objects                  (const std::vector<YaToolObjectId>& objects) override;
    void                        invalidate_objects              (const std::vector<YaToolObjectId>& objects, bool set_to_null) override;

    // IModelVisitor
    void                        visit_start                     () override;
    void                        visit_end                       () override;

private:
    void                        add_object_to_update_queue  (resolver_object_idx_t object);
    void                        send_object_to_next_visitor (const std::shared_ptr<YaToolObjectVersion>& object);
    void                        walk_waiting_objects        ();
    resolver_object_idx_t       get_resolver_object         (YaToolObjectId id);
    DependencyResolverObject&   get                         (resolver_object_idx_t idx);
    void                        set_object_type             (DependencyResolverObject& obj, YaToolObjectType_e type);
    void                        set_object_state            (DependencyResolverObject& obj, ObjectState_e new_state);
    bool                        try_go_next_state           (DependencyResolverObject& obj); // should eventually return ids of "notified objects"
    void                        resolve_object_address      (DependencyResolverObject& obj);
    void                        register_dependencies       (DependencyResolverObject& obj);
    void                        update_dependencies         (DependencyResolverObject& obj);
    bool                        dependencies_met            (DependencyResolverObject& obj);
    void                        flush_object                (DependencyResolverObject& obj);
    void                        invalidate_object           (DependencyResolverObject& obj, bool set_to_null);
    void                        flush_sub_objects           (DependencyResolverObject& obj);
    void                        set_parent_object           (DependencyResolverObject& obj, resolver_object_idx_t dep_idx);
    void                        add_dependency_to           (DependencyResolverObject& obj, DependencyResolverObject& dep, ObjectState_e state);
    void                        add_dependency_from         (DependencyResolverObject& obj, resolver_object_idx_t dep_idx, ObjectState_e state);
    void                        update_dependency_to        (DependencyResolverObject& obj, DependencyResolverObject& dep, ObjectState_e state);
    void                        update_dependency_from      (DependencyResolverObject& obj, resolver_object_idx_t dep_idx, ObjectState_e state);
    void                        remove_dependency_to        (DependencyResolverObject& obj, DependencyResolverObject& dep, ObjectState_e state);
    void                        remove_dependency_from      (DependencyResolverObject& obj, resolver_object_idx_t dep_idx, ObjectState_e state);
    void                        set_objects_to_notify       (DependencyResolverObject& obj);
    void                        set_object                  (DependencyResolverObject& obj, const std::shared_ptr<YaToolObjectVersion>& object);
    void                        release_object_resources    (DependencyResolverObject& obj);
    void                        flush_objects               ();

private:
    std::set<resolver_object_idx_t>                             objects_waiting_for_update;
    std::deque<DependencyResolverObject>                        object_pool;
    std::unordered_map<YaToolObjectId, resolver_object_idx_t>   all_objects;
    std::shared_ptr<IModelVisitor>                      next_visitor;
};

enum HasParent_e
{
    PARENT_NONE,
    PARENT_HAS,
};

enum SelfResolved_e
{
    UNRESOLVED,
    SELF_RESOLVED,
};

// In which state the objects should be sent to the next visitor
const struct
{
    YaToolObjectType_e  type;
    ObjectState_e       state;
    HasParent_e         parent;
    ObjectState_e       parent_required;
    SelfResolved_e      resolved;
}
gObjects[] =
{
    { OBJECT_TYPE_UNKNOWN,           OBJECT_STATE_UNREACHABLE,      PARENT_NONE, OBJECT_STATE_UNSET,            UNRESOLVED },
    { OBJECT_TYPE_BINARY,            OBJECT_STATE_COMMIT,           PARENT_NONE, OBJECT_STATE_UNSET,            SELF_RESOLVED },
    { OBJECT_TYPE_DATA,              OBJECT_STATE_COMMIT,           PARENT_HAS,  OBJECT_STATE_END,              UNRESOLVED },
    { OBJECT_TYPE_CODE,              OBJECT_STATE_COMMIT,           PARENT_HAS,  OBJECT_STATE_END,              UNRESOLVED },
    { OBJECT_TYPE_FUNCTION,          OBJECT_STATE_COMMIT,           PARENT_HAS,  OBJECT_STATE_END,              UNRESOLVED },
    { OBJECT_TYPE_STRUCT,            OBJECT_STATE_ADDRESS_RESOLVED, PARENT_NONE, OBJECT_STATE_UNSET,            SELF_RESOLVED },
    { OBJECT_TYPE_ENUM,              OBJECT_STATE_ADDRESS_RESOLVED, PARENT_NONE, OBJECT_STATE_UNSET,            SELF_RESOLVED },
    { OBJECT_TYPE_ENUM_MEMBER,       OBJECT_STATE_COMMIT,           PARENT_HAS,  OBJECT_STATE_ADDRESS_RESOLVED, SELF_RESOLVED },
    { OBJECT_TYPE_BASIC_BLOCK,       OBJECT_STATE_COMMIT,           PARENT_HAS,  OBJECT_STATE_END,              UNRESOLVED },
    { OBJECT_TYPE_SEGMENT,           OBJECT_STATE_COMMIT,           PARENT_HAS,  OBJECT_STATE_END,              UNRESOLVED },
    { OBJECT_TYPE_SEGMENT_CHUNK,     OBJECT_STATE_COMMIT,           PARENT_HAS,  OBJECT_STATE_END,              UNRESOLVED },
    { OBJECT_TYPE_STRUCT_MEMBER,     OBJECT_STATE_COMMIT,           PARENT_HAS,  OBJECT_STATE_ADDRESS_RESOLVED, SELF_RESOLVED },
    { OBJECT_TYPE_STACKFRAME,        OBJECT_STATE_COMMIT,           PARENT_HAS,  OBJECT_STATE_END,              UNRESOLVED },
    { OBJECT_TYPE_STACKFRAME_MEMBER, OBJECT_STATE_COMMIT,           PARENT_HAS,  OBJECT_STATE_END,              SELF_RESOLVED },
    { OBJECT_TYPE_REFERENCE_INFO,    OBJECT_STATE_COMMIT,           PARENT_NONE, OBJECT_STATE_ADDRESS_RESOLVED, SELF_RESOLVED },
};
static_assert(COUNT_OF(gObjects) == OBJECT_TYPE_COUNT, "invalid number of objects");

bool HasParent(YaToolObjectType_e type)
{
    assert(0 <= type && type < OBJECT_TYPE_COUNT);
    assert(gObjects[type].type == type);
    return gObjects[type].parent == PARENT_HAS;
}

ObjectState_e RequiredParentState(YaToolObjectType_e type)
{
    assert(0 <= type && type < OBJECT_TYPE_COUNT);
    assert(gObjects[type].type == type);
    return gObjects[type].parent_required;
}

bool IsSelfResolved(YaToolObjectType_e type)
{
    assert(0 <= type && type < OBJECT_TYPE_COUNT);
    assert(gObjects[type].type == type);
    return gObjects[type].resolved == SELF_RESOLVED;
}

const struct
{
    YaToolObjectType_e      type;
    struct
    {
        YaToolObjectType_e  type;
        ObjectState_e       state;
    }                       deps[8];
}
gXrefDependencies[] =
{
    {
        OBJECT_TYPE_UNKNOWN, {}
    },
    {
        OBJECT_TYPE_BINARY,
        {
            { OBJECT_TYPE_UNKNOWN,              OBJECT_STATE_TYPE_KNOWN },
            { OBJECT_TYPE_SEGMENT,              OBJECT_STATE_TYPE_KNOWN },
        }
    },
    {
        OBJECT_TYPE_DATA,
        {
            { OBJECT_TYPE_STRUCT,               OBJECT_STATE_END },
            { OBJECT_TYPE_UNKNOWN,              OBJECT_STATE_TYPE_KNOWN },
        }
    },
    {
        OBJECT_TYPE_CODE, {}
    },
    {
        OBJECT_TYPE_FUNCTION,
        {
            { OBJECT_TYPE_UNKNOWN,              OBJECT_STATE_TYPE_KNOWN },
            { OBJECT_TYPE_BASIC_BLOCK,          OBJECT_STATE_VISITED },
            { OBJECT_TYPE_STACKFRAME,           OBJECT_STATE_TYPE_KNOWN },
            { OBJECT_TYPE_STRUCT,               OBJECT_STATE_END },
        }
    },
    {
        OBJECT_TYPE_STRUCT,
        {
            { OBJECT_TYPE_UNKNOWN,              OBJECT_STATE_TYPE_KNOWN },
            { OBJECT_TYPE_STRUCT_MEMBER,        OBJECT_STATE_END },
        }
    },
    {
        OBJECT_TYPE_ENUM,
        {
            { OBJECT_TYPE_UNKNOWN,              OBJECT_STATE_TYPE_KNOWN },
            { OBJECT_TYPE_ENUM_MEMBER,          OBJECT_STATE_END },
        }
    },
    {
        OBJECT_TYPE_ENUM_MEMBER, {}
    },
    {
        OBJECT_TYPE_BASIC_BLOCK,
        {
            { OBJECT_TYPE_UNKNOWN,              OBJECT_STATE_TYPE_KNOWN },
            { OBJECT_TYPE_STRUCT,               OBJECT_STATE_END },
            { OBJECT_TYPE_STRUCT_MEMBER,        OBJECT_STATE_END },
            { OBJECT_TYPE_STACKFRAME,           OBJECT_STATE_END },
            { OBJECT_TYPE_DATA,                 OBJECT_STATE_ADDRESS_RESOLVED },
            { OBJECT_TYPE_FUNCTION,             OBJECT_STATE_ADDRESS_RESOLVED },
            { OBJECT_TYPE_ENUM,                 OBJECT_STATE_ADDRESS_RESOLVED },
            { OBJECT_TYPE_REFERENCE_INFO,       OBJECT_STATE_ADDRESS_RESOLVED },
        }
    },
    {
        OBJECT_TYPE_SEGMENT,
        {
            { OBJECT_TYPE_UNKNOWN,              OBJECT_STATE_TYPE_KNOWN },
            { OBJECT_TYPE_SEGMENT_CHUNK,        OBJECT_STATE_TYPE_KNOWN },
        }
    },
    {
        OBJECT_TYPE_SEGMENT_CHUNK,
        {
            { OBJECT_TYPE_UNKNOWN,              OBJECT_STATE_TYPE_KNOWN },
            { OBJECT_TYPE_FUNCTION,             OBJECT_STATE_TYPE_KNOWN },
            { OBJECT_TYPE_DATA,                 OBJECT_STATE_TYPE_KNOWN },
            { OBJECT_TYPE_CODE,                 OBJECT_STATE_TYPE_KNOWN },
        }
    },
    {
        OBJECT_TYPE_STRUCT_MEMBER,
        {
            { OBJECT_TYPE_STRUCT,               OBJECT_STATE_ADDRESS_RESOLVED },
            { OBJECT_TYPE_ENUM,                 OBJECT_STATE_END },
            { OBJECT_TYPE_UNKNOWN,              OBJECT_STATE_TYPE_KNOWN },
        }
    },
    {
        OBJECT_TYPE_STACKFRAME,
        {
            { OBJECT_TYPE_UNKNOWN,              OBJECT_STATE_TYPE_KNOWN },
            { OBJECT_TYPE_STACKFRAME_MEMBER,    OBJECT_STATE_VISITED },
        }
    },
    {
        OBJECT_TYPE_STACKFRAME_MEMBER,
        {
            { OBJECT_TYPE_STRUCT,               OBJECT_STATE_END },
            { OBJECT_TYPE_ENUM,                 OBJECT_STATE_END },
            { OBJECT_TYPE_UNKNOWN,              OBJECT_STATE_TYPE_KNOWN },
        }
    },
    {
        OBJECT_TYPE_REFERENCE_INFO, {}
    },
};
static_assert(COUNT_OF(gXrefDependencies) == OBJECT_TYPE_COUNT, "invalid number of xref dependencies");

const YaToolObjectType_e gFlushTypes[] =
{
    OBJECT_TYPE_BINARY,
    OBJECT_TYPE_STRUCT,
    OBJECT_TYPE_SEGMENT,
    OBJECT_TYPE_SEGMENT_CHUNK,
    OBJECT_TYPE_STACKFRAME,
    OBJECT_TYPE_FUNCTION,
    OBJECT_TYPE_DATA,
    OBJECT_TYPE_BASIC_BLOCK,
};

const struct
{
    YaToolObjectType_e in;
    YaToolObjectType_e out;
}
gKnownXrefedObjects[] =
{
    {OBJECT_TYPE_SEGMENT,       OBJECT_TYPE_SEGMENT_CHUNK},
    {OBJECT_TYPE_STACKFRAME,    OBJECT_TYPE_STACKFRAME_MEMBER},
    {OBJECT_TYPE_STRUCT,        OBJECT_TYPE_STRUCT_MEMBER},
    {OBJECT_TYPE_ENUM,          OBJECT_TYPE_ENUM_MEMBER},
};

const YaToolObjectType_e* FindKnownXrefedObject(YaToolObjectType_e type)
{
    assert(0 <= type && type < OBJECT_TYPE_COUNT);
    for(size_t i = 0; i < COUNT_OF(gKnownXrefedObjects); ++i)
        if(gKnownXrefedObjects[i].in == type)
            return &gKnownXrefedObjects[i].out;
    return nullptr;
}
}

DependencyResolverVisitor::DependencyResolverVisitor(const std::shared_ptr<IModelVisitor>& next_visitor)
    : next_visitor(next_visitor)
{
    add_delegate(MakeSingleObjectVisitor(*this));
}

DependencyResolverObject& DependencyResolverVisitor::get(resolver_object_idx_t idx)
{
    return object_pool[idx];
}

void DependencyResolverVisitor::delete_objects(const std::vector<YaToolObjectId>& objects)
{
    visit_start();
    for(const auto& id : objects)
    {
        auto it = all_objects.find(id);
        if(it != all_objects.end())
        {
            visit_start_deleted_object(get(it->second).type);
            visit_id(id);
            visit_end_deleted_object();
        }
        deleted_object_version_visited(id);
    }
    visit_end();
}
void DependencyResolverVisitor::invalidate_objects(const std::vector<YaToolObjectId>& objects, bool set_to_null)
{
    LOG(INFO, " object invalidating\n");
    for(const auto& id : objects)
    {
        auto obj_p = all_objects.find(id);

        if (obj_p == all_objects.end())
        {
            LOG(INFO, "invalidating missing object : %s\n", YaToolObjectId_To_StdString(id).data());
        }
        else
        {
            auto& obj = get(obj_p->second);
            invalidate_object(obj, set_to_null);
            set_object(obj, nullptr);
        }
    }

    LOG(INFO, " object invalidated, finished\n");
}

void DependencyResolverVisitor::object_version_visited(YaToolObjectId object_id, const std::shared_ptr<YaToolObjectVersion>& object)
{
    LOG(INFO, ":in  %s\n", YaToolObjectId_To_StdString(object_id).data());
    const auto idx = get_resolver_object(object_id);
    auto& obj = get(idx);

    set_object_type(obj, object->get_type());
    set_object(obj, object);

    objects_waiting_for_update.insert(idx);

    walk_waiting_objects();
    LOG(INFO, ":out %s\n", YaToolObjectId_To_StdString(object_id).data());
}

void DependencyResolverVisitor::deleted_object_version_visited(YaToolObjectId object_id)
{
    if(all_objects.erase(object_id) == 0)
    {
        LOG(INFO, "Trying to delete object %s which does not exist in dependency resolver object list\n", YaToolObjectId_To_StdString(object_id).data());
    }

}

void DependencyResolverVisitor::default_object_version_visited(YaToolObjectId object_id)
{
    UNUSED(object_id);
}

resolver_object_idx_t DependencyResolverVisitor::get_resolver_object(YaToolObjectId id)
{
    auto obj_p = all_objects.find(id);

    if (obj_p == all_objects.end())
    {
        LOG(INFO, "Creating object for %s\n", YaToolObjectId_To_StdString(id).data());
        resolver_object_idx_t new_object_idx = static_cast<resolver_object_idx_t>(object_pool.size());
        object_pool.emplace_back(id, new_object_idx);

        auto inserted = all_objects.insert(std::make_pair(id, new_object_idx));
        UNUSED(inserted);
        assert(inserted.second);
        add_object_to_update_queue(new_object_idx);
        LOG(INFO, "Object created : pool size=%zu\n", object_pool.size());
        return new_object_idx;
    }
    else
    {
        LOG(INFO, "Return already created for %s\n", YaToolObjectId_To_StdString(id).data());
        return obj_p->second;
    }
}

void DependencyResolverVisitor::visit_end()
{
    flush_objects();
    DelegatingVisitor::visit_end();
    next_visitor->visit_end();
}

void DependencyResolverVisitor::visit_start()
{
    next_visitor->visit_start();
    DelegatingVisitor::visit_start();
}

void DependencyResolverVisitor::flush_objects()
{
    LOG(INFO, "Flushing objects : first pass\n");
    //First, flush objects whose type is known but which are not loaded : they will never be.
    //For those, the flush order does not need to be enforced.
    for(const auto& item : all_objects)
    {
        auto& obj = get(item.second);
        if(obj.state == OBJECT_STATE_TYPE_KNOWN)
        {
            flush_object(obj);
        }
    }
    walk_waiting_objects();

    LOG(INFO, "Flushing objects : second pass\n");

    //Then, flush unknown children of objects, in correct order.
    for(size_t i = 0; i < COUNT_OF(gFlushTypes); ++i)
    {
        for(const auto& item : all_objects)
        {
            auto& obj = get(item.second);
            if(obj.type == gFlushTypes[i])
            {
                if(obj.state != OBJECT_STATE_TYPE_UNKNOWN && obj.state != OBJECT_STATE_END)
                {
                    flush_sub_objects(obj);
                }
            }
        }
        walk_waiting_objects();
    }

    for(const auto& item : all_objects)
    {
        auto& obj = get(item.second);
        if(obj.state != OBJECT_STATE_END && obj.state != OBJECT_STATE_FLUSHED)
        {
            YALOG_DEBUG(nullptr, "Warning : stalled object : %s\n", TO_STRING(obj));
        }
    }
}

void DependencyResolverVisitor::send_object_to_next_visitor(const std::shared_ptr<YaToolObjectVersion>& object)
{
    YALOG_DEBUG(nullptr, "sending object to next visitor (type: %x : %s)\n", object->get_type(), YaToolObjectId_To_StdString(object->get_id()).data());
    next_visitor->visit_start_reference_object(object->get_type());
    next_visitor->visit_id(object->get_id());
    object->accept(*next_visitor);
    next_visitor->visit_end_reference_object();
}

void DependencyResolverVisitor::add_object_to_update_queue(resolver_object_idx_t object)
{
    objects_waiting_for_update.insert(object);
}

void DependencyResolverVisitor::walk_waiting_objects()
{
//  const auto a = std::chrono::high_resolution_clock::now();
//  int subidx = 0;
//  int subidx2 = 0;
    while(objects_waiting_for_update.empty() == false)
    {
//      subidx++;
        //object_pool may be expanded during loop
        std::set<resolver_object_idx_t> objects_to_walk;
        objects_waiting_for_update.swap(objects_to_walk);
        for(const auto idx : objects_to_walk)
        {
            auto& obj = get(idx);
            const auto start_state = obj.state;
            while(try_go_next_state(obj))
                continue;

            if(obj.state == start_state)
                continue;

            set_objects_to_notify(obj);
        }

    }
}

DependencyResolverObject::DependencyResolverObject(YaToolObjectId id, resolver_object_idx_t idx)
    : idx       (idx)
    , id        (id)
    , type      (OBJECT_TYPE_UNKNOWN)
    , state     (OBJECT_STATE_UNSET)
    , address   (UNKNOWN_ADDR)
    , parent_idx(InvalidResolverObjectIdx)
    , is_flushed(false)
{
}

void DependencyResolverVisitor::set_object_state(DependencyResolverObject& obj, ObjectState_e new_state)
{
    LOG(INFO, "%s : changed state : %s --> %s (obj_type=%x)\n",
        YaToolObjectId_To_StdString(obj.id).data(),
        resolver_object_state_to_str(obj.state),
        resolver_object_state_to_str(new_state),
        obj.type
    );
    /*
     * state==OBJECT_STATE_END && new_state==OBJECT_STATE_TYPE_KNOWN
     * happens when we loop back the state machine
     */
    assert(obj.state < new_state || new_state==OBJECT_STATE_INVALIDATED);

    obj.state = new_state;

    switch (new_state)
    {
        case OBJECT_STATE_COUNT:
            assert(false);
            break;

        case OBJECT_STATE_UNSET:
        {
            break;
        }
        case OBJECT_STATE_INVALIDATED:
        {
            break;
        }
        case OBJECT_STATE_UNFLUSHED:
        {
            obj.is_flushed = false;
            for(const auto& elem : obj.flushed_dependent_objects)
            {
                invalidate_object(get(elem.first), false);
            }
            break;
        }
        case OBJECT_STATE_TYPE_UNKNOWN:
        {
            break;
        }
        case OBJECT_STATE_TYPE_KNOWN:
        {
            assert(obj.type != OBJECT_TYPE_UNKNOWN);
            break;
        }
        case OBJECT_STATE_VISITED:
        {
            assert(obj.object != nullptr);
            break;
        }
        case OBJECT_STATE_ORPHANED:
        {
            //In the "normal case", the parent will be notified of a state change of this child.
            //However, if the current object was previously invalidated, the parent is already present
            //In this case, we can directly go the the next state
            if(obj.parent_idx != InvalidResolverObjectIdx)
            {
                set_object_state(obj, OBJECT_STATE_WAITING_FOR_PARENT_ADDRESS);
            }
            break;
        }
        case OBJECT_STATE_WAITING_FOR_PARENT_ADDRESS:
        {
            assert(obj.parent_idx != InvalidResolverObjectIdx);
            auto& parent = get(obj.parent_idx);
            obj.object->set_parent_object_id(parent.id);
            //register as "listener" on parent state
            add_dependency_to(obj, parent, RequiredParentState(obj.type));
            break;
        }
        case OBJECT_STATE_ADDRESS_RESOLVED:
        {
            //resolve the address now that we have all the elements
            resolve_object_address(obj);
            //register as "listener" on dependencies
            register_dependencies(obj);
            break;
        }
        case OBJECT_STATE_COMMIT:
        {
            //see end of function
            break;
        }
        case OBJECT_STATE_END:
        {
            release_object_resources(obj);
            break;
        }
        case OBJECT_STATE_FLUSHED:
        {
            release_object_resources(obj);
            break;
        }
        case OBJECT_STATE_UNREACHABLE:
        {
            LOG(ERROR, "Error : reached the unreachable state\n");
            assert(false);
            break;
        }
    }

    if (obj.is_flushed == false && gObjects[obj.type].state == obj.state)
    {
        send_object_to_next_visitor(obj.object);
    }
}

bool DependencyResolverVisitor::try_go_next_state(DependencyResolverObject& obj)
{
    if (obj.is_flushed && obj.state != OBJECT_STATE_FLUSHED && obj.state != OBJECT_STATE_INVALIDATED)
    {
        set_object_state(obj, OBJECT_STATE_FLUSHED);
        return true;
    }

    switch (obj.state)
    {
        case OBJECT_STATE_UNSET:
        {
            set_object_state(obj, OBJECT_STATE_TYPE_UNKNOWN);
            return true;
        }
        case OBJECT_STATE_INVALIDATED:
        {
            if(obj.is_flushed)
            {
                set_object_state(obj, OBJECT_STATE_UNFLUSHED);
            }
            else
            {
                set_object_state(obj, OBJECT_STATE_TYPE_UNKNOWN);
            }
            return true;
        }
        case OBJECT_STATE_UNFLUSHED:
        {
            set_object_state(obj, OBJECT_STATE_TYPE_UNKNOWN);
            return true;
        }
        case OBJECT_STATE_TYPE_UNKNOWN:
        {
            if (obj.object != nullptr || obj.type != OBJECT_TYPE_UNKNOWN)
            {
                set_object_state(obj, OBJECT_STATE_TYPE_KNOWN);
                return true;
            }
            else
            {
                return false;
            }
            break;
        }
        case OBJECT_STATE_TYPE_KNOWN:
        {
            assert(obj.type != OBJECT_TYPE_UNKNOWN);
            if (obj.object != nullptr)
            {
                set_object_state(obj, OBJECT_STATE_VISITED);
                return true;
            }
            else
            {
                return false;
            }

            break;
        }
        case OBJECT_STATE_VISITED:
        {
            assert(obj.object != nullptr);

            if (HasParent(obj.type))
            {
                //has parent
                set_object_state(obj, OBJECT_STATE_ORPHANED);
                return true;
            }
            else
            {
                assert(IsSelfResolved(obj.type));
                //self resolved
                set_object_state(obj, OBJECT_STATE_ADDRESS_RESOLVED);
                return true;
            }
        }
        case OBJECT_STATE_ORPHANED:
        {
            if (obj.parent_idx != InvalidResolverObjectIdx)
            {
                set_object_state(obj, OBJECT_STATE_WAITING_FOR_PARENT_ADDRESS);
                return true;
            }
            else
            {
                return false;
            }
            break;
        }
        case OBJECT_STATE_WAITING_FOR_PARENT_ADDRESS:
        {
            assert(obj.parent_idx != InvalidResolverObjectIdx);
            auto& parent_obj = get(obj.parent_idx);
            if (parent_obj.state == OBJECT_STATE_ADDRESS_RESOLVED
             || parent_obj.state == OBJECT_STATE_COMMIT
             || parent_obj.state == OBJECT_STATE_END)
            {
                set_object_state(obj, OBJECT_STATE_ADDRESS_RESOLVED);
                return true;
            }
            else
            {
                return false;
            }
            break;
        }
        case OBJECT_STATE_ADDRESS_RESOLVED:
        {
            if (dependencies_met(obj))
            {
                set_object_state(obj, OBJECT_STATE_COMMIT);
                return true;
            }
            else
            {
                return false;
            }
            break;
        }
        case OBJECT_STATE_COMMIT:
        {
            set_object_state(obj, OBJECT_STATE_END);
            return true;
        }
        case OBJECT_STATE_END:
        {
            return false;
        }
        case OBJECT_STATE_FLUSHED:
        {
            return false;
        }
        case OBJECT_STATE_COUNT:
        case OBJECT_STATE_UNREACHABLE:
        {
            assert(false);
            return false;
        }
    }
    LOG(ERROR, "We should never reach this line, type=%x, state=%x\n", obj.type, obj.state);
    assert(false);
    return false;
}

void DependencyResolverVisitor::set_object(DependencyResolverObject& obj, const std::shared_ptr<YaToolObjectVersion>& object_p)
{
//  assert(object == nullptr);
//  assert(object_p != nullptr || object==nullptr);
    obj.object = object_p;
}

void DependencyResolverVisitor::set_object_type(DependencyResolverObject& obj, YaToolObjectType_e type)
{
    assert(type != OBJECT_TYPE_UNKNOWN);
    assert(obj.state!=OBJECT_STATE_TYPE_UNKNOWN || obj.type == OBJECT_TYPE_UNKNOWN);

    obj.type = type;
    add_object_to_update_queue(obj.idx);
}

void DependencyResolverVisitor::release_object_resources(DependencyResolverObject& obj)
{
    if(obj.state == OBJECT_STATE_END)
    {
        assert(obj.dependencies.empty());
    }
    else if(obj.state == OBJECT_STATE_FLUSHED)
    {

    }
    else
    {
        YALOG_ERROR(nullptr, "release_object_resources %p\n", this);
        assert(false);
    }

//  object = nullptr;
}


void DependencyResolverVisitor::resolve_object_address(DependencyResolverObject& obj)
{
    assert(obj.state == OBJECT_STATE_ADDRESS_RESOLVED);
    assert(obj.object != nullptr);

    if (IsSelfResolved(obj.type))
    {
        obj.address = obj.object->get_relative_object_address();
    }
    else
    {
        assert(obj.parent_idx != InvalidResolverObjectIdx);
        obj.address = get(obj.parent_idx).address + obj.object->get_relative_object_address();
    }

    obj.object->set_absolute_object_address(obj.address);
}

namespace
{
template<typename T>
ObjectState_e FindDependencies(const T& deps, YaToolObjectType_e type)
{
    for(size_t i = 0; deps[i].state; ++i)
        if(deps[i].type == type)
            return deps[i].state;
    return OBJECT_STATE_UNSET;
}

template<typename T>
bool HasStates(const T& deps)
{
    return deps->state != OBJECT_STATE_UNSET;
}
}

void DependencyResolverVisitor::register_dependencies(DependencyResolverObject& obj)
{
    assert(obj.object != nullptr);

    const auto& deps = gXrefDependencies[obj.type].deps;
    assert(gXrefDependencies[obj.type].type == obj.type);
    if(!HasStates(deps))
    {
        LOG(INFO, "No dependencies for object of type %x\n", obj.type);
        return;
    }

    const auto known_xrefed_type = FindKnownXrefedObject(obj.type);

    for (const auto& xrefed_id : obj.object->get_xrefed_ids())
    {
        auto xrefed_idx = get_resolver_object(xrefed_id);
        auto& xrefed_obj = get(xrefed_idx);
        if(known_xrefed_type)
        {
            set_object_type(xrefed_obj, *known_xrefed_type);
            if(IS_PARENT_OF(obj.type, *known_xrefed_type))
            {
                set_parent_object(xrefed_obj, obj.idx);
            }
        }

        if(const auto state = FindDependencies(deps, xrefed_obj.type))
            add_dependency_to(obj, xrefed_obj, state);
    }

    /**
     * Parse the prototype.
     * At export, the prototype is modified to add special markups that indicate the hashes of objects
     * it references.
     * This helps the DependencyResolverVisitor, since it can add dependencies to those object.
     */
    ParseProtoFromHashes(obj.object->get_prototype(), [&](const std::string& name, YaToolObjectId id)
    {
        UNUSED(name);
        LOG(DEBUG, "Prototype added dependency for name %s with id %s\n", name.data(), TO_STRING(YaToolObjectId_To_StdString(id)));

        auto xrefed_idx = get_resolver_object(id);
        auto& xrefed_obj = get(xrefed_idx);
        if(const auto state = FindDependencies(deps, xrefed_obj.type))
        {
            LOG(DEBUG, "    --> needed dependency state : %x\n", state);
            add_dependency_to(obj, xrefed_obj, state);
        }
        return WALK_CONTINUE;
    });
}

bool DependencyResolverVisitor::dependencies_met(DependencyResolverObject& obj)
{
    update_dependencies(obj);
    return obj.dependencies.empty();
}

void DependencyResolverVisitor::update_dependencies(DependencyResolverObject& obj)
{
    const auto& deps = gXrefDependencies[obj.type].deps;
    assert(gXrefDependencies[obj.type].type == obj.type);

    std::unordered_map<resolver_object_idx_t, ObjectState_e> dependencies_to_remove;
    std::unordered_map<resolver_object_idx_t, ObjectState_e> dependencies_to_update;

    for(const auto& it : obj.dependencies)
    {
        auto dep_idx = it.first;
        auto dep_state = it.second;
        auto& dep_obj = get(dep_idx);
        if(dep_obj.state < dep_state)
            continue;
        //The state has evolved!
        if(!HasStates(deps))
        {
            dependencies_to_remove.insert(it);
        }
        else
        {
            if(const auto new_state = FindDependencies(deps, dep_obj.type))
            {
                UNUSED(new_state);
                //TODO : this should be new_state instead of dependency_state
                if(dep_obj.state >= dep_state)
                {
                    dependencies_to_remove.insert(it);
                }
                else
                {
                    dependencies_to_update.insert(it);
                }
            }
            else
            {
                dependencies_to_remove.insert(it);
            }
        }

        if(IS_PARENT_OF(obj.type, dep_obj.type) && dep_obj.state <= OBJECT_STATE_ORPHANED)
        {
            set_parent_object(dep_obj, obj.idx);
        }
    }

    for(const auto& p : dependencies_to_remove)
    {
        remove_dependency_to(obj, get(p.first), p.second);
    }

    for(const auto& p : dependencies_to_update)
    {
        update_dependency_to(obj, get(p.first), p.second);
    }

}


void DependencyResolverVisitor::flush_object(DependencyResolverObject& obj)
{
    LOG(INFO, "object flushed : %p, %s\n", this, TO_STRING(YaToolObjectId_To_StdString(obj.id)));
    obj.is_flushed = true;
    add_object_to_update_queue(obj.idx);
}

void DependencyResolverVisitor::invalidate_object(DependencyResolverObject& obj, bool set_to_null)
{
    LOG(INFO, "object invalidated : %p\n", this);
    set_object_state(obj, OBJECT_STATE_INVALIDATED);
    if(set_to_null)
    {
        set_object(obj, nullptr);
    }
    add_object_to_update_queue(obj.idx);
}

void DependencyResolverVisitor::flush_sub_objects(DependencyResolverObject& obj)
{
    LOG(INFO, "flushing sub objects of %s\n", TO_STRING(YaToolObjectId_To_StdString(obj.id)));
    for(const auto& it : obj.dependencies)
    {
        auto dep_idx = it.first;
        auto& dep_obj = get(dep_idx);
        if(dep_obj.state == OBJECT_STATE_TYPE_UNKNOWN || dep_obj.state == OBJECT_STATE_TYPE_KNOWN)
        {
            flush_object(dep_obj);
        }
    }
}

/**
 * Set the parent of this object
 */
void DependencyResolverVisitor::set_parent_object(DependencyResolverObject& obj, resolver_object_idx_t new_idx)
{
    const auto debugCheck = [&]
    {
        auto& parent_obj = get(obj.parent_idx);
        auto& new_obj = get(new_idx);
        if(obj.parent_idx == InvalidResolverObjectIdx || parent_obj.id == new_obj.id)
            return;
        LOG(ERROR,
            "*****************************************************\n"
            "*****************************************************\n"
            "**********  set_parent_object assert failed  ********\n"
            "*****************************************************\n"
            "*****************************************************\n"
            "id:%s\n"
            "parent_idx.is_valid():%s\n"
            "obj->id:%s\n"
            "parent_obj->id:%s\n"
            "*obj->id:%s\n"
            "parent_obj->id == obj->id=%s\n"
            "*****************************************************\n"
            "*****************************************************\n"
            "**********  set_parent_object assert failed  ********\n"
            "*****************************************************\n"
            "*****************************************************\n",
            TO_STRING(YaToolObjectId_To_StdString(obj.id)),
            TO_STRING(obj.parent_idx != InvalidResolverObjectIdx),
            TO_STRING(YaToolObjectId_To_StdString(obj.id)),
            TO_STRING(YaToolObjectId_To_StdString(parent_obj.id)),
            TO_STRING(YaToolObjectId_To_StdString(obj.id)),
            TO_STRING(parent_obj.id == obj.id)
        );
    };
#if DEBUG
    debugCheck();
#else
    UNUSED(debugCheck);
#endif

    assert(new_idx != InvalidResolverObjectIdx);
    obj.parent_idx = new_idx;
    add_object_to_update_queue(obj.idx);
}

/**
 * Add a new dependency to this object.
 * this will call add_dependency on the object, and add the object in an internal list.
 */
void DependencyResolverVisitor::add_dependency_to(DependencyResolverObject& obj, DependencyResolverObject& dep, ObjectState_e state)
{
    assert(dep.idx != InvalidResolverObjectIdx);
    add_dependency_from(dep, obj.idx, state);
    obj.dependencies.insert(std::make_pair(dep.idx, state));
}

void DependencyResolverVisitor::add_dependency_from(DependencyResolverObject& obj, resolver_object_idx_t dep_idx, ObjectState_e state)
{
    assert(dep_idx != InvalidResolverObjectIdx);
    obj.dependent_objects[dep_idx] = state;
}

void DependencyResolverVisitor::update_dependency_to(DependencyResolverObject& obj, DependencyResolverObject& dep, ObjectState_e state)
{
    assert(dep.idx != InvalidResolverObjectIdx);
    update_dependency_from(dep, obj.idx, state);
    obj.dependencies[dep.idx] = state;
}

void DependencyResolverVisitor::update_dependency_from(DependencyResolverObject& obj, resolver_object_idx_t dep_idx, ObjectState_e state)
{
    assert(dep_idx != InvalidResolverObjectIdx);
    obj.dependent_objects[dep_idx] = state;
}

void DependencyResolverVisitor::remove_dependency_to(DependencyResolverObject& obj, DependencyResolverObject& dep, ObjectState_e state)
{
    assert(dep.idx != InvalidResolverObjectIdx);
    remove_dependency_from(dep, obj.idx, state);
    obj.dependencies.erase(dep.idx);
}

void DependencyResolverVisitor::remove_dependency_from(DependencyResolverObject& obj, resolver_object_idx_t dep_idx, ObjectState_e state)
{
    UNUSED(state);
    assert(dep_idx != InvalidResolverObjectIdx);
    if(obj.state == OBJECT_STATE_FLUSHED)
    {
        const auto& it = obj.dependent_objects.find(dep_idx);
        if(it != obj.dependent_objects.end())
        {
            obj.flushed_dependent_objects[it->first] = it->second;
            obj.dependent_objects.erase(dep_idx);
        }
    }
    else
    {
        obj.dependent_objects.erase(dep_idx);
    }
}

void DependencyResolverVisitor::set_objects_to_notify(DependencyResolverObject& obj)
{
    LOG(INFO, "%s getting objects to notify\n", YaToolObjectId_To_StdString(obj.id).data());
    for(const auto& dependency : obj.dependent_objects)
    {
        assert(dependency.first != InvalidResolverObjectIdx);

        if(obj.state >= dependency.second)
        {
            LOG(INFO, "%s notifies %s (new state : %x, required : %x)\n",
                YaToolObjectId_To_StdString(obj.id).data(),
                YaToolObjectId_To_StdString(get(dependency.first).id).data(),
                obj.state, dependency.second);
            objects_waiting_for_update.insert(dependency.first);
        }
    }
}

DependencyResolver MakeDependencyResolverVisitor(const std::shared_ptr<IModelVisitor>& visitor)
{
    const auto ptr = std::make_shared<DependencyResolverVisitor>(visitor);
    return DependencyResolver{ptr, ptr};
}

DependencyResolver MakeDependencyResolverVisitor(IObjectVisitorListener& listener, bool validate, const std::string& name)
{
    auto object_visitor = MakeSingleObjectVisitor(listener);
    if(!validate)
        return MakeDependencyResolverVisitor(object_visitor);

    auto exporter = MakeExporterValidatorVisitor();
    auto validator = MakePathDebuggerVisitor(name, exporter, PrintValues);
    auto multi_visitor = std::make_shared<DelegatingVisitor>();
    multi_visitor->add_delegate(validator);
    multi_visitor->add_delegate(object_visitor);
    return MakeDependencyResolverVisitor(multi_visitor);
}
