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

#include "Ida.h"
#include "Hooks.hpp"

#include "Repository.hpp"
#include "YaToolsHashProvider.hpp"
#include "IModel.hpp"
#include "Model.hpp"
#include "IDANativeModel.hpp"
#include "XML/XMLExporter.hpp"
#include "Logger.h"
#include "Yatools.h"
#include "Utils.hpp"

#define MODULE_NAME "hooks"
#include "IDAUtils.hpp"

#include <memory>
#include <tuple>
#include <chrono>

#ifdef _MSC_VER
#   include <filesystem>
#else
#   include <experimental/filesystem>
#endif

namespace fs = std::experimental::filesystem;

namespace
{
    std::string get_cache_folder_path()
    {
        std::string cache_folder_path = get_path(PATH_TYPE_IDB);
        remove_substring(cache_folder_path, fs::path(cache_folder_path).filename().string());
        cache_folder_path += "cache";
        return cache_folder_path;
    }

    struct Hooks
        : public IHooks
    {

        Hooks(const std::shared_ptr<IHashProvider>& hash_provider, const std::shared_ptr<IRepository>& repo_manager);

        void save() override;

    private:
        void add_address_to_process(ea_t ea, const std::string& message);
        void save_structures(std::shared_ptr<IModelIncremental>& ida_model, IModelVisitor* memory_exporter);
        void save_enums(std::shared_ptr<IModelIncremental>& ida_model, IModelVisitor* memory_exporter);

        std::shared_ptr<IHashProvider> hash_provider_;
        std::shared_ptr<IRepository> repo_manager_;

        std::set<ea_t> addresses_to_process_;
        std::set<tid_t> structures_to_process_;
        std::map<tid_t, std::tuple<tid_t, ea_t>> structmember_to_process_; // map<struct_id, tuple<member_id, offset>>
        std::set<enum_t> enums_to_process_;
        std::map<ea_t, tid_t> enummember_to_process_;
        std::set<ea_t> comments_to_process_;
        std::set<std::tuple<ea_t, ea_t>> segments_to_process_; // set<tuple<seg_ea_start, seg_ea_end>>
    };
}

Hooks::Hooks(const std::shared_ptr<IHashProvider>& hash_provider, const std::shared_ptr<IRepository>& repo_manager)
    : hash_provider_{ hash_provider }
    , repo_manager_{ repo_manager }
{

}

void Hooks::save()
{
    const auto time_start = std::chrono::system_clock::now();

    std::shared_ptr<IModelIncremental> ida_model = MakeModelIncremental(hash_provider_.get());
    ModelAndVisitor db = MakeModel();

    db.visitor->visit_start();

    // add comments to adresses to process
    for (ea_t ea : comments_to_process_)
        add_address_to_process(ea, "Changed comment");

    // process structures
    save_structures(ida_model, db.visitor.get());

    // process enums
    save_enums(ida_model, db.visitor.get());

    // process addresses
    for (ea_t ea : addresses_to_process_)
        ida_model->accept_ea(*db.visitor, ea);

    // process segments
    for (const std::tuple<ea_t, ea_t>& segment_ea : segments_to_process_)
        ida_model->accept_segment(*db.visitor, std::get<0>(segment_ea));

    db.visitor->visit_end();

    db.model->accept(*MakeXmlExporter(get_cache_folder_path()));

    const auto time_end = std::chrono::system_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(time_end - time_start);
    IDA_LOG_INFO("Saved in %lld seconds", elapsed.count());
}

void Hooks::add_address_to_process(ea_t ea, const std::string& message)
{
    addresses_to_process_.insert(ea);
    repo_manager_->add_auto_comment(ea, message);
}

void Hooks::save_structures(std::shared_ptr<IModelIncremental>& ida_model, IModelVisitor* memory_exporter)
{
    // structures: export modified ones, delete deleted ones
    for (tid_t struct_id : structures_to_process_)
    {
        uval_t struct_idx = get_struc_idx(struct_id);
        if (struct_idx != BADADDR)
        {
            // structure or stackframe modified
            ida_model->accept_struct(*memory_exporter, BADADDR, struct_id);
            continue;
        }

        // structure or stackframe deleted
        // need to export the parent (function)
        ea_t func_ea = get_func_by_frame(struct_id);
        if (func_ea != BADADDR)
        {
            // if stackframe
            ida_model->accept_struct(*memory_exporter, func_ea, struct_id);
            ida_model->accept_ea(*memory_exporter, func_ea);
            continue;
        }
        // if structure
        ida_model->delete_struct(*memory_exporter, struct_id);
    }

    // structures members : update modified ones, remove deleted ones
    for (const std::pair<const tid_t, std::tuple<tid_t, ea_t>>& struct_info : structmember_to_process_)
    {
        tid_t struct_id = struct_info.first;
        ea_t member_offset = std::get<1>(struct_info.second);

        struc_t* ida_struct = get_struc(struct_id);
        uval_t struct_idx = get_struc_idx(struct_id);

        ea_t stackframe_func_addr = BADADDR;

        if (!ida_struct || struct_idx == BADADDR)
        {
            // structure or stackframe deleted
            ea_t func_ea = get_func_by_frame(struct_id);
            if (func_ea == BADADDR)
            {
                // if structure
                ida_model->delete_struct_member(*memory_exporter, BADADDR, struct_id, member_offset);
                continue;
            }
            // if stackframe
            stackframe_func_addr = func_ea;
            ida_model->accept_function(*memory_exporter, stackframe_func_addr);
        }

        // structure or stackframe modified
        member_t* ida_member = get_member(ida_struct, member_offset);
        if (!ida_member || ida_member->id == -1)
        {
            // if member deleted
            ida_model->delete_struct_member(*memory_exporter, stackframe_func_addr, struct_id, member_offset);
            continue;
        }

        if (member_offset > 0)
        {
            member_t* ida_prev_member = get_member(ida_struct, member_offset - 1);
            if (ida_prev_member && ida_prev_member->id == ida_member->id)
            {
                // if member deleted and replaced by member starting above it
                ida_model->delete_struct_member(*memory_exporter, stackframe_func_addr, struct_id, member_offset);
                continue;
            }
        }

        // if member updated
        ida_model->accept_struct_member(*memory_exporter, stackframe_func_addr, ida_member->id);
    }
}

void Hooks::save_enums(std::shared_ptr<IModelIncremental>& ida_model, IModelVisitor* memory_exporter)
{
    // enums: export modified ones, delete deleted ones
    for (enum_t enum_id : enums_to_process_)
    {
        uval_t enum_idx = get_enum_idx(enum_id);
        if (enum_idx == BADADDR)
        {
            // enum deleted
            ida_model->delete_enum(*memory_exporter, enum_id);
            continue;
        }

        // enum modified
        ida_model->accept_enum(*memory_exporter, enum_id);
    }

    // not implemented in Python, TODO after porting to C++ events
    // enums members : update modified ones, remove deleted ones
    /*
    iterate over members :
        -if the parent enum has been deleted, delete the member
        -otherwise, detect if the member has been updated or removed
            -updated : accept enum_member
            -removed : accept enum_member_deleted
    */
}


std::shared_ptr<IHooks> MakeHooks(const std::shared_ptr<IHashProvider>& hash_provider, const std::shared_ptr<IRepository>& repo_manager)
{
    return std::make_shared<Hooks>(hash_provider, repo_manager);
}
