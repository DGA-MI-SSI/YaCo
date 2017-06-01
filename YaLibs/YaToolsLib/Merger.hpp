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

#include "HVersion.hpp"
#include "VersionRelation.hpp"

#include <set>

/*
 * Merge conflict prompt callback.
 * When a conflict rises up, we have to call a callback to prompt user for resolving conflict.
 */
class PromptMergeConflict
{
public:
    PromptMergeConflict() { }
    virtual ~PromptMergeConflict() { }

    virtual std::string merge_attributes_callback(const char * message_info, const char* input_attribute1, const char* input_attribute2) = 0;
};

/**
 * Merge strategy during merge of two ObjectVersion
 */
enum ObjectVersionMergeStrategy_e
{
    OBJECT_VERSION_MERGE_PROMPT = 0, /* prompt user if a conflict appears */
    OBJECT_VERSION_MERGE_FORCE_REFERENCE, /* use local infos and overwrite remote infos */
    OBJECT_VERSION_MERGE_FORCE_NEW, /* use remote infos and overwrite local infos */
    OBJECT_VERSION_MERGE_IGNORE, /* don't fix conflict */
};

/**
 * Object Merge Flags
 */
enum MergeStatus_e
{
    OBJECT_MERGE_STATUS_NOT_UPDATED           = 0x00,
    OBJECT_MERGE_STATUS_LOCAL_UPDATED         = 0x01,
    OBJECT_MERGE_STATUS_REMOTE_UPDATED        = 0x10,
    OBJECT_MERGE_STATUS_BOTH_UPDATED          = 0x11,
};

#define OBJECT_MERGE_STATUS_IS_LOCAL_UPDATED(X)     (X && OBJECT_MERGE_STATUS_LOCAL_UPDATED)
#define OBJECT_MERGE_STATUS_IS_REMOTE_UPDATED(X)    (X && OBJECT_MERGE_STATUS_REMOTE_UPDATED)


enum PromptMergeConflictResult_e
{
    PROMPT_MERGE_CONFLICT_SOLVED = 0,
    PROMPT_MERGE_CONFLICT_UNSOLVED
};

class Merger
{
public:
    Merger(PromptMergeConflict* MergePrompt, ObjectVersionMergeStrategy_e MergeStrategy);

    MergeStatus_e mergeObjectVersions( IModelVisitor& visitor_db, std::set<YaToolObjectId>& newObjectIds,
                                                            const Relation& relation);
    void mergeAttributes(const std::string& attribute_name, const const_string_ref& ref_attr, const const_string_ref& new_attr,
                                 const std::function<void(const const_string_ref&)>& fnCallback);
    MergeStatus_e smartMerge(   const char* input_file1, const char* input_file2,
                                const char* output_file_result);

private:
    PromptMergeConflict*            mpMergePrompt;
    ObjectVersionMergeStrategy_e    mMergeStrategy;
};

