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

#include "YaTypes.hpp"
#include "XmlAccept.hpp"
#include "IModelVisitor.hpp"
#include "IModel.hpp"
#include "XmlVisitor.hpp"
#include "FlatBufferModel.hpp"
#include "Yatools.hpp"
#include "FlatBufferVisitor.hpp"
#include "HVersion.hpp"

#include <string>
#include <chrono>
#include <iostream>
#include <memory>
#include <assert.h>
#include <functional>

#ifdef _MSC_VER
#   include <optional.hpp>
using namespace nonstd;
#else
#   include <experimental/optional>
using namespace std::experimental;
#endif

using namespace std;

void print_usage(char* name)
{
    std::cerr << "Usage: " << name << " OUTPUT_FILE INPUT_FILE [INPUT_FILE ...]" << std::endl;
    std::cerr << "\tOUTPUT_FILE:\t\toutput xml file" << std::endl;
    std::cerr << "\tINPUT_FILE:\t\tinput yadb file" << std::endl;

}

int main(int argc, char** argv)
{
    globals::InitFileLogger(*globals::Get().logger, stdout);

    globals::InitFileLogger(*globals::Get().logger, stdout);

    if (argc < 3)
    {
        fprintf(stderr, "Bad arguments\n"
                        "Usage :\n"
                        "basicblockstripper <flatbuffer_in> <flatbuffer_out>\n");
        exit(-1);
    }

    const auto db1 = MakeFlatBufferModel(argv[1]);


    const auto visitor = MakeFlatBufferVisitor();

    visitor->visit_start();
    db1->walk([&](const HVersion& version)
    {
        if (version.type() == OBJECT_TYPE_BASIC_BLOCK)
        {
            return WALK_CONTINUE;
        }
		if (version.type() != OBJECT_TYPE_FUNCTION)
		{
			version.accept(*visitor);
			return WALK_CONTINUE;
		}

		if (version.address() == 0x0000000000049310)
		{
			printf("in insert_special\n");
		}
		YaToolObjectId firstbb_id = 0;
   		version.walk_xrefs([&](offset_t offset, operand_t /*base_operand*/, YaToolObjectId base_id, const XrefAttributes* /*base_hattr*/)
		{
   			const auto& refed_obj = db1->get(base_id);
   			if(refed_obj.type() == OBJECT_TYPE_BASIC_BLOCK && (version.address() == refed_obj.address() || offset == 0))
			{
   				firstbb_id = base_id;
   				return WALK_STOP;
			}
   			return WALK_CONTINUE;
		});

   		const auto& firstbb = db1->get(firstbb_id);

        visitor->visit_start_version(version.type(), version.id());
        visitor->visit_size(version.size());
        visitor->visit_parent_id(version.parent_id());
        visitor->visit_address(version.address());

        if(firstbb.username().size > 0)
            visitor->visit_name(firstbb.username(), firstbb.username_flags());

        if(version.prototype().size > 0)
            visitor->visit_prototype(version.prototype());

        visitor->visit_flags(version.flags());

        const auto string_type = version.string_type();
        if(string_type != UINT8_MAX)
            visitor->visit_string_type(string_type);

        // signatures
        visitor->visit_start_signatures();

        version.walk_signatures([&](const HSignature& sig)
        {
            const auto& s = sig.get();
            visitor->visit_signature(s.method, s.algo, make_string_ref(s.buffer));
            return WALK_CONTINUE;
        });
        visitor->visit_end_signatures();

        if(version.header_comment(true).size > 0)
            visitor->visit_header_comment(true, version.header_comment(true));

        if(version.header_comment(false).size > 0)
            visitor->visit_header_comment(false, version.header_comment(false));

        // offsets
        if(version.has_comments() || version.has_value_views() || version.has_register_views() || version.has_hidden_areas())
        {
            visitor->visit_start_offsets();
            version.walk_comments([&](offset_t offset, CommentType_e this_type, const const_string_ref& this_comment)
			{
				visitor->visit_offset_comments(offset, this_type, this_comment);
				return WALK_CONTINUE;
			});
            version.walk_value_views([&](offset_t offset, operand_t operand, const const_string_ref& value)
			{
				visitor->visit_offset_valueview(offset, operand, value);
				return WALK_CONTINUE;
			});
            version.walk_register_views([&](offset_t offset, offset_t end, const const_string_ref& name, const const_string_ref& newname)
			{
				visitor->visit_offset_registerview(offset, end, name, newname);
				return WALK_CONTINUE;
			});
            version.walk_hidden_areas([&](offset_t offset, offset_t offset_end, const const_string_ref& value)
			{
				visitor->visit_offset_hiddenarea(offset, offset_end, value);
				return WALK_CONTINUE;
			});
            visitor->visit_end_offsets();
        }

        // xrefs
        visitor->visit_start_xrefs();
   		version.walk_xrefs([&](offset_t base_offset, operand_t base_operand, YaToolObjectId base_id, const XrefAttributes* base_hattr)
		{
   			const auto& refed_obj = db1->get(base_id);
   			if(refed_obj.type() != OBJECT_TYPE_BASIC_BLOCK)
			{
   	            visitor->visit_start_xref(base_offset, base_id, base_operand);
   	            version.walk_xref_attributes(base_hattr, [&](const const_string_ref& key, const const_string_ref& value)
   	            {
   	            	visitor->visit_xref_attribute(key, value);
   	            	return WALK_CONTINUE;
   	            });

   	            visitor->visit_end_xref();
   	            return WALK_CONTINUE;
			}

   			//For basic blocks : walk their xrefs and propagate them to this function object
   			refed_obj.walk_xrefs([&](offset_t offset, operand_t operand, YaToolObjectId id, const XrefAttributes* hattr)
			{
   				const auto& refed_obj_by_bb = db1->get(id);
   				if(refed_obj_by_bb.model_ == nullptr)
   					return WALK_CONTINUE;

   				if(refed_obj_by_bb.type() == OBJECT_TYPE_BASIC_BLOCK)
   				{
   					id = refed_obj_by_bb.parent_id();
   					if(id == version.id())
   						return WALK_CONTINUE;
   				}

				visitor->visit_start_xref(base_offset + offset, id, operand);
				if(version.address() == 0x0000000000049310 && id == 0x2DDCC3C2C42DFC06)
				{
					printf("plop");
				}
				version.walk_xref_attributes(hattr, [&](const const_string_ref& key, const const_string_ref& value)
				{
					visitor->visit_xref_attribute(key, value);
					return WALK_CONTINUE;
				});
				visitor->visit_end_xref();
   				return WALK_CONTINUE;
			});

            return WALK_CONTINUE;
        });
        visitor->visit_end_xrefs();

        // attributes
        version.walk_attributes([&](const const_string_ref& key, const const_string_ref& val)
		{
        	visitor->visit_attribute(key, val);
			return WALK_CONTINUE;
		});

        // blobs
        version.walk_blobs([&](offset_t offset, const void* data, size_t len)
		{
        	visitor->visit_blob(offset, data, len);
			return WALK_CONTINUE;
		});

        visitor->visit_end_version();

        return WALK_CONTINUE;
    });
    visitor->visit_end();



    // export buffer to file
    const auto buf = visitor->GetBuffer();
    FILE* fh = fopen(argv[2], "wb");
    if(!fh)
        return false;
    const auto size = fwrite(buf.value, buf.size, 1, fh);
    if(size != 1)
    {
    	printf("ERR:%s", strerror(errno));
    }
    const auto err = fclose(fh);
    if(err)
    {
    	printf("ERR:%s", strerror(errno));
    }
    return size != 1 || err;

}

