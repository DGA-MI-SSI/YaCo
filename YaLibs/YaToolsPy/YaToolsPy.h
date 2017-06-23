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

%include "std_pair.i"
%include "std_string.i"
%include "std_map.i"
%include "std_multimap.i"
%include "std_set.i"
%include "cstring.i"

%include "std_vector.i"
%include "stl.i"

%include "YaTypes.hpp"
%{
#include <stdint.h>
#include "YaTypes.hpp"
%}

%template () std::pair<unsigned long long, int>;
%template () std::pair<unsigned long long, unsigned long long>;
%template () std::pair<long long unsigned int, unsigned long long>;
%template () std::pair<long long unsigned int, int>;
%template () std::map<std::pair<unsigned long long, int>,std::string>;
%template () std::map<std::pair<unsigned long long, unsigned long long>,std::string>;
%template () std::map<std::pair<long long unsigned int, int>,std::string>;
%template () std::map<std::pair<long long unsigned int, unsigned long long>,std::string>;
%template () std::map<long long,std::string>;
%template () std::map<int,std::pair<int,int> >;
%template () std::vector<unsigned char>;
%template () std::vector<unsigned int>;
%template () std::vector<unsigned long long>;
%template () std::vector<long long unsigned int>;
%template () std::vector<std::shared_ptr<IModelVisitor> >;
%template () std::set<unsigned long long>;

%template () std::pair<unsigned long int, int>;
%template () std::pair<unsigned long int, unsigned long long>;
%template () std::map<std::pair<unsigned long int, int>,std::string>;
%template () std::map<std::pair<unsigned long int, unsigned long long>,std::string>;
%template () std::map<long,std::string>;
%template () std::vector<unsigned long int>;

%template () std::map<string,string>;
namespace std
{
	%template (StringVector) vector<string>;
}

%{
#include "Yatools_swig.h"
#include "Logger.h"
%}

%include "Yatools_swig.h"
%include "Logger.h"

%typemap(in) offset_t
{
	//printf("converting from 64b addr\n");
	if (PyLong_Check($input))
	{
		$1 = (offset_t)PyLong_AsUnsignedLongLongMask($input);
	    if (PyErr_Occurred())
	    {
		    printf("PyErr_Occurred on long converting 0x%p", &*$input);
		}
	}
	else if(PyInt_Check($input))
	{
		$1 = PyInt_AsUnsignedLongMask($input);
	    if (PyErr_Occurred())
	    {
		    printf("PyErr_Occurred on int converting 0x%p", &*$input);
		}
	}
	else
	{
		printf("bad input : 0x%p\n", &*$input);
	}
}

%typemap(directorin) offset_t{
	//printf("converting from 64b addr\n");
	if (PyLong_Check($input))
	{
		$1 = (offset_t)PyLong_AsUnsignedLongLongMask($input);
	    if (PyErr_Occurred())
	    {
		    printf("PyErr_Occurred on long converting 0x%p", &*$input);
		}
	}
	else if(PyInt_Check($input))
	{
		$1 = PyInt_AsUnsignedLongMask($input);
	    if (PyErr_Occurred())
	    {
		    printf("PyErr_Occurred on int converting 0x%p", &*$input);
		}
	}
	else
	{
		printf("bad input : 0x%p\n", &*$input);
	}
}


%typemap(out) offset_t
{
	//printf("converting from 64b addr\n");
	$result = PyLong_FromUnsignedLongLong((unsigned long long) $1);
	Py_XINCREF($result);
}


//get_xrefed_id_map
%typemap(out) std::map< std::pair< offset_t,operand_t >,std::vector< XrefedId_T,std::allocator< XrefedId_T > >,std::less< std::pair< offset_t,operand_t > >,std::allocator< std::pair< std::pair< offset_t,operand_t > const,std::vector< XrefedId_T,std::allocator< XrefedId_T > > > > > const & 
{
    $result = PyDict_New();
    for(const auto& it : *$1)
    {
    	offset_t ea = (it).first.first;
    	operand_t operand = (it).first.second;
    	auto list_val = PyList_New(0);
    	for (const XrefedId_T& elem : (it).second)
    	{
	    	YaToolObjectId xref_id = elem.object_id;
	    	auto py_id = PyLong_FromUnsignedLongLong(xref_id);
	    	
	    	const std::map<std::string, std::string>& attributes = elem.attributes;
	    	auto py_attributes = PyDict_New();
	    	for(const auto& it_attr : attributes)
	    	{
	    		PyDict_SetItem(py_attributes, SWIG_From_std_string(it_attr.first), SWIG_From_std_string(it_attr.second)); 
	    	}
	    	
	    	auto tuple_entry = PyTuple_New(2);
	    	PyTuple_SetItem(tuple_entry, 0, py_id);
	    	PyTuple_SetItem(tuple_entry, 1, py_attributes);
	    	
	    	PyList_Append(list_val, tuple_entry);
	    }
	    
    	auto tuple_key = PyTuple_New(2);
        PyTuple_SetItem(tuple_key, 0, PyLong_FromUnsignedLongLong(ea));
    	PyTuple_SetItem(tuple_key, 1, PyLong_FromLong(operand));

    	PyDict_SetItem($result, tuple_key, list_val);
    }
}
 
%typemap(in) (const void* blob, size_t len) {
  if (!PyByteArray_Check($input)) {
    SWIG_exception_fail(SWIG_TypeError, "in method '" "$symname" "', argument "
                       "$argnum"" of type '" "$type""'");
  }
  $1 = PyByteArray_AsString($input);
  $2 = PyByteArray_Size($input);
}
 
%typemap(directorin) (const void* blob, size_t len) {
  if (!PyByteArray_Check($input)) {
    Swig::DirectorException::raise("in method '" "$symname" "', argument "
                       "$argnum"" of type '" "$type""'");
  }
  $1 = PyByteArray_AsString($input);
  $2 = PyByteArray_Size($input);
}

%cstring_output_allocate_size(char **buffer, size_t *len, free(*$1));
%apply (char *STRING, size_t LENGTH) { (char *str, size_t len) };


/**
for YaToolObjectId_To_String : the caller needs to allocate a buffer (enventually in stack) and pass it as 
argument to the function, along with its length.
The buffer length must be >=YATOOL_OBJECT_ID_STR_LEN+1, which is also enough
The first instruction tells SWIG to allocate a buffer in stack and use is as parameter
The second instruction tells it to use a constant as second argument, with value fixed to YATOOL_OBJECT_ID_STR_LEN+1
*/
%cstring_bounded_output(char* YaToolObjectId_output, YATOOL_OBJECT_ID_STR_LEN)
%typemap(in, numinputs=0) size_t YaToolObjectId_output_len {
    $1 = YATOOL_OBJECT_ID_STR_LEN+1;
}
void YaToolObjectId_To_String(char* YaToolObjectId_output, size_t YaToolObjectId_output_len, YaToolObjectId id);

/**
YaToolObjectId_From_String compute an ID from a string, we need to pass the string length
*/
%apply (char *STRING, size_t LENGTH) { (const char* input, size_t input_len) };
YaToolObjectId YaToolObjectId_From_String(const char* input, size_t input_len);

%include <stdint.i>
%include <std_shared_ptr.i>

%shared_ptr(Hashable)
%shared_ptr(Comparable)
%shared_ptr(Comparable<ObjectSignature>)
%shared_ptr(Comparable<YaToolObjectVersion>)
%shared_ptr(Comparable<YaToolReferencedObject>)
%shared_ptr(Comparable<VersionRelation>)
%shared_ptr(ObjectSignature)
%shared_ptr(CRC32FunctionSignature)
%shared_ptr(IModelAccept)
%shared_ptr(IModelIncremental)
%shared_ptr(IModelVisitor)
%shared_ptr(IFlatExporter)
%shared_ptr(IModel)
%shared_ptr(IObjectVisitorListener)
%shared_ptr(YaToolObjectVersion)
%shared_ptr(YaToolReferencedObject)
%shared_ptr(VersionRelation)
%shared_ptr(Yatools)
%shared_ptr(IDeleter)
 
%typemap(in) const const_string_ref& (const_string_ref temp)
{
	if(PyByteArray_Check($input))
	{
		temp = const_string_ref{PyByteArray_AsString($input), static_cast<size_t>(PyByteArray_Size($input))};
		$1 = &temp;
	}
	else if(PyString_Check($input))
	{
		temp = const_string_ref{PyString_AsString($input), static_cast<size_t>(PyString_Size($input))};
		$1 = &temp;
	}
	else
	{
		SWIG_exception_fail(SWIG_TypeError, "in method '" "$symname" "', argument "
			"$argnum"" of type '" "$type""'");
	}
}

%typemap(directorin) const const_string_ref&
{
	$input = PyByteArray_FromStringAndSize($1.value, $1.size);
}

%typemap(out) const_string_ref
{
	$result = PyByteArray_FromStringAndSize($1.value, $1.size);
}

%typemap(out) ExportedBuffer
{
	$result = PyBuffer_FromMemory(const_cast<void*>($1.value), $1.size);
}

%typemap(out) std::unordered_map< YaToolObjectId, std::shared_ptr< YaToolReferencedObject > > const &
{
	$result = PyList_New(0);
	for (auto element : *$1)
	{
	    std::shared_ptr<  YaToolReferencedObject > *smartresult = new std::shared_ptr<  YaToolReferencedObject >(element.second);
    	auto thisobj = SWIG_NewPointerObj(SWIG_as_voidptr(smartresult), SWIGTYPE_p_std__shared_ptrT_YaToolReferencedObject_t, SWIG_POINTER_OWN);
        PyList_Append($result, thisobj);
    }
}  

%typemap(out) std::unordered_set< std::shared_ptr< YaToolObjectVersion > > const &
{
	$result = PyList_New(0);
	for (auto element : *$1)
	{
	    std::shared_ptr<  YaToolObjectVersion > *smartresult = new std::shared_ptr<  YaToolObjectVersion >(element);
    	auto thisobj = SWIG_NewPointerObj(SWIG_as_voidptr(smartresult), SWIGTYPE_p_std__shared_ptrT_YaToolObjectVersion_t, SWIG_POINTER_OWN);
        PyList_Append($result, thisobj);
    }
	//using typemap
}                       


%template () std::vector<YaToolObjectId>;
%template () std::set<YaToolObjectId>;
%{
#include "Comparable.hpp"
#include "Hashable.hpp"
#include "Signature.hpp"
#include "IModelAccept.hpp"
#include "IModelVisitor.hpp"
#include "ExporterValidatorVisitor.hpp"
#include "MultiplexerDelegatingVisitor.hpp"
#include "PathDebuggerVisitor.hpp"
#include "XML/XMLDatabaseModel.hpp"
#include "XML/XMLExporter.hpp"
#include "FlatBufferExporter.hpp"
#include "FlatBufferDatabaseModel.hpp"
#include "StdModel.hpp"
#include "IObjectVisitorListener.hpp"
#include "YaToolObjectId.hpp"
#include "YaToolObjectVersion.hpp"
#include "YaToolReferencedObject.hpp"
#include "HObject.hpp"
#include "DependencyResolverVisitor.hpp"
#include "VersionRelation.hpp"
#include "Merger.hpp"
#include <exception>
#include "git_version.h"
%}

%feature("director:except") {
    if ($error != NULL) {
//    	PyErr_Print();
//  	PyObject *ptype;
//  	PyObject *pvalue;
//  	PyObject *ptraceback;
//    	PyErr_Fetch(&ptype, &pvalue, &ptraceback);
    	//PyObject_CallMethod(ptraceback, const_cast<char*>("print_exc"), NULL); 
        throw Swig::DirectorMethodException();
    }
}

%exception {
 	try {
		$action	
	} catch(const char *exc) {
		PyErr_SetString(PyExc_RuntimeError, const_cast<char*>(exc));
		return NULL;
	} catch(const Swig::DirectorException& /*exc*/) {
//		PyErr_SetString(PyExc_RuntimeError, const_cast<char*>(exc.getMessage()));
 		SWIG_fail;
//		return NULL;
	} catch(const std::exception& exc) {
		PyErr_SetString(PyExc_RuntimeError, const_cast<char*>(exc.what()));
		return NULL;
	} catch(const std::string& exc) {
		PyErr_SetString(PyExc_RuntimeError, const_cast<char*>(exc.c_str()));
		return NULL;
 	} catch( ... ) {
		PyErr_SetString(PyExc_RuntimeError, const_cast<char*>("an unexpected error occured (default message)"));
 		return NULL;
 	}
 }

%include "Hashable.hpp"
%include "Comparable.hpp"
%template (ComparableYaToolObjectVersion) Comparable<YaToolObjectVersion>;
%template (ComparableYaToolReferencedObject) Comparable<YaToolReferencedObject>;
%template (ComparableVersionRelation) Comparable<VersionRelation>;
%include "Signature.hpp"

%feature("director") IModelVisitor;
%feature("director") IObjectVisitorListener;
%feature("director") PromptMergeConflict;
%include "IModelVisitor.hpp"
%include "ExporterValidatorVisitor.hpp"
%include "IModelAccept.hpp"

%include "YaToolObjectId.hpp"
%include "YaToolObjectVersion.hpp"

%include "IObjectVisitorListener.hpp"

%include "MultiplexerDelegatingVisitor.hpp"
%include "PathDebuggerVisitor.hpp"
%include "DependencyResolverVisitor.hpp"
%include "IModel.hpp"
%include "XML/XMLExporter.hpp"
%include "FlatBufferExporter.hpp"
%include "FlatBufferDatabaseModel.hpp"
%include "StdModel.hpp"
%include "yatools_/git_version.h"

%pythonprepend MakeXmlFilesDatabaseModel %{
    if len(files) > 0 :
        if(isinstance(files, list)):
            files = StringVector(files)
        elif(isinstance(files, set)):
            files = StringVector(list(files))
        else:
            files = StringVector(list())
    else:
        files = StringVector()
%}
%include "XML/XMLDatabaseModel.hpp"



%include "YaToolObjectId.hpp"
%include "YaToolObjectVersion.hpp"
%include "YaToolReferencedObject.hpp"

%include "VersionRelation.hpp"
%include "Merger.hpp"

// include other yatools python modules
%include "YaIDAPy.h"
%include "YaGitPy.h"
