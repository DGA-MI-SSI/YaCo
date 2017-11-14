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
%include <stdint.i>
%include <std_shared_ptr.i>

namespace std
{
	%template (StringVector) vector<string>;
}

%{
#include <exception>
#include <stdint.h>
#include <memory>

//in pro.h, they forbid use of some functions that SWIG needs : use them anyway and f*** ida!
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#include <pro.h>
#include <kernwin.hpp>

#include "ExporterValidatorVisitor.hpp"
#include "FlatBufferDatabaseModel.hpp"
#include "FlatBufferExporter.hpp"
#include "git_version.h"
#include "HObject.hpp"
#include "IDANativeExporter.hpp"
#include "IDANativeModel.hpp"
#include "IModelAccept.hpp"
#include "IModelVisitor.hpp"
#include "Logger.h"
#include "Merger.hpp"
#include "Model.hpp"
#include "MultiplexerDelegatingVisitor.hpp"
#include "PathDebuggerVisitor.hpp"
#include "RepoManager.hpp"
#include "ResolveFileConflictCallback.hpp"
#include "Signature.hpp"
#include "XML/XMLDatabaseModel.hpp"
#include "XML/XMLExporter.hpp"
#include "YaGitLib.hpp"
#include "Yatools_swig.h"
#include "YaToolsHashProvider.hpp"
#include "YaTypes.hpp"
%}

/**
YaToolObjectId_From_String compute an ID from a string, we need to pass the string length
*/
%apply (char *STRING, size_t LENGTH) { (const char* input, size_t input_len) };
YaToolObjectId YaToolObjectId_From_String(const char* input, size_t input_len);

%shared_ptr(IFlatExporter)
%shared_ptr(IHashProvider)
%shared_ptr(IModel)
%shared_ptr(IModelAccept)
%shared_ptr(IModelIncremental)
%shared_ptr(IModelVisitor)
%shared_ptr(IRepoManager)
%shared_ptr(Yatools)

%typemap(out) ExportedBuffer
{
	$result = PyBuffer_FromMemory(const_cast<void*>($1.value), $1.size);
}

%feature("director:except")
{
    if ($error != NULL)
    {
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
 		SWIG_fail;
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

%feature("director") IModelVisitor;
%feature("director") PromptMergeConflict;

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

%template () std::vector<ea_t>;

%typemap(typecheck) ea_t
{
    $1 = PyLong_Check($input) || PyInt_Check($input);
}

%typemap(in) ea_t {
        if (PyLong_Check($input))
            $1 = static_cast<ea_t>(PyLong_AsUnsignedLongLongMask($input));
        else if(PyInt_Check($input))
            $1 = static_cast<ea_t>(PyInt_AsUnsignedLongMask($input));
        else
            SWIG_exception_fail(SWIG_ValueError, "invalid ea_t value");
}

%typemap(directorin) ea_t {
        if (PyLong_Check($input))
            $1 = static_cast<ea_t>(PyLong_AsUnsignedLongLongMask($input));
        else if(PyInt_Check($input))
            $1 = static_cast<ea_t>(PyInt_AsUnsignedLongMask($input));
        else
            SWIG_exception_fail(SWIG_ValueError, "invalid ea_t value");
}

%typemap(out) ea_t {
#ifdef __EA64__
        $result = PyLong_FromUnsignedLongLong($1);
        Py_XINCREF($result);
#else
        $result = PyLong_FromUnsignedLong($1);
        Py_XINCREF($result);
#endif
}

%typemap(out)  std::vector< ea_t,std::allocator< ea_t > >
{
    $result = PyList_New(0);
    for(const auto element : $1)
    {
#ifdef __EA64__
        const auto obj = PyLong_FromUnsignedLongLong(element);
#else
        const auto obj = PyLong_FromUnsignedLong(element);
#endif
        Py_XINCREF(obj);
        PyList_Append($result, obj);
    }
}

namespace std
{
	%template (StringSet) std::set<std::string>;
}
%template () std::map<string,string>;

%feature("director") ResolveFileConflictCallback;

// interfaces first
%include "IModelAccept.hpp"
%include "IModel.hpp"
%include "IModelVisitor.hpp"

%include "ExporterValidatorVisitor.hpp"
%include "FlatBufferDatabaseModel.hpp"
%include "FlatBufferExporter.hpp"
%include "IDANativeExporter.hpp"
%include "IDANativeModel.hpp"
%include "Logger.h"
%include "Merger.hpp"
%include "Model.hpp"
%include "MultiplexerDelegatingVisitor.hpp"
%include "PathDebuggerVisitor.hpp"
%include "RepoManager.hpp"
%include "ResolveFileConflictCallback.hpp"
%include "XML/XMLDatabaseModel.hpp"
%include "XML/XMLExporter.hpp"
%include "YaGitLib.hpp"
%include "yatools_/git_version.h"
%include "Yatools_swig.h"
%include "YaToolsHashProvider.hpp"
%include "YaTypes.hpp"
