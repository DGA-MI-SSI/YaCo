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

%shared_ptr(IModelAccept)
%shared_ptr(IModelIncremental)
%shared_ptr(IModelVisitor)
%shared_ptr(IFlatExporter)
%shared_ptr(IModel)
%shared_ptr(Yatools)
%shared_ptr(IDeleter)
 
%typemap(out) ExportedBuffer
{
	$result = PyBuffer_FromMemory(const_cast<void*>($1.value), $1.size);
}

%{
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
#include "Model.hpp"
#include "YaToolObjectId.hpp"
#include "HObject.hpp"
#include "VersionRelation.hpp"
#include "Merger.hpp"
#include <exception>
#include "git_version.h"
%}

%feature("director:except") {
    if ($error != NULL) {
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

%include "IModelVisitor.hpp"
%include "ExporterValidatorVisitor.hpp"
%include "IModelAccept.hpp"

%include "YaToolObjectId.hpp"

%include "MultiplexerDelegatingVisitor.hpp"
%include "PathDebuggerVisitor.hpp"
%include "IModel.hpp"
%include "XML/XMLExporter.hpp"
%include "FlatBufferExporter.hpp"
%include "FlatBufferDatabaseModel.hpp"
%include "Model.hpp"
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
%include "Merger.hpp"

%include "std_vector.i"
%include "stl.i"

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

%include <stdint.i>
%include <std_shared_ptr.i>

%shared_ptr(IExporter)

%{
//in pro.h, they forbid use of some functions that SWIG needs : use them anyway and f*** ida!
#define USE_DANGEROUS_FUNCTIONS

#include <memory>
#include <pro.h>
#include <kernwin.hpp>
#include "IDANativeExporter.hpp"
#include "IDANativeModel.hpp"

#include "YaToolsHashProvider.hpp"
#include <exception>

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
#include "YaToolObjectId.hpp"
#include "VersionRelation.hpp"


%}

%feature("director:except") {
    if ($error != NULL) {
//      PyErr_Print();
//      PyObject *ptype;
//      PyObject *pvalue;
//      PyObject *ptraceback;
//      PyErr_Fetch(&ptype, &pvalue, &ptraceback);
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

%include "IDANativeExporter.hpp"
%include "IDANativeModel.hpp"
%include "YaToolsHashProvider.hpp"

%include "std_string.i"
%include "std_map.i"
%include "std_set.i"
%include "std_vector.i"

%{
#include "YaGitLib.hpp"
#include "ResolveFileConflictCallback.hpp"
#include <exception>
%}

namespace std
{
	%template (StringSet) std::set<std::string>;
}
%template () std::map<string,string>;

%feature("director:except") {
    if ($error != NULL) {
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
%feature("director") ResolveFileConflictCallback;

%include "YaGitLib.hpp"
%include "ResolveFileConflictCallback.hpp"
