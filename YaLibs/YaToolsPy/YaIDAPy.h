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

%shared_ptr(YaToolsIDANativeLib)
%shared_ptr(IExporter)

%template () std::shared_ptr<YaToolsIDANativeLib>;
%template () std::vector<std::shared_ptr<YaToolsIDANativeLib> >;
%{
//in pro.h, they forbid use of some functions that SWIG needs : use them anyway and f*** ida!
#define USE_DANGEROUS_FUNCTIONS

#include <memory>
#include <pro.h>
#include <kernwin.hpp>
#include "YaToolsIDANativeLib.hpp"
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

%include "YaToolsIDANativeLib.hpp"
%include "IDANativeExporter.hpp"
%include "IDANativeModel.hpp"
%include "YaToolsHashProvider.hpp"
