# YaTools : Developper Manual




## YaTools

### Definitions

* __Flatbuffer__ : Flat dumping/buffering of dynamique (i.e. in RAM) structures
* __Visitor__: Some recursive structure crawler/parser. It calls a callback (called operand) for each (xref/function/bb/ea) found on objectId
* __Acceptor__: Visit with a `f_put_in_database` callback
* __ObjectId__ : Unique hash (integer) representing ida object (basic bloc, effective address) for easy indexing and retrieval
* __ObjectVersion__ : Ida object (can be any type defined in YaEnums.hpp) with its members (defined in HVersion) 

### Architecture

[File diagram here](./img/architecture_yatool.svg)

[Dynamic diagram here](./img/dynamic_yatool.jpg)

### Filesystem

```
├───bin                                 | Executable output
├───build                               | Build files (cmake)
├───deps                                | Dependencies library statically included
├───doc                                 | Documentation (here I am)
├───out                                 | Configuration (Visual Sutio) output folder
├───tests                               | Test script container
├───YaCo                                | YaCo python files
├───YaDiff                              | YaDiff cpp files
│   ├───tests                           |     tests
│   ├───merge_idb.py                    |     exe: idb1_new <- idb2_old : symbol propagation
│   ├───MergeYaDb.cpp                   |     exe: yadb1_new <- yadb2_old
│   └───YaDiffLib                       |     code (algo orchestator)
│       └───Algo                        |     algo container
├───YaLibs                              | Library used
│   ├───tests                           |     Test 
│   ├───YaToolsIDALib                   |     Code to communicate with IDA
│   ├───YaToolsLib                      |     YaCo code is here
│   │   ├───Events.cpp                  |         Implement event callbacks
│   │   ├───Hash.cpp                    |         Wraps some hashing primitives <- farmhash.h
│   │   ├───Hooks.cpp                   |         Bind callbacks (named) to addactions (in Ida.h)
│   │   ├───Ida.h                       |         Declare Idaapi (include other ida headers)
│   │   ├───IdaDeleter.cpp              |         Implement functions to delete some Ida structures
│   │   ├───IdaModel.cpp                |         Implement vistors and acceptors
│   │   ├───IdaVisitor.cpp              |         Implement callback on Idactions
│   │   ├───PluginArm.cpp               |         Helper: Arm thumb or not
│   │   ├───Plugins.hpp                 |         Declare visitors and acceptors
│   │   ├───Pool.hpp                    |         Helper: Declare allocators
│   │   ├───Repository.cpp              |         Manage yagit repository
│   │   ├───Strucs.cpp                  |         Implement structure and enum visitors
│   │   ├───YaCo.cpp                    |         Implement main synchronization routine
│   │   └───YaHelpers.cpp               |         Helpers for YaTools : ea -> strings for example
│   └───YaToolsPy                       |     YaCo code used to be here, now swig (python <-> cpp)
└───YaToolsUtils                        | Utility code (entry points) -> executable
    ├───YaToolsBasicBlockStripper       |     Strip Basic Bloc
    ├───YaToolsBinToVect                |     Bin -> Txt (containting function signatures as vectors)
    ├───YaToolsCacheMerger              |     1yadb + 2yadb -> yadb_merged
    ├───YaToolsFBToXML                  |     Flatbuffer -> Xml
    ├───YaToolsXMLToFB                  |     Xml -> Flatbuffer
    └───YaToolsYaDBToVectors            |     YaDb -> Vect
```

## YaCo

Yet Another COlaboration tool.

YaCo intercept and generate IDA events, share them thought git/network in order to maintain 2 similar idb for different users working on the same binary.


## YaDiff

Yet Another DIFFing software.

Takes as input 2 idbs: idb_new and idb_old.  
Fills the idb_new with symbols from idb_old.

### Architecture

[See diagram here](./img/architecture_yadiff.svg)

### More

* [YaDiff presentation at SSTIC 2018 (pdf)](presentation/2018_yadiff_sstic_presentation.pdf)
* [YaDiff short article at MISC 2018 (html)](presentation/2018_misc.htm)
