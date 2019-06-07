# YaTools : Developper Manual




## YaTools

### Definitions

* __Flatbuffer__ : flat dumping/buffering of dynamique (i.e. in RAM) structures
* __Visitor__: Some recursive structure crawler/parser

### Architecture

[See diagram here](./img/architecture_yatool.svg)

### Filesystem

```
├───bin                                 | Executable output
├───build                               | Build files (cmake)
├───deps                                | Dependencies library statically included
├───doc                                 | Documentation (here I am)
├───out                                 | Configuration (Visual Sutio) output folder
├───tests                               | Binaries to test (bin)
├───YaCo                                | YaCo python files
├───YaDiff                              | YaDiff cpp files
│   ├───tests                           |     tests
│   └───YaDiffLib                       |     code (algo orchestator)
│       └───Algo                        |     algo container
├───YaLibs                              | Library used
│   ├───tests                           |     Test 
│   ├───YaToolsIDALib                   |     Code to communicate with IDA
│   ├───YaToolsLib                      |     YaCo code is here
│   └───YaToolsPy                       |     YaCo code used to be here, now swig (python <-> cpp)
└───YaToolsUtils                        | Utility code (entry points)
    ├───YaToolsBasicBlockStripper       |     Strip Basic Bloc
    ├───YaToolsBinToVect                |     Bin -> Txt (containting function signatures as vectors)
    ├───YaToolsCacheMerger              |     1yadb + 2yadb -> yadb_merged
    ├───YaToolsFBToXML                  |     Flatbuffer -> Xml
    ├───YaToolsXMLToFB                  |     Xml -> Flatbuffer
    └───YaToolsYaDBToVectors            |     YaDb -> Vect
```

## YaCo


## YaDiff


### Architecture

[See diagram here](./img/architecture_yadiff.svg)
