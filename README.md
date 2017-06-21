## Synopsis
**YaCo** is an [**Hex-Rays IDA**](https://www.hex-rays.com/products/ida/) plugin.
When enabled, multiple users can work simultaneously on the same binary.
Any modification done by any user is synchronized through **git** version control.

## Motivation
**IDA** does not allow multiple users to work on the same binary.
During large malware analysis, we had to use a team of reversers and manual synchronization is a tedious and error-prone process. 

**YaCo** goals are:

  * to support all **IDA** events (renaming, structure mapping, ...)
  * to be fast (users do not want to wait when working)
  * to prevent conflicts between user modifications
  * to be easy to setup and easy to use

## Installation

### Debian stretch/x64
As **IDA** is a 32bits software, **YaCo** must be built for 32 bits architecture.

Install dependencies
```
sudo apt install build-essential cmake gcc-multilib g++-multilib
```

Add i386 architecture and install dependencies
```
sudo dpkg --add-architecture i386
sudo apt update
sudo apt install binutils:i386
sudo apt install gcc:i386
sudo apt install g++:i386
sudo apt install libpython2.7-dev:i386
```

Set IDA_DIR & IDASDK_DIR environment variables
```
export IDA_DIR=/opt/ida6.8/
export IDASDK_DIR=/opt/idasdk/
```

Clone, configure & build **YaCo**
```
~/YaCo (master) $ cd build
~/YaCo/build (master) $ ./configure.sh
~/YaCo/build (master) $ pushd ../out/x86_64_Release
~/YaCo/out/x86_64_Release (master) $ make -j4
~/YaCo/out/x86_64_Release (master) $ pushd $IDA_DIR/plugin
$IDA_DIR/plugin $ ~/YaCo/build/deploy.sh
```

### Windows

CMake must be installed and in the PATH
Only visual studio 2015 is currently supported

Configure and build **YaCo**
```
set IDA_DIR=/your/ida/directory
set IDASDK_DIR=/your/idasdk/directory
build> configure_2015.cmd
out/x86> cmake --build . --config RelWithDebInfo
out/x86> ctest . --output-on-failure -C RelWithDebInfo -j4
```

## Usage

### First user
To create the **YaCo** environment:

  1. open binary or idb file as usual
  2. click on Edit menu, Plugins, YaCo
  3. enter path to git remote (could be a file system path, or empty to use current dir)
  4. a warning will inform you that **IDA** have to be re-launch with correct idb
  5. **IDA** auto close
  6. launch **IDA** for your FILE_local.idb file
  7. save database
  8. start working as usual

Warning, to use with multiple user, **YaCo** project must be in a bare git project.

### Other users
Setup **YaCo** environment:

  1. clone a **YaCo** project
  2. open idb/i64 file with ida
  3. click on Edit menu, Plugins, YaCo
  4. a warning will inform you that **IDA** have to be re-launch with correct idb
  5. **IDA** auto close
  6. launch **IDA** for your FILE_local.idb file
  7. save database
  8. start working as usual


## Contributors

  * Benoît Amiaux
  * Frederic Grelot
  * Jeremy Bouetard
  * Martin Tourneboeuf
  * Valerian Comiti

## License

YaCo is licensed under the GNU General Public License v3.0 that can be found in the LICENSE file
