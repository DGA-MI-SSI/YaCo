# YaCo - Collaborative Reverse-Engineering for IDA
# YaDiff - Symbols Propagation between IDA databases

## [Latest Releases](https://github.com/DGA-MI-SSI/YaCo/releases)

## Yaco 

**YaCo** is a [**Hex-Rays IDA**](https://www.hex-rays.com/products/ida/) plugin enabling collaborative reverse-engineering on IDA databases for multiple users. Incremental database changes are stored & synchronized through **Git** distributed version control system.
Both offline & online work is supported.

### Motivation

**IDA** does not allow multiple users to work on the same binary.
During large malware analysis, we had to use a team of reversers and manual synchronization is a tedious and error-prone process. 

**YaCo** goals are:

  * Support all **IDA** events
  * Be fast, users must not wait for synchronisation events
  * Prevent conflicts between users
  * Be user-friendly & easy to install
  
## YaDiff 

**YaDiff** is a standalone command-line tool allowing symbol, comment, enum & struct propagation between distinct IDA databases.

### Motivation

There are two major use cases for YaDiff
    
  * Merging previously-analyzed binary symbols into an updated binary
  * Merging debug symbols from an external library into another stripped binary
    
### Usage

  * Uncompress the release into a directory
  * Put each of your two IDA databases in a different directory
  * Call merge_idb.py on those two databases
```
python $yatools_directory/YaTools/bin/merge_idb.py $source_dir/source.idb $destination_dir/destination.idb
```
  * Open ```$destination_dir/destination.yadiff_local.idb``` and check results

## Installation

### Debian stretch/x64

**YaTools** is 64-bit only, like **IDA** 7.1.

Install dependencies
```
sudo apt install build-essential git cmake python2.7 libpython2.7 libpython2.7-dev
```

Configure & build **YaTools**
```
export NUM_CPU=4
export IDA_DIR=/opt/ida7.1/
export IDASDK_DIR=/opt/idasdk71/
$yaco/build> ./configure.sh
$yaco/out/x64_RelWithDebInfo> make -j $NUM_CPU
$yaco/out/x64_RelWithDebInfo> ctest . --output-on-failure -C RelWithDebInfo -j $NUM_CPU
$IDA_DIR/plugins> $yaco/build/deploy.sh
```

### Windows

CMake & Python 2.7 64-bit must be installed and in the PATH
Only visual studio 2017 is currently supported

Configure and build **YaTools**
```
# export directories without quotes
set NUM_CPU=4
set IDA_DIR=C:\Program Files\IDA Pro 7.1
set IDASDK_DIR=C:\idasdk71
$yaco/build> configure_2017.cmd
$yaco/out/x64> cmake --build . --config RelWithDebInfo
$yaco/out/x64> ctest . --output-on-failure -C RelWithDebInfo -j %NUM_CPU%
$IDA_DIR/plugins> $yaco/build/deploy.cmd
```

## YaCo Usage

### First user
To create the **YaCo** environment:

  1. open binary or idb file as usual
  2. click on Edit menu, Plugins, YaCo
  3. enter path to Git remote (could be a file system path, or empty to use current dir)
  4. a warning will inform you that **IDA** have to be re-launch with correct idb
  5. **IDA** auto close
  6. launch **IDA** for your FILE_local.idb file
  7. save database
  8. start working as usual

Warning, in order to use it with multiple users, **YaCo** project must be in a bare Git repository.

### Other users
Setup **YaCo** environment:

  1. clone a **YaCo** project
  2. open idb/i64 file with ida
  3. click on Edit menu, Plugins, YaCo
  4. a warning will inform you that **IDA** has to be re-launched with correct idb
  5. **IDA** auto close
  6. launch **IDA** for your FILE_local.idb file
  7. save database
  8. start working as usual
  
### How it works
**YaCo** uses a Git server to synchronize changes between users.

In the local repository, **YaCo** stores the original IDB and incremental changes as xml files & commits.

Note that the database is not modified anymore unless you force a synchronisation.
When saving the database, we fetch remote changes, rebase local changes on top of those, import this new state into IDA and push this state to the remote Git server.

Any Git server should work, for example github, gitlab or gitea instances. Note that some Git hosts have a file size limit, which can be an issue for large IDB files. See [#13](https://github.com/DGA-MI-SSI/YaCo/issues/13).

Currently, **YaCo** only supports SSH authentication. To keep the plugin user-friendly, there is no mechanism asking for passwords & passphrases on every Git operation. Instead, it is recommended to use an ssh agent, like pageant under windows or ssh-agent under linux.

### How to use YaCo with git & SSH on Windows

You have a git repository, on github or equivalent

  * Clone the git repository ```git clone git@server_name:group_name/repo_name.git```
  * Import/generate your SSH key with puttygen.exe & save the private key into a ppk file
  * Associate your public key in your server profile
  * Start pageant.exe & add your ppk key
  * Try to connect once using bare SSH on your server with plink ```plink git@server_name:group_name/repo_name.git```
  * It should connect & exit immediately
  * Copy the file.idb into file_local.idb in the repository
  * Open file_local.idb with IDA & check YaCo is properly starting
  * Save the file once & check whether YaCo is able to fetch, rebase & push on the git server

## More

* __Developer__ : you can read the [Readme for developers](./doc/developer.md)

## Contributors

  * Benoît Amiaux
  * Frederic Grelot
  * Jeremy Bouetard
  * Martin Tourneboeuf
  * Maxime Pinard
  * Valerian Comiti

## License

YaCo is licensed under the GNU General Public License v3.0 that can be found in the LICENSE file
