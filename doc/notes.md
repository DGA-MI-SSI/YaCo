# Notes for YaDiff


## State of art

* Diaphora
    * python, sqlite, hand written (inteligent) discrimination
* Fcatalog
    * MinHash of n-grams of 4 next intructions
    * ! Must install both server and client
    * ! Different database for different architecture
    * ! For Linux
* Bmap
* BinDiff Zynamic
* TurboDiff
    * The fastest, open source
    * 3 metrics only :
        * Size
        * Checksum
        * Graph equation
    * Build to identify the security updates from the last version
* BitShred
    * Create overlapping shreds of (16) bytes -> Bloom Filter
    * Purposed for malware clustering
* SMIT
* BitBlaze
    * Purposed to see what was not pathed (do not contain a certain patch)
* SIGMA
* DarunGrim
    * Purposed for patches
    * Do not work anymore. Used to need server + client
* PatchDiff
* SimMetrics
* MOSSS
* Gorille
    * Isomorphisme de sous -sites
    * dans des graphes orienté étiquété (par la denrière instruction du bloque basique)
* BinClone
    * Locality Sensitive hashing; then calculate edit-distance
    * Maximal clone pairs (like `diff` command)
* BeaEngine
    * Karp-Rabin String machine, Bloom filter
* peHash
    * Purposed for malware clustering


## Usefull Algo

* B+ tree
* Hungarian algo
* Vantage point tree
* Longest common subsequence
* Levfenstein
* Edit distance
* Hamming distance
* n-grams, n-perm
* McCabe metric : 2 + (number of edges) - (number of nodes) [cyclomatic complexity ??]
* Locally senbsitive hash
* Cosine similarity mesure
* MinHash : Faster -> replaces Jaccard coefficiant



## TODO interface

* Colorier en vert et bleu et rouge
* Commencer par le versionning, benchmarking, debug, doc, test
* Output en python/numpy


## To sign

* Fct epilogue and startup
* Entropy
* Fct type : local, statically linked, dynamically linked
* Strings : number contains, hash of them
* Nb of references to data
* The 10 first immediates like `mov ax, 'a'` : keep only the low bytes
* Register flow graph, API call graph, structural flow (?) (SIGMA)
* Identifier les constantes (parfois pmarquantes)
* Number of variables used and set
