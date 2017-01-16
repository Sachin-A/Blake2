#Blake2b
Basic implementation of Blake2b in C as a base for Argon2 for Mozilla's Network Security Services.

##Getting started
In order to clone the source code

    git clone https://github.com/Sachin-A/Blake2.git

##Build instructions for test file

### Build requirements
1. Install gyp 
     
        sudo apt-get install gyp

2. Install ninja 
 
        sudo apt-get install ninja

### Steps
1. Change into the blake2b directory
    
        cd Blake2/blake2b

2. Generate ninja build file through gyp

        gyp blake2b.gyp --depth=. --generator-output=release -f ninja

3. Produce the executable *blake2b* by running ninja

        ninja -C ./release/out/Default/ all

### Running known answer tests

      ./release/out/Default/blake2b
