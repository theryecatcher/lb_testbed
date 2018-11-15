# lb_testbed
Load Balancer Testbed based on DPDK

### Compiling the Application
1. Download it to you local workspace.
2. Make sure you have DPDK installed and have the below set
```
export RTE_SDK=<DPDKInstallDir>
export RTE_TARGET=x86_64-native-linuxapp-gcc
```
3. Change to the downloaded directory and run `make clean && make`

### Running the Application
The application needs a few command line options as below
```
./lb_testbed [EAL options] -- -p PORTMASK --config(port,queue,lcore)[,(port,queue,lcore)]
```    
For Example:
```
./build/lb_testbed -l 0 -n 4 -- -p 0x1 --config="(0,0,0)"
```
#### EAL Options
These are the normal ones that need to be provided with any dpdk base application.
