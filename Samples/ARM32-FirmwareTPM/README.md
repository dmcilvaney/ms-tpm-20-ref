# MS-IoT fTPM
## Trusted firmware for Windows based AArch32 (32-bit) ARM SoC's
Please see the build-firmware.md document in project-kayla (**UPDATE**) for information on including this TA in an IoTCore image.

## Included TAs

### fTPM TA
The fTPM Trusted Application (TA) provides a secure firmware implementation of a TPM using the MS reference implementation.
Platform specific code is copied and modified locally in optee_ta/fTPM/platform. /fTPM/reference contains files to support WolfSSL, control the fTPM's functionality, and define basic types, which may not be found in OpTEE.

See the reference implementation documentation for more details.

## Extra Installation Steps
The secure firmware utilizes the OpTEE implementation of the Global Platform specifications. The OpTEE project is
not duplicated in this repository but is obtained directly from the public release. The build of OpTEE is based on a
native Linux build however the following installation steps allow OpTEE to be built under Windows using WSL. Only the optee_os
repository is relevant for trusted firmware use - the optee_client & optee_linuxdriver repositories are integration
components for Linux and can serve as a reference for the Windows equivalent components. Note that optee_linuxdriver
is GPL.

OpTEE generates a build environment for trusted applications which is based on Make (See TA_DEV_KIT_DIR in the build directions).
This build environment places several constraints on how the code is organized, which are explained in the relevent makefiles.
See https://github.com/OP-TEE/optee_os/blob/master/documentation/build_system.md for details about how OpTEE build works.

---
#### 1. Enable Windows Subsystem for Linux
See instructions at https://docs.microsoft.com/en-us/windows/wsl/install-win10

#### 2. Launch Bash
Search for "bash" in the start menu, OR press Windows key + 'R', then type bash.

#### 3. Install the ARM tool chain
Install the ARM toolchain to a directory of your choice.

In WSL:
```
cd ~
mkdir toolchains
wget https://releases.linaro.org/components/toolchain/binaries/6.4-2017.11/arm-linux-gnueabihf/gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz
tar xf gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz
rm gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabihf.tar.xz
```

#### 4. Clone the OpTEE OS source code (if you don't have a copy)
If you do not already have a version of the ms-iot OpTEE OS repo cloned on your machine you may run:
```
$ cd ~
$ mkdir devel
$ cd devel
$ git clone https://github.com/ms-iot/optee_os.git
```
 (**UPDATE**)

#### 5. Build OpTEE OS for the target platform
TA_CROSS_COMPILE should point to the ARM toolchain installed in step 3.
```
$ cd ~/devel/optee_os
$ CROSS_COMPILE=~/toolchains/gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabihf/bin/arm-linux-gnueabihf- make PLATFORM=imx-mx6qhmbedge CFLAGS="-fshort-wchar" platform-cflags="-fshort-wchar" CFG_NS_ENTRY_ADDR=0x10820000 CFG_TEE_CORE_LOG_LEVEL=4 CFG_REE_FS=n CFG_RPMB_FS=y CFG_RPMB_TESTKEY=y CFG_RPMB_WRITE_KEY=y CFG_TA_HELLO_WORLD=y -j20
```
Additional information on ms-iot OpTEE OS can be found at https://github.com/ms-iot/optee_os. (**UPDATE**)

CFG_NS_ENTRY_ADDR may be different for various boards:
```
PLATFORM=imx-mx6qhmbedge CFG_NS_ENTRY_ADDR=0x10820000
```
```
PLATFORM=imx-mx6qsabresd CFG_NS_ENTRY_ADDR=0x10820000
```

#### 6. Clone the ms-tpm-20-ref source code
```
$ cd ~/devel
$ git clone https://github.com/Microsoft/ms-tpm-20-ref.git
```
 (**UPDATE**)

#### 7. Initialize the git submodules
```
$ cd ~/devel/ms-tpm-20-ref
$ git submodule init
$ git submodule update
```

## Building the TPM

#### 1. Build the Firmware TPM Trusted Application
TA_CROSS_COMPILE should point to the ARM toolchain installed in step 3.

TA_DEV_KIT_DIR should point to the directory the optee_os TA devkit was compiled to in step 6.

-j increases the parallelism of the build process.

```
$ cd ~/devel/ms-tpm-20-ref/Samples/ARM32-FirmwareTPM/optee_ta
$ TA_CPU=cortex-a9 TA_CROSS_COMPILE=~/toolchains/gcc-linaro-6.4.1-2017.11-x86_64_arm-linux-gnueabihf/bin/arm-linux-gnueabihf- TA_DEV_KIT_DIR=~/devel/optee_os/out/arm-plat-imx/export-ta_arm32 CFG_TEE_TA_LOG_LEVEL=2 make -j20
```
Debugging options you may want to add:

CFG_TEE_TA_LOG_LEVEL=3  "1" is fatal errors only, other values increase debug tracing output.

CFG_TA_DEBUG=y          Turns on debug output from the TAs, and enables extra correctness checks in the fTPM TA.

### Notes about building OpTEE for the IMX platform flavors:
The build options are:

"CFG_TEE_CORE_LOG_LEVEL" defines the tracing level for the optee OS. "1" is fatal errors only, other values increase debug tracing output.

"CFG_RPMB_TESTKEY" defines that the ONE TIME PROVSIONED test key should be used. In the production environment with the SoC hardware ID defined this option is not required.
 
"CFG_RPMB_RESET_FAT" defines that the RPMB storage should be cleared out on boot. This is provided to allow recovery from corrupt storage or to get back to a 1st boot state.

"CFG_RPMB_WRITE_KEY" defines that first provisioning is enabled.
