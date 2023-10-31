# DPE Verification Tests

This test suite is a userspace test-suite which exercises DPE commands end-to-end and ensures compliance with the DPE iRoT Profile.

## Requirements
* Ubuntu 20 LTS and above
* Golang >= 1.20
* Make
* Rustup, RustC >= 1.70

## Setting up Caliptra DPE Simulator
```sh
git clone https://github.com/chipsalliance/caliptra-dpe.git
cd caliptra-dpe/simulator/
cargo build
cd ../verification
go test .
```

## Setting up TPM emulator
The Software TPM (emulator) is required to run a specific test that verifies Caliptra DPE flow with TPM emulator.
User may choose to configure test requirements either by using Makefile or through command line. 

### Setting up using Makefile
Users may use the target `setup_tpm_emulator` to install and configure TPM emulator.
```sh
# Navigate to verification folder if it is not the current directory
sudo make setup_tpm_emulator
```
### Setting up using command line
Users may use command line instead of Makefile to install and configure TPM emulator.   
If already configured using Makefile, this section shall be skipped and continue with section giving the steps to run the emulator. 

#### Install dependencies
Install the dependencies for software TPM installation. 
```sh
sudo apt-get update && \
sudo apt-get install dh-autoreconf libssl-dev \
	libtasn1-6-dev pkg-config libtpms-dev \
	net-tools iproute2 libjson-glib-dev \
	tar\
	wget\
	git\
	build-essential\
	linux-generic\
	libgnutls28-dev expect gawk socat \
	libseccomp-dev make -y
```
#### Build TPM emulator
Run autogen.sh, make, check, and install
```sh
export SETUP_TPM_EMU_PATH="/tmp/setup_tpm_emulator"
sudo rm -rf ${SETUP_TPM_EMU_PATH}
mkdir ${SETUP_TPM_EMU_PATH} && cd ${SETUP_TPM_EMU_PATH}
git clone https://github.com/stefanberger/swtpm.git
cd ${SETUP_TPM_EMU_PATH}/swtpm
./autogen.sh --with-openssl --prefix=/usr
make -j4
make -j4 check
sudo make install
```
#### Install TPM tools
- Install_tpm2_tss
```sh
sudo apt-get install libjson-c-dev libssl-dev libcurl4-gnutls-dev -y
cd ${SETUP_TPM_EMU_PATH}
wget https://github.com/tpm2-software/tpm2-tss/releases/download/3.1.0/tpm2-tss-3.1.0.tar.gz
tar -xzvf tpm2-tss-3.1.0.tar.gz && cd tpm2-tss-3.1.0/ && ./configure && sudo make install && sudo ldconfig
```
- Install tpm2-tools
```sh
sudo apt-get install tpm2-tools
```
### Run TPM emulator
- To run the Go test to verify TPM Policy Signing, start the TPM emulator.
- Open separate terminal instance and issue commands to start.
- When started properly it displays the path of TPM device file.
- Mostly, TPM device path is /dev/tpm0
```sh
mkdir -p /tmp/myvtpm
sudo modprobe tpm_vtpm_proxy
sudo swtpm chardev --vtpm-proxy --tpmstate dir=/tmp/myvtpm --tpm2 --ctrl type=tcp,port=2322     
```
### Run TPM policy signing test
- Open another instance of terminal.
- Run the go test.
```sh
cd caliptra-dpe/verification
sudo go test . -v -tpm-policy-signing-validation="enabled" -tpm-path="/dev/tpm0"
```
