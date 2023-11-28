# Makefile to install and configure tpm emulator to run Go test verifying Caliptra DPE commands with TPM policy Signing

SHELL := /bin/bash
SETUP_TPM_EMU_PATH := "/tmp/setup_tpm_emulator"
# Install tpm emulator dependencies
install_dependencies:
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

# Build and install tpm emulator
run_autogen_and_install:
	sudo rm -rf $(SETUP_TPM_EMU_PATH)
	mkdir $(SETUP_TPM_EMU_PATH) && cd $(SETUP_TPM_EMU_PATH); \
        git clone https://github.com/stefanberger/swtpm.git; \
	cd swtpm; \
	./autogen.sh --with-openssl --prefix=/usr; \
	make -j4; \
	make -j4 check; \
	sudo make install

# Install tpm2-tss
install_tpm2_tss:
	sudo apt-get install libjson-c-dev libssl-dev libcurl4-gnutls-dev -y
	cd $(SETUP_TPM_EMU_PATH); \
	wget https://github.com/tpm2-software/tpm2-tss/releases/download/3.1.0/tpm2-tss-3.1.0.tar.gz; \
	tar -xzvf tpm2-tss-3.1.0.tar.gz && cd tpm2-tss-3.1.0/ && ./configure && sudo make install && sudo ldconfig

# Install tpm2-tools
install_tpm2_tools:
	sudo apt-get install tpm2-tools

# The 'setup_tpm_emulator' target runs all steps in order
setup_tpm_emulator: install_dependencies run_autogen_and_install  install_tpm2_tss install_tpm2_tools
