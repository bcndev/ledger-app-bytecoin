# ledger-app-bytecoin

## Prerequisites

* Ubuntu Linux 16.04 x86-64

## Environment preparing (done once)
```
sudo apt update
sudo apt install gcc-multilib g++-multilib git libusb-1.0-0-dev python python-pip libudev-dev
mkdir -p ~/bolos-devenv
cd ~/bolos-devenv
git clone https://github.com/LedgerHQ/nanos-secure-sdk.git
wget https://launchpad.net/gcc-arm-embedded/5.0/5-2016-q1-update/+download/gcc-arm-none-eabi-5_3-2016q1-20160330-linux.tar.bz2
wget http://releases.llvm.org/4.0.0/clang+llvm-4.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz
tar xvfj gcc-arm-none-eabi-5_3-2016q1-20160330-linux.tar.bz2
tar xvfJ clang+llvm-4.0.0-x86_64-linux-gnu-ubuntu-16.04.tar.xz
mv clang+llvm-4.0.0-x86_64-linux-gnu-ubuntu-16.04 clang-arm-fropi
pip install --user ledgerblue
echo "SUBSYSTEMS==\"usb\", ATTRS{idVendor}==\"2c97\", ATTRS{idProduct}==\"0001\", MODE=\"0660\", GROUP=\"plugdev\"" | sudo tee -a /etc/udev/rules.d/20-hw1.rules
sudo udevadm trigger
sudo udevadm control --reload-rules
cd ~
git clone https://github.com/bcndev/ledger-app-bytecoin
cd ledger-app-bytecoin
```
## Building and deployment

* Attach a Ledger Nano S to a computer and enter your pin code.
* The following command builds and installs the Bytecoin app to the Ledger Nano S. Run it every time you want to rebuild and/or reinstall the Bytecoin app:
```
make BOLOS_ENV=~/bolos-devenv BOLOS_SDK=~/bolos-devenv/nanos-secure-sdk load
```
* Follow the instructions on the Ledger's screen to finish the installation procedure.
