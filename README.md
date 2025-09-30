# PKCSExamples

Example code that demonstrates [PKCS#11 APIs](https://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html) using SoftHSMv2 as an HSM emulator.

## Setup
Install the following dependencies:
1. [SoftHSMv2](https://formulae.brew.sh/formula/softhsm#default)
2. [P11-Kit](https://formulae.brew.sh/formula/p11-kit)

If you have Homebrew installed, you can run `brew install softhsm p11-kit`.

- Run `softhsm2-util` and confirm SoftHSMv2 installed successfully.
- Run `softhsm2-util --init-token --free --label Token` to create a new token in an empty slot.
- Enter an easy to remember SO (Security Officer) PIN and User PIN (something like `1234` is fine).
- Run `softhsm2-util --show-slots` and copy the Slot number (above Slot info).
- Paste the slot number for the token you wish to use next to `#define SLOT` and the corresponding user pin next to `#define USER_PIN`.

## Issues
- If the compiler can't find the p11-kit headers, run `brew --prefix p11-kit` to find the path to the headers and update the Makefile accordingly. 
- If you're getting an error loading the SoftHSMv2 module, run `brew --prefix softhsm` to find the module path and update the module path in the code accordingly.

## Compilation
- Run `make digest` to compile the digest program and run it with `./digest`. The Makefile uses `gcc` to compile.
- If you want your IDE to recognize PKCS prototypes, add the p11-kit headers to your IDE's C include path.
