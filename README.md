# Covert-Security

This is the implementation for my master thesis in computer science about covert security. This project uses the [Crypto++ library](https://www.cryptopp.com/) and the [libOTe library](https://github.com/osu-crypto/libOTe) by Peter Rindal. The circuit files in the folder called circuits comes from [https://homes.esat.kuleuven.be/~nsmart/MPC/](https://homes.esat.kuleuven.be/~nsmart/MPC/) by David Archer, Victor Arribas Abril, Pieter Maene, Nele Mertens, Danilo Sijacic and Nigel Smart. The project requires an Intel processor since instructions from Intel are used to take advantage of the hardware. The guide was used from [https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf](https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf) by Shay Gueron. 

To run the project the main function takes 5 arguments: the filename, type, lambda, x and y.
