#!/usr/bin/bash
pip3 install -r requirements.txt # (tested versions indicated in requirements.txt)

install nodejs # (tested with 8.10.0)
install npm # (tested with 3.5.2)
cd pdg_generation && npm install escodegen && cd -; # (tested with 1.9.1)
cd classification  && npm install esprima && cd -; # (tested with 4.0.1)
