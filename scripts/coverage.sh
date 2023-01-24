#!/bin/sh

mkdir -p ./coverage
exec cargo llvm-cov --lcov --output-path ./coverage/lcov.info
