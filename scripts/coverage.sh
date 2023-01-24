#!/bin/sh

exec cargo llvm-cov --lcov --output-path ./coverage/lcov.info
