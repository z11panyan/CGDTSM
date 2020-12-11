#!/bin/bash
# Copyright 2016 Google Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
DATADIR=./random
NSETS=5000
for i in $(seq 1 $NSETS); do
	dd if=/dev/urandom of=$DATADIR/random$i.bin bs=1024 count=10 >/dev/null 2>&1
done
