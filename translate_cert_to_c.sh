#!/bin/sh
sed -i -e 's/$/\\r\\n"/g' $1
sed -i -e 's/^/"/g' $1
