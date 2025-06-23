#!/usr/bin/sh

mkdir -p testrepo || exit 1
cp ./.gitignore testrepo

cd testrepo || exit 1
test -d .git || git init

touch -- -blob
touch 1blob
touch []
touch []blub
touch [blub
touch \\blub
touch ^blub
touch ablob
touch ablub
touch b
touch bblob
touch bblub
touch blab
touch blab\\
touch blabblab
touch blablab
touch blib
touch blub
