#!/usr/bin/env bash

version=$(go tool dist version)
release=$(wget -qO- "https://golang.org/VERSION?m=text")

if [[ $version == "$release" ]]; then
    echo "The local Go version ${release} is up-to-date."
    exit 0
else
    echo "The local Go version is ${version}. A new release ${release} is available."
fi

release_file="${release}.linux-amd64.tar.gz"

tmp=$(mktemp -d)
cd $tmp || exit 1

echo "Downloading https://go.dev/dl/$release_file ..." 
curl -OL https://go.dev/dl/$release_file

rm -f ${HOME}/go 2>/dev/null

tar -C ${HOME}/ -xzf $release_file
rm -rf $tmp

mv ${HOME}/go ${HOME}/apps/$release
ln -sf ${HOME}/$release ${HOME}/apps/go

version=$(go tool dist version)
echo "Now, local Go version is $version"
