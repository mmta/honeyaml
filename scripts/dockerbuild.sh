#!/bin/bash

dir="./docker"
[ ! -e $dir ] && echo must be executed from app root directory. && exit 1

tmpctx=$dir/ctx
mkdir -p $tmpctx
rsync -vhra ./ $tmpctx/ --include='**.gitignore' --exclude='/.git' --filter=':- .gitignore' --delete-after

pkg="$tmpctx/Cargo.toml"
[ ! -f "$pkg" ] && echo $pkg isnt available && exit 1

version=$(grep version Cargo.toml | head -1 | cut -d\" -f2)

for v in name version; do
  declare "${v}=$(grep ${v} $pkg | head -1 | cut -d\" -f2)"
  [ "${!v}" = "null" ] && echo cant read $v && exit 1
done

cd $dir
base=mmta

docker build -f Dockerfile -t $base/$name:$version -t $base/$name:latest .

if [ "$1" = "push" ]; then
  echo pushing
  docker push $base/$name:$version
  docker push $base/$name:latest
fi
