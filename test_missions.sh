#!/bin/bash

for f in "$@"; do
    base_f=$(basename "$f")
    tmpname=$(mktemp --suffix="-$base_f")
    # Workaround comparators containing "<" (technically invalid XML, but
    # Artemis allows it).
    sed 's/"</"\&lt;/g' "$f" > "$tmpname"
    jing -c mission.rnc "$tmpname"
    rm "$tmpname"
done
