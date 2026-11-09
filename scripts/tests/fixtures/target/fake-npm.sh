#!/bin/sh
# A stand-in for npm, for the target.sh cases of scripts/tests/test-runners.sh, which copies it with @T@
# replaced by its temporary directory. npm takes a project's settings from the .npmrc of the package root it
# finds from its working directory up, a workspace's root among them. This one appends to @T@/calls the block
# fixtures/runners/fake-tool.sh writes (== npm <arguments>, cwd and env lines), then one line for each
# directory from its working directory up to the top of target.sh's copy that holds a .npmrc of any kind,
#   npmrc: <its path in the copy>: <its text, lines joined with |>
# or "npmrc: none" when none does; for npm ci, "lock: yes" or "lock: no" after it. When NODE_OPTIONS is
# --require="<file>", it copies that file to @T@/preload.js. It exits 0.
T=@T@
top=$PWD
while [ -n "$top" ]; do
  case "${top%/*}" in */auditor-target.??????) break ;; esac
  top=${top%/*}
done
{
  printf '== npm %s\n' "$*"
  printf 'cwd: %s\n' "$PWD"
  env | LC_ALL=C sort | sed 's/^/env: /'
  d=$PWD n=0
  while [ -n "$top" ]; do
    if [ -e "$d/.npmrc" ] || [ -L "$d/.npmrc" ]; then
      rel=${d#"$top"}
      rel=${rel#/}
      printf 'npmrc: %s.npmrc: %s\n' "${rel}${rel:+/}" "$(tr '\n' '|' < "$d/.npmrc" 2>/dev/null)"
      n=$((n + 1))
    fi
    [ "$d" != "$top" ] || break
    d=${d%/*}
  done
  [ "$n" -gt 0 ] || echo 'npmrc: none'
  [ "${1:-}" != ci ] || printf 'lock: %s\n' "$([ -f package-lock.json ] && echo yes || echo no)"
} >> "$T/calls"
case "${NODE_OPTIONS:-}" in
  --require=\"*\") p=${NODE_OPTIONS#--require=\"}; cp "${p%\"}" "$T/preload.js" ;;
esac
exit 0
