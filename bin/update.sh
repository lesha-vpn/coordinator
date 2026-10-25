#!/bin/sh
# npm run update: pull master, reinstall deps only when needed, build, reload pm2.
# The body is one { } block so sh parses it fully before git pull can rewrite this file.
{
  set -e
  git pull --ff-only origin master

  # npm ci wipes node_modules and recompiles native modules (minutes on a small
  # server), so run it only when the lockfile or the Node version changed.
  stamp=node_modules/.update-stamp
  want="$(node -v) $(sha256sum package-lock.json | cut -d' ' -f1)"
  if [ "$(cat "$stamp" 2>/dev/null)" != "$want" ]; then
    npm ci
    echo "$want" > "$stamp"
  else
    echo "Зависимости не менялись, npm ci пропущен"
  fi

  npm run build
  npm run pm2:reload
  exit
}
