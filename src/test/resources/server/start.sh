#!/usr/bin/env bash
# Fixture start script: a realistic mix of a wrapper, a continuation and stale flags.
cd "$(dirname "$0")" || exit 1

while true; do
  java -Xms2G -Xmx14G -XX:+UseG1GC -XX:+UseParallelGC \
    -XX:+UseConcMarkSweepGC -XX:CMSInitiatingOccupancyFraction=70 \
    -XX:MaxGCPauseMillis=200 -XX:G1NewSizePercent=30 \
    -Ddisable.watchdog=true -Dcom.mojang.eula.agree=true \
    -jar paper.jar --nogui
  echo "server stopped, restarting in 5s"
  sleep 5
done
