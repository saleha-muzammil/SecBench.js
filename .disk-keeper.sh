#!/bin/sh
# Reclaim finished-entry images while an evasion campaign runs. Exits when no
# campaign runs.
#
# This used to be `docker image prune -a -f`, which had two problems.
#
# 1. RACE. `prune -a` protects only images backing a RUNNING container. The
#    campaign builds an entry's image and starts a container from it a moment
#    later, so a prune landing in that window deletes the image out from under
#    the run and the entry dies with
#        Unable to find image 'secbench-fixed/<x>:latest' locally
#        docker: Error response from daemon: pull access denied ...
#    which the harness reports as `infra-error`. three@0.122.0, querymen@2.1.3
#    and mithril@1.0.0 were all lost to exactly this race.
#
# 2. BLAST RADIUS. `-a` reaps EVERY unused image on the host, including images
#    belonging to whatever else the machine is running (secbench-fullloop/*
#    from run_stratified_full_loop.py, base images, other projects' builds).
#
# Both are fixed by being specific: only touch `secbench-fixed/*` -- the tags
# this campaign creates -- and only once an image is older than the longest
# plausible entry (slowest observed ~21 min, so 90m is a wide margin). The
# campaign removes each entry's image itself as soon as that entry finishes, so
# this loop is only a safety net for images it did not get to.
STALE_MINUTES=90

while pgrep -f "run_evasion_campaign.py" >/dev/null 2>&1; do
  now=$(date +%s)
  docker images --filter "reference=secbench-fixed/*" \
                --format '{{.ID}} {{.CreatedAt}} {{.Repository}}:{{.Tag}}' 2>/dev/null |
  while read -r id created_date created_time created_off _rest; do
    created=$(date -j -f '%Y-%m-%d %H:%M:%S %z' \
                   "$created_date $created_time $created_off" +%s 2>/dev/null) ||
    created=$(date -d "$created_date $created_time $created_off" +%s 2>/dev/null) || continue
    [ $(( (now - created) / 60 )) -ge "$STALE_MINUTES" ] || continue
    docker rmi "$id" >/dev/null 2>&1   # no -f: a running container keeps its image
  done
  # dangling layers only -- never `-a`, which would take other projects' images
  docker image prune -f >/dev/null 2>&1
  sleep 300
done
