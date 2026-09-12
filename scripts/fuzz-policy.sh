#!/usr/bin/env bash
# Single owner of bounds shared by QA corpus import and fuzz campaigns.
# shellcheck disable=SC2034 # This file is sourced; its owner value is consumed there.
readonly FUZZ_MAX_SEED_BYTES=65536
