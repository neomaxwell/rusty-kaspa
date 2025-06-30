#!/bin/bash

CUR_DIR=$(realpath "$(dirname "${BASH_SOURCE:-$0}")")

function up() {
    pushd "$CUR_DIR"
    COMPOSE_BAKE=true docker compose up -d --build
    popd
}

up
