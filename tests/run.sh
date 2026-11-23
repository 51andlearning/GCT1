#!/bin/sh
# Runs the middleware tests. The Vercel import is swapped for a local stub so
# the tests need no network and no Vercel runtime.
set -e
cd "$(dirname "$0")"
mkdir -p .tmp
sed 's|import { next } from "@vercel/edge";|const next = () => new Response("PASS_THROUGH", { status: 200, headers: { "x-mw": "next" } });|' ../middleware.js > .tmp/mw.mjs
cp gate-and-signing.test.mjs .tmp/gate.mjs
cp otp-flow.test.mjs .tmp/otp.mjs
cp no-secret.test.mjs .tmp/nosecret.mjs
cp no-gate-code.test.mjs .tmp/nogate.mjs
echo "== gate and signing =="
node .tmp/gate.mjs
echo
echo "== one time code flow =="
node .tmp/otp.mjs
echo
echo "== unconfigured signing secret =="
node .tmp/nosecret.mjs
echo
echo "== unconfigured access code =="
node .tmp/nogate.mjs
