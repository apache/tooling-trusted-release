#!/bin/sh
set -eu

if ! which npm
then
  echo requires npm
  exit 1
fi

if ! which sass
then
  echo requires sass
  exit 1
fi

test -d build || mkdir build
cd build
npm install bootstrap
test -d scss || mkdir scss
cp ../custom.scss scss/custom.scss
cp ../reboot-shim.scss scss/reboot-shim.scss
sass -q scss/custom.scss css/custom.css
cp css/custom.css ../../atr/static/css/bootstrap.custom.css
cp css/custom.css.map ../../atr/static/css/bootstrap.custom.css.map
cp node_modules/bootstrap/dist/js/bootstrap.bundle.min.js ../../atr/static/js/bootstrap.bundle.min.js
cp node_modules/bootstrap/dist/js/bootstrap.bundle.min.js.map ../../atr/static/js/bootstrap.bundle.min.js.map
