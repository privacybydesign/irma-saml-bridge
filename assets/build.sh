rm -rf dist
yarn install
yarn run build
rm -rf ../src/main/resources/static/assets
cp -R dist/ ../src/main/resources/static/assets
