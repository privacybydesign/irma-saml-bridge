del dist\* /Q
yarn install
yarn run build
del C:\workspaces\irma-saml-bridge\.metadata\.plugins\org.eclipse.wst.server.core\tmp0\wtpwebapps\irma-saml-bridge\assets\* /Q
copy dist\* C:\workspaces\irma-saml-bridge\.metadata\.plugins\org.eclipse.wst.server.core\tmp0\wtpwebapps\irma-saml-bridge\assets /Y