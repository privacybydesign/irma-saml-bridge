package saml_test

import "encoding/xml"

func xmlMarshal(v any) ([]byte, error) { return xml.Marshal(v) }
