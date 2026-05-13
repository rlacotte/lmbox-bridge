package kit

import "encoding/base64"

// _b64 is the standard base64 encoding (with padding), accessed
// via a package-level var so it's swappable in tests should we
// ever need RawStdEncoding instead.
var _b64 = base64.StdEncoding
