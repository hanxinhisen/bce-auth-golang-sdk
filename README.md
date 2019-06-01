使用方法
```
package main

import (
	"fmt"
	bgs "github.com/hanxinhisen/bce-auth-golang-sdk"
	"time"
)

func main() {

	var r bgs.Request
	r.Headers.Headers = make(map[string]interface{}, 100)
	r.Headers.Headers["x-bce-date"] = time.Now().UTC().Format("2006-01-02T15:04:05Z")
	//r.Headers.Headers["x-bce-date"] = "2019-06-01T10:02:58Z"
	r.Headers.Headers["Host"] = "dcc.bj.baidubce.com"
	r.Headers.Headers["X-BCE-Scope"] = "BCE_DCC"
	r.Headers.Headers["Content-Type"] = "application/json"
	r.Params.Params = make(map[string]interface{}, 100)
	r.Method = "GET"
	r.Uri = "/v1/dedicatedHost/d-qADDDRYs"
	b := bgs.BceSigner{Access_key: "s7446830374c", Secret_key: "1d4d3e5fe7020"}
	d := b.GenAuthorization(&r)
	fmt.Println(d)
}

```