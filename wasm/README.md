# WASM bindings of ssi-sdk into javascript

https://github.com/TBD54566975/ssi-sdk is the home of self soverign stuff at TBD, implented in golang. 
We want to use this from the web as well, this minimal demo shows how.

`webserver` is a sample webserver which serves up a sample js app from `static` which also contains the wasm bindings and wasm "binary".

# status
This just has some example usage of apis to start with.

# building (from top level)

`mage buildwasm`

# running web server to test out

`cd wasm && go run webserver/main.go` - then go to localhost:3000 to try it out!


