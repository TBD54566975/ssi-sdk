# Mobile

Mobile makes use of [Go Mobile](https://pkg.go.dev/golang.org/x/mobile/cmd/gomobile). Bindings are maintained in this
package. Mage targets are exposed to generate bindings for iOS and Android. At present, files must not be nested in
subdirectories for bindings to be generated correctly.

## iOS

```
mage ios
```

## Android

```
mage android
```