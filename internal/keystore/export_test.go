package keystore

// PrivateMaterial lets the external leak test (leak_test.go, package
// keystore_test) ask the store for its private encodings. It exists only in
// test builds: a _test.go file is never compiled into the binary.
var PrivateMaterial = (*Store).privateMaterial
