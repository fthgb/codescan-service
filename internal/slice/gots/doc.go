// Package gots is the Go-native Java slicer: a pure-Go tree-sitter
// implementation of slice.FunctionExtractor (no Python subprocess, no CGO).
//
// Maintenance cheatsheet:
//
//  Bump gotreesitter grammar:
//   1. go get github.com/odvcencio/gotreesitter@<ver>
//   2. go test ./internal/slice/gots/   (node-type gate + TestCompareGolden)
//   3. If red: review golden diff in testdata/golden/slice/. If new behavior
//      still matches Python 0.23.5 semantics, update golden (commit w/
//      rationale). If regression, pin back.
//
//  Change a slicing rule (e.g. control_flow_mutex):
//   1. Edit extractor.go.
//   2. go test ./internal/slice/gots/ (compare) + full go test ./... (e2e).
//   3. Output unchanged -> merge (pure robustness gain). Output changed ->
//      review golden diff; better -> update golden w/ rationale; worse ->
//      revert. e2e verdict change is the hard floor.
//
//  Golden (frozen reference):
//   testdata/golden/slice/ holds the frozen slicer output the gots port is
//   verified against (TestCompareGolden, default build — no external deps).
//   The Python tree-sitter oracle that originally produced it is not part of
//   this repo; regenerating golden from a fresh Python reference is out of
//   scope here — treat the frozen golden as the contract.
//
// See docs/superpowers/specs/2026-08-08-gotreesitter-native-slicer-design.md.
package gots
