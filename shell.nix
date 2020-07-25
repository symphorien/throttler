with import <nixpkgs> {};
mkShell {
  buildInputs = [ cargo rustc rls ];
}
