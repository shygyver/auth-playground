{
  description = "A development environment for Bun projects";

  inputs = {
    # Using unstable for the latest Bun versions
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.bun
          ];

          shellHook = ''
            echo "🥟 Bun development environment loaded!"
            bun --version
          '';
        };
      }
    );
}

