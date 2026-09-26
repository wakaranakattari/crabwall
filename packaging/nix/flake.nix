{
  description = "crabwall - Little Snitch for Linux";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        packages.default = pkgs.callPackage ./package.nix { };
        apps.default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/crabwall";
        };
        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.default ];
          packages = with pkgs; [ cargo rustc clippy rustfmt llvm pkg-config ];
        };
      }) // {
        nixosModules.default = import ./module.nix;
      };
}
