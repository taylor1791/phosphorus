{
  description = "carbon: encrypted secrets for monorepos, stored in the repo";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      version = "1.0.0-dev";
    in
    {
      packages = forAll (pkgs: rec {
        carbon = pkgs.buildGoModule {
          pname = "carbon";
          inherit version;
          src = ./.;
          subPackages = [ "cmd/carbon" ];
          vendorHash = "sha256-tbO+ezq9kFroFk2/7BXeCZsgpg4sQzGPH57ikDcuQWM=";
          env.CGO_ENABLED = "0";
          ldflags = [ "-s" "-w" "-X github.com/taylor1791/phosphorus/internal/cli.Version=${version}" ];
          # The tests build binaries and drive git in temporary repositories;
          # run them with `go test ./...` in the dev shell.
          doCheck = false;
          meta = {
            description = "Encrypted secrets for monorepos, stored in the repo";
            mainProgram = "carbon";
          };
        };
        default = carbon;
      });

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = [ pkgs.go pkgs.git pkgs.age pkgs.sops ];
          env.CGO_ENABLED = "0";
        };
      });
    };
}
