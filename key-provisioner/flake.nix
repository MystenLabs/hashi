{
  description = "Hashi guardian key provisioner Mac configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-25.11-darwin";

    nix-darwin = {
      url = "github:nix-darwin/nix-darwin/nix-darwin-25.11";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nix-darwin, ... }:
    {
      darwinConfigurations.hashi-guardian-key-provisioner = nix-darwin.lib.darwinSystem {
        system = "aarch64-darwin";

        modules = [
          (
            { pkgs, ... }:
            {
              environment.systemPackages = [
                pkgs.cargo
                pkgs.cargo-nextest
                pkgs.clippy
                pkgs.neovim
                pkgs.rust-analyzer
                pkgs.rustc
                pkgs.rustfmt
              ];

              nix.enable = false; # For determinate nix
              nix.settings = {
                substituters = [
                  "https://nix-community.cachix.org/"
                ];

                trusted-public-keys = [
                  "nix-community.cachix.org-1:mB9FSh9qf2dCimDSUo8Zy7bkq5CX+/rkCWyvRCYg3Fs="
                ];
              };

              nixpkgs.hostPlatform = "aarch64-darwin";

              system.primaryUser = "admin";
              system.stateVersion = 7;

              system.defaults = {
                CustomUserPreferences = {
                  NSGlobalDomain.ApplePersistenceIgnoreState = true;
                  "com.apple.loginwindow" = {
                    LoginwindowLaunchesRelaunchApps = false;
                    TALLogoutSavesState = false;
                  };
                };

                NSGlobalDomain = {
                  AppleInterfaceStyle = "Dark";
                  NSAutomaticWindowAnimationsEnabled = false;
                };

                WindowManager = {
                  StageManagerHideWidgets = true;
                  StandardHideWidgets = true;
                };

                dock = {
                  autohide = false;
                  orientation = "right";
                  persistent-apps = [
                    "/System/Applications/Utilities/Terminal.app"
                  ];
                  persistent-others = [ ];
                  show-recents = false;
                };

                finder = {
                  AppleShowAllExtensions = true;
                  AppleShowAllFiles = true;
                  FXRemoveOldTrashItems = true;
                  _FXShowPosixPathInTitle = true;
                  _FXSortFoldersFirst = true;
                };
              };

              system.keyboard = {
                enableKeyMapping = true;
                remapCapsLockToEscape = true;
              };
            }
          )
        ];
      };
    };
}
