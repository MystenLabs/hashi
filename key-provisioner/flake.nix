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
          {
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

            system.defaults.NSGlobalDomain.NSAutomaticWindowAnimationsEnabled = false;
            system.defaults.NSGlobalDomain.AppleInterfaceStyle = "Dark";

            system.defaults.CustomUserPreferences = {
              NSGlobalDomain.ApplePersistenceIgnoreState = true;
              "com.apple.loginwindow" = {
                LoginwindowLaunchesRelaunchApps = false;
                TALLogoutSavesState = false;
              };
            };

            system.defaults.WindowManager = {
              StageManagerHideWidgets = true;
              StandardHideWidgets = true;
            };

            system.defaults.dock = {
              autohide = false;
              orientation = "right";
              persistent-apps = [
                "/System/Applications/System Settings.app"
                "/System/Applications/Utilities/Terminal.app"
                "/System/Cryptexes/App/System/Applications/Safari.app"
              ];
              persistent-others = [ ];
              show-recents = false;
            };

            system.defaults.finder = {
              AppleShowAllExtensions = true;
              AppleShowAllFiles = true;
              FXRemoveOldTrashItems = true;
              _FXShowPosixPathInTitle = true;
              _FXSortFoldersFirst = true;
            };

            system.keyboard = {
              enableKeyMapping = true;
              remapCapsLockToEscape = true;
            };
          }
        ];
      };
    };
}
