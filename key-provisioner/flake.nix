{
  description = "Hashi guardian key provisioner Mac configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    nix-darwin = {
      url = "github:nix-darwin/nix-darwin";
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
                pkgs._1password-gui
                pkgs.awscli2
                pkgs.cargo
                pkgs.gnupg
                pkgs.neovim
                pkgs.openpgp-card-tools
                pkgs.rustc
                pkgs.yubikey-manager
              ];

              networking = {
                hostName = "kp-mbn";
                computerName = "kp-mbn";
              };

              nix.enable = false; # For determinate nix

              nixpkgs.config.allowUnfree = true;
              nixpkgs.hostPlatform = "aarch64-darwin";

              system.primaryUser = "kp";
              system.stateVersion = 7;

              system.defaults = {
                CustomUserPreferences = {
                  NSGlobalDomain.ApplePersistenceIgnoreState = true;
                  "com.apple.loginwindow" = {
                    LoginwindowLaunchesRelaunchApps = false;
                    TALLogoutSavesState = false;
                  };
                };

                NSGlobalDomain.NSAutomaticWindowAnimationsEnabled = false;

                WindowManager = {
                  EnableStandardClickToShowDesktop = false;
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
                  NewWindowTarget = "Home";
                  ShowPathbar = true;
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
