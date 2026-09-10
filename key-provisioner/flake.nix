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
                pkgs.ghostty-bin
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

              system.activationScripts.postActivation.text = ''
                /usr/bin/install -d -o kp -m 0755 "/Users/kp/Library/Application Support/com.mitchellh.ghostty"
                /usr/bin/install -o kp -m 0644 ${
                  pkgs.writeText "ghostty-config" ''
                    auto-update = off
                    theme = Dimidium
                    font-size = 16
                    maximize = true
                    quit-after-last-window-closed = true
                  ''
                } "/Users/kp/Library/Application Support/com.mitchellh.ghostty/config.ghostty"
              '';

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
                  autohide = true;
                  orientation = "right";
                  persistent-apps = [
                    "/Applications/Nix Apps/Ghostty.app"
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
