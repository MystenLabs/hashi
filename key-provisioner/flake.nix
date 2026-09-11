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
            { config, pkgs, ... }:
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
                pkgs.tmux
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
                # Install Ghostty preferences
                /usr/bin/install -d -o kp -m 0755 "/Users/kp/Library/Application Support/com.mitchellh.ghostty"
                /usr/bin/install -o kp -m 0644 ${pkgs.writeText "ghostty-config" ''
                  auto-update = off
                  theme = Dimidium
                  font-size = 16
                  maximize = true
                  quit-after-last-window-closed = true
                ''} "/Users/kp/Library/Application Support/com.mitchellh.ghostty/config.ghostty"

                # Install neovim settings
                /usr/bin/install -d -o kp -m 0755 "/Users/kp/.config/nvim"
                /usr/bin/install -o kp -m 0644 ${pkgs.writeText "nvim-init.lua" ''
                  vim.opt.number = true
                  vim.opt.cursorline = true
                  vim.opt.scrolloff = 10
                  vim.opt.sidescrolloff = 10
                  vim.opt.ignorecase = true
                  vim.opt.smartcase = true
                  vim.opt.inccommand = "split"
                  vim.opt.list = true
                  vim.opt.listchars = { tab = "» ", trail = "·", nbsp = "␣" }
                  vim.opt.expandtab = true
                  vim.opt.tabstop = 4
                  vim.opt.shiftwidth = 4
                  vim.opt.clipboard = "unnamedplus"
                  vim.opt.swapfile = false
                  vim.opt.backup = false
                  vim.opt.writebackup = false
                  vim.opt.undofile = false
                  vim.opt.shadafile = "NONE"
                ''} "/Users/kp/.config/nvim/init.lua"
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

              launchd.user.agents.keyboard-mapping = {
                script = config.system.activationScripts.keyboard.text;
                serviceConfig.RunAtLoad = true;
              };
            }
          )
        ];
      };
    };
}
