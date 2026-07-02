# NixOS module for the Fides server. Import via the flake:
#
#   imports = [ fides.nixosModules.default ];
#   services.fides = {
#     enable = true;
#     environmentFile = "/run/secrets/fides.env";  # DB_DSN, FIDES_ENCRYPTION_KEY, ...
#   };
#
# `self` is the flake, used to pin the default package to this source tree.
self:
{ config, lib, pkgs, ... }:

let
  cfg = config.services.fides;
in
{
  options.services.fides = {
    enable = lib.mkEnableOption "the Fides compliance & evidence-tracking server";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.fides;
      defaultText = lib.literalExpression "fides.packages.\${system}.fides";
      description = "The Fides package providing bin/fides-server.";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "TCP port the API server listens on (sets PORT).";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open {option}`services.fides.port` in the firewall.";
    };

    stateDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/fides";
      description = ''
        Working directory and default local storage root. The `web/` static
        portal is served relative to this directory, so deployments using the
        bundled portal should place it here.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "fides";
      description = "User account under which the server runs.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "fides";
      description = "Group under which the server runs.";
    };

    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      example = "/run/secrets/fides.env";
      description = ''
        Path to an EnvironmentFile (read by systemd) holding secrets and
        connection settings — at minimum `DB_DSN`, and `FIDES_ENCRYPTION_KEY`
        for evidence encryption. Keep this file out of the Nix store (e.g.
        provisioned by agenix/sops-nix). See the Fides docs for the full set of
        `FIDES_*` / storage / AI variables.
      '';
    };

    settings = lib.mkOption {
      type = with lib.types; attrsOf (oneOf [ str int bool ]);
      default = { };
      example = lib.literalExpression ''
        {
          STORAGE_DRIVER = "local";
          FIDES_EVENTS_ENABLED = true;
          FIDES_PUBLIC_URL = "https://fides.example.com";
        }
      '';
      description = ''
        Non-secret environment variables passed to the server. Booleans are
        rendered as `true`/`false` and integers as decimal strings. Do not put
        secrets here — they land in the world-readable Nix store; use
        {option}`services.fides.environmentFile` instead.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    users.users = lib.mkIf (cfg.user == "fides") {
      fides = {
        isSystemUser = true;
        group = cfg.group;
        home = cfg.stateDir;
      };
    };

    users.groups = lib.mkIf (cfg.group == "fides") {
      fides = { };
    };

    networking.firewall.allowedTCPPorts = lib.mkIf cfg.openFirewall [ cfg.port ];

    systemd.services.fides = {
      description = "Fides compliance & evidence-tracking server";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      environment = {
        PORT = toString cfg.port;
        STORAGE_LOCAL_DIR = "${cfg.stateDir}/evidence";
      } // lib.mapAttrs
        (_: v: if lib.isBool v then lib.boolToString v else toString v)
        cfg.settings;

      serviceConfig = {
        ExecStart = "${lib.getExe' cfg.package "fides-server"}";
        User = cfg.user;
        Group = cfg.group;
        WorkingDirectory = cfg.stateDir;
        StateDirectory = lib.mkIf (lib.hasPrefix "/var/lib/fides" cfg.stateDir) "fides";
        EnvironmentFile = lib.mkIf (cfg.environmentFile != null) cfg.environmentFile;
        Restart = "on-failure";
        RestartSec = 5;

        # Hardening — the server needs only outbound network + its state dir.
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictSUIDSGID = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        ReadWritePaths = [ cfg.stateDir ];
        SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
      };
    };

    assertions = [
      {
        assertion = cfg.environmentFile != null;
        message = ''
          services.fides requires an environmentFile providing DB_DSN (the
          server refuses to start without it). Set
          services.fides.environmentFile.
        '';
      }
    ];
  };
}
