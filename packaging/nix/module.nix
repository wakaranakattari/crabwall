{ config, lib, pkgs, ... }:

{
  options.services.crabwall = {
    enable = lib.mkEnableOption "crabwall per-app firewall daemon";
    package = lib.mkPackageOption pkgs "crabwall" { };
  };

  config = lib.mkIf config.services.crabwall.enable {
    systemd.services.crabwalld = {
      description = "crabwall per-app firewall daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        Type = "simple";
        ExecStart = "${config.services.crabwall.package}/bin/crabwalld";
        Restart = "on-failure";
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" "CAP_SYS_RESOURCE" "CAP_DAC_READ_SEARCH" ];
        AmbientCapabilities = [ "CAP_NET_ADMIN" "CAP_SYS_RESOURCE" "CAP_DAC_READ_SEARCH" ];
      };
    };

    environment.systemPackages = [ config.services.crabwall.package ];
  };
}
