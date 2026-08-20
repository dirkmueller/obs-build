################################################################
#
# Copyright (c) 2026 SUSE LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program (see the file COPYING); if not, write to the
# Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
#
################################################################

package PBuild::Obsgit;

use PBuild::AssetMgr;
use PBuild::Cpio;

sub merge_obsgit_data {
  my ($preset, $assetdir, $opts) = @_;
  eval { require YAML::XS; $YAML::XS::LoadBlessed = 0; };
  die("Need YAML::XS to parse the obs configuration\n") unless defined &YAML::XS::LoadFile;
  my $obsgit = $preset->{'obsgit'};
  die("invalid obsgit url $obsgit \n") unless $obsgit =~ /^(?:git\+)?(https?:\/\/[^\/]+)\/(.+)$/;
  my $gitrepo = $2;
  my $assetmgr = PBuild::AssetMgr::create($assetdir);
  my $asset = { 'file' => 'configuration', 'url' => "git+$1/obs/configuration", 'type' => 'url', 'isdir' => 1 };
  $asset->{'assetid'} = PBuild::AssetMgr::get_assetid($asset->{'file'}, $asset);
  $assetmgr->force_update_single($asset) if $opts->{'update-assets'};
  my $assetfile = $assetmgr->getremoteasset_single($asset, 1);
  if (!$assetfile) {
    print "fetching obs configuration asset\n";
    $assetfile = $assetmgr->getremoteasset_single($asset);
    die("obs configuration not found\n") unless $assetfile;
  }
  my $configuration_yaml;
  PBuild::Cpio::cpio_extract($assetfile, sub {\$configuration_yaml} , 'extract' => 'configuration/configuration.yaml', 'missingok' => 1);
  die("obs configuration does not include a configuration.yaml file\n") unless defined $configuration_yaml;
  my $obsconfiguration = eval { YAML::XS::Load($configuration_yaml) };
  die("could not parse obs configuration: $@") if $@;
  # fill preset with data from the configuration
  $preset->{'obs'} = $obsconfiguration->{'obs_apiurl'} unless defined $preset->{'obs'};
  my $obsprj = $gitrepo;
  $obsprj =~ s/[\/#]/:/g;
  $obsprj =~ s/(?::main|:master)$//;
  $obsprj = "$obsprj/standard";
  $preset->{'config'} ||= [ "obs:/$obsprj" ];
}

1;
