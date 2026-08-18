################################################################
#
# Copyright (c) 2021 SUSE LLC
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

package PBuild::Preset;

use PBuild::Structured;
use PBuild::Util;

use strict;

my $dtd_pbuild = [
    'pbuild' =>
     [[ 'preset' =>
	    'name',
	    'default',
	    'arch',
	  [ 'config' ],
	  [ 'repo' ],
	  [ 'registry' ],
	  [ 'assets' ],
	    'obs',
	  [ 'hostrepo' ],
	  [ 'architectures' ],
	    'obsgit',
     ]],
];

sub read_preset_file {
  my ($dir) = @_;
  my $pbuild_str = PBuild::Util::readstr("$dir/_pbuild");
  if ($pbuild_str !~ /^\s*</s) {
    eval { require YAML::XS; $YAML::XS::LoadBlessed = 0; };
    die("Need YAML::XS to parse the _pbuild file\n") unless defined &YAML::XS::Load;
    my $pbuild = eval { YAML::XS::Load($pbuild_str) };
    die("Could not parse _pbuild file: $@") if $@;
    return PBuild::Structured::postprocess({ 'pbuild' => [ $pbuild ] }, $dtd_pbuild);
  }
  return PBuild::Structured::fromxml($pbuild_str, $dtd_pbuild);
}

sub read_manifest_file {
  my ($dir) = @_;
  eval { require YAML::XS; $YAML::XS::LoadBlessed = 0; };
  die("Need YAML::XS to parse the _manifest file\n") unless defined &YAML::XS::LoadFile;
  my $manifest = eval { YAML::XS::LoadFile("$dir/_manifest") };
  die("Could not parse _manifest file: $@") if $@;
  return {} unless defined $manifest;
  die("Bad _manifest file\n") unless ref($manifest) eq 'HASH';
  return $manifest;
}

sub get_presets_array {
  my ($dir) = @_;
  if (-f "$dir/_pbuild") {
    my $pbuild = read_preset_file($dir);
    return $pbuild->{'preset'};
  } elsif (-f "$dir/_manifest") {
    my $manifest = read_manifest_file($dir);
    return undef unless ref($manifest->{'presets'}) eq 'ARRAY';
    my $presets = PBuild::Structured::postprocess({ 'pbuild' => [ { 'preset' => $manifest->{'presets'} } ] }, $dtd_pbuild);
    return $presets->{'preset'};
  }
  return undef;
}

# read presets, take default if non given.
sub read_presets {
  my ($dir, $presetname) = @_;
  my $presets = get_presets_array($dir);
  for my $preset (@{$presets || []}) {
    next unless $preset->{'name'};
    if (defined($presetname)) {
      # check for selected preset
      return $preset if $presetname eq $preset->{'name'};
    } else {
      # check for default
      return $preset if exists $preset->{'default'};
    }
  }
  die("unknown preset '$presetname'\n") if defined $presetname;
  return undef;
}

# get a list of defined presets
sub known_presets {
  my ($dir) = @_;
  my @presetnames;
  my $presets = get_presets_array($dir);
  for my $d (@{$presets || []}) {
    push @presetnames, $d->{'name'} if defined $d->{'name'};
  }
  return PBuild::Util::unify(@presetnames);
}

# show presets
sub list_presets {
  my ($dir) = @_;
  my @presetnames = known_presets($dir);
  if (@presetnames) {
    print "Known presets:\n";
    print "  - $_\n" for @presetnames;
  } else {
    print "No presets defined\n";
  }
}

# get reponame/dist/repo/registry options from preset
sub apply_preset {
  my ($opts, $preset) = @_;
  $opts->{'arch'} = $preset->{'arch'} if $preset->{'arch'} && !$opts->{'arch'};
  $opts->{'reponame'} = $preset->{'name'} if $preset->{'name'} && !$opts->{'reponame'};
  push @{$opts->{'dist'}}, @{$preset->{'config'}} if $preset->{'config'} && !$opts->{'dist'};
  push @{$opts->{'repo'}}, @{$preset->{'repo'}} if $preset->{'repo'} && !$opts->{'repo'};
  push @{$opts->{'registry'}}, @{$preset->{'registry'}} if $preset->{'registry'} && !$opts->{'registry'};
  push @{$opts->{'assets'}}, @{$preset->{'assets'}} if $preset->{'assets'} && !$opts->{'assets'};
  $opts->{'obs'} = $preset->{'obs'} if $preset->{'obs'} && !$opts->{'obs'};
  push @{$opts->{'hostrepo'}}, @{$preset->{'hostrepo'}} if $preset->{'hostrepo'} && !$opts->{'hostrepo'};
}

1;
