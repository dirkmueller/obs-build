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

package PBuild::RemoteRegistry;

use strict;

use Build::Download;
use Build::SimpleJSON;

use PBuild::BearerAuth;
use PBuild::Verify;

eval { require JSON::XS };
*JSON::XS::decode_json = sub {die("JSON::XS is not available\n")} unless defined &JSON::XS::decode_json;

#
# mime types
#
my $mt_docker_manifest     = 'application/vnd.docker.distribution.manifest.v2+json';
my $mt_docker_manifestlist = 'application/vnd.docker.distribution.manifest.list.v2+json';
my $mt_oci_manifest        = 'application/vnd.oci.image.manifest.v1+json';
my $mt_oci_index           = 'application/vnd.oci.image.index.v1+json';

#
# convert arch to goarch/govariant
#
sub arch2goarch {
  my ($arch) = @_;
  return ('amd64') if $arch eq 'x86_64';
  return ('386') if $arch =~ /^i[3456]86$/;
  return ('arm64', 'v8') if $arch eq 'aarch64';
  return ('arm', "v$1") if $arch =~ /^armv(\d+)/;
  return $arch;
}

#
# select a matching manifest from a manifest index (aka fat manifest)
#
sub select_manifest {
  my ($manifests, $arch) = @_;
  my ($goarch, $govariant) = arch2goarch($arch);
  my $goos = 'linux';
  for my $m (@{$manifests || []}) {
    next unless $m->{'digest'};
    my $platform = $m->{'platform'};
    if ($platform) {
      next if $goarch && $platform->{'architecture'} && $platform->{'architecture'} ne $goarch;
      next if $govariant && $platform->{'variant'} && $platform->{'variant'} ne $govariant;
      next if $goos && $platform->{'os'} && $govariant && $platform->{'os'} ne $goos;
    }
    return $m;
  }
  return undef;
}

#
# retrieve a manifest using a HEAD request first for the docker registry
#
sub fetch_manifest {
  my ($repodir, $registry, @args) = @_;
  return Build::Download::fetch(@args) if $registry !~ /docker.io\/?$/;
  my ($data, $ct);
  eval { ($data, $ct) = Build::Download::head(@args) };
  die($@) if $@ && $@ !~ /401 Unauthorized/;	# sigh, docker returns 401 for not-existing repositories
  return (undef, $ct) unless $data;
  my $digest = $data->{'docker-content-digest'};
  return Build::Download::fetch(@args) unless $digest;
  my $content = PBuild::Util::readstr("$repodir/manifest.$digest", 1);
  if ($content) {
    my %opts = ('url', @args);
    ${$opts{'replyheaders'}} = $data if $opts{'replyheaders'};
    Build::Download::checkdigest($content, $digest);
    return ($content, $ct);
  }
  ($content, $ct) = Build::Download::fetch(@args);
  return undef unless $content;
  Build::Download::checkdigest($content, $digest);
  PBuild::Util::mkdir_p($repodir);
  PBuild::Util::writestr("$repodir/.manifest.$digest.$$", "$repodir/manifest.$digest", $content);
  return ($content, $ct);
}

# fetch the sbom for a container image digest
sub fetch_sbom {
  my ($repodir, $registry, $repository, $digest, $ua) = @_;
  my $digtag = $digest;
  $digtag =~ s/:/-/;
  my $att_digest;
  my ($content, $ct) = eval { Build::Download::fetch("$registry/v2/$repository/manifests/$digtag.att", 'ua' => $ua, 'accept' => [ $mt_oci_manifest ], 'missingok' => 1) };
  if (!$@ && $content && $ct eq $mt_oci_manifest) {
    my $mani = JSON::XS::decode_json($content);
    for my $l (@{$mani->{'layers'} || []}) {
      next if ($l->{'mediaType'} || '') ne 'application/vnd.dsse.envelope.v1+json';
      next if ($l->{'size'} || 0) > 200 * 1024 * 1024;
      my $annotations = $l->{'annotations'} || {};
      my $is_att;
      $is_att = 1 if ($annotations->{'org.open-build-service.intoto.predicatetype'} || '') eq 'https://cyclonedx.org/bom';
      next unless $is_att;
      $att_digest = $l->{'digest'};
      last;
    }
  }
  PBuild::Util::mkdir_p($repodir);
  return '' unless $att_digest;
  PBuild::Verify::verify_digest($att_digest);
  return (Build::Download::fetch("$registry/v2/$repository/blobs/$att_digest", 'digest' => $att_digest, 'ua' => $ua))[0];
}

sub get_intoto_predicate {
  my $envelope = JSON::XS::decode_json($_[0]);
  die("bad payload type\n") unless ($envelope->{'payloadType'} || '') eq 'application/vnd.in-toto+json';
  die("no payload\n") unless exists $envelope->{'payload'};
  my $att_json = MIME::Base64::decode_base64($envelope->{'payload'});
  $envelope = undef;	# free mem
  my $att = JSON::XS::decode_json($att_json);
  die("missing predicate\n") unless $att->{'predicate'};
  return $att->{'predicate'};
}

sub sbom2installed {
  my ($att) = @_;
  my @inst;
  for my $comp (@{$att->{'components'} || []}) {
    next unless $comp->{'type'} eq 'library' && $comp->{'name'} && $comp->{'version'} && $comp->{'purl'};
    next unless $comp->{'purl'} =~ /^pkg:(?:rpm|deb|apk|alpm)\//;       # filter out golang et al
    next if $comp->{'name'} eq 'gpg-pubkey';
    my $epoch = '';
    $epoch = "$1:" if $comp->{'purl'} =~ /[\?\&]epoch=(\d+)/ && $1;
    push @inst, "$comp->{'name'} = $epoch$comp->{'version'}";
  }
  return @inst ? \@inst : undef;
}

#
# create a binary referencing a container on a remote registry
#
sub createcontainerbinary {
  my ($repository, $repotag, $imageid, $blobs, $annotation) = @_;
  my $name = $repotag;
  $name =~ s/[:\/]/-/g;
  $name = "_$name" if $name =~ /^_/;    # just in case
  $name = "container:$name";
  my $version = 0;
  my @provides = ("$name = $version");
  push @provides, "container:$repotag" unless $name eq "container:$repotag";
  my $q = {
    'name' => $name,
    'version' => $version,
    'arch' => 'noarch',
    'source' => $name,
    'provides' => \@provides,
    'hdrmd5' => $imageid,
    'location' => $repository,
    'blobs' => $blobs,
    'containertags' => [ $repotag ],
    'annotation' => $annotation,
  };
  return $q;
}

#
# query a registry about a container
#
sub queryremotecontainer {
  my ($ua, $arch, $repodir, $registry, $repotag, $oldbin) = @_;
  my $registrydomain = $registry;
  $registrydomain =~ s/^[^\/]+\/\///;
  $registrydomain =~ s/\/.*//;
  die unless $repotag =~ /^(.*):([^\/:]+)$/;
  my ($repository, $tag) = ($1, $2);
  my $refname = "$repository:$tag";
  if ($repository !~ /\//) {
    $repository = "library/$repository" if $registry =~ /docker\.io\/?$/;
  } else {
    # strip domain part if it matches the registry url
    $repository = $2 if $repository =~ /^([^\/]+)\/(.+)$/s && $1 eq $registrydomain;
    $refname = "$repository:$tag";
  }
  # use an if-none-match query if we have the old binary data
  my $olddigest;
  my $oldannotation = ($oldbin || {})->{'annotation'};
  if ($oldannotation && $oldannotation->{'binaryid'}) {
    $olddigest = $oldannotation->{'registry_fatdigest'} || $oldannotation->{'registry_digest'};
  }
  my $tagqueryheaders = $olddigest ? [ 'If-None-Match' => "\"$olddigest\"" ] : undef;
  my @accept = ($mt_docker_manifestlist, $mt_docker_manifest, $mt_oci_index, $mt_oci_manifest);
  my $replyheaders;
  my ($data, $ct) = fetch_manifest($repodir, $registry, "$registry/v2/$repository/manifests/$tag",
	'ua' => $ua, 'accept' => \@accept, 'missingok' => 1,
	'headers' => $tagqueryheaders, 'notmodifiedok' => ($olddigest ? 1 : 0),
	'replyheaders' => \$replyheaders);
  if (!defined($data)) {
    return undef unless $olddigest && $ct && $ct == 304;
    $replyheaders = { 'docker-content-digest' => $olddigest };
  }
  my $digest = $replyheaders->{'docker-content-digest'};
  die("no docker-content-digest set in answer\n") unless $digest;
  # reuse the old binary data if it matches the digest
  if ($oldannotation && $oldannotation->{'binaryid'} && ($oldannotation->{'registry_digest'} eq $digest || ($oldannotation->{'registry_fatdigest'} || '') eq $digest)) {
    # tag is unchanged, reuse data from old binary
    my $annotation = { %$oldannotation };
    $annotation->{'registry_refname'} = ($registrydomain =~ /docker\.io/ ? 'docker.io/' : "$registrydomain/") . $refname;
    return createcontainerbinary($repository, $repotag, $oldannotation->{'binaryid'}, $oldbin->{'blobs'}, $annotation);
  }
  die("content missing from answer\n") unless $data;
  die("no content type set in answer\n") unless $ct;
  my $fatdigest;
  if ($ct eq $mt_docker_manifestlist || $ct eq $mt_oci_index) {
    # fat manifest, select the one we want
    $fatdigest = $digest;
    my $r = JSON::XS::decode_json($data);
    my $manifest = select_manifest($r->{'manifests'}, $arch);
    return undef unless $manifest;
    $digest = $manifest->{'digest'};
    @accept = ($mt_docker_manifest, $mt_oci_manifest);
    ($data, $ct) = fetch_manifest($repodir, $registry, "$registry/v2/$repository/manifests/$digest",
	'ua' => $ua, 'accept' => \@accept);
    die("no content type set in answer\n") unless $ct;
  }
  die("unknown content type\n") unless $ct eq $mt_docker_manifest || $ct eq $mt_oci_manifest;
  my $r = JSON::XS::decode_json($data);
  my @blobs;
  die("manifest has no config\n") unless $r->{'config'};
  push @blobs, $r->{'config'};
  push @blobs, @{$r->{'layers'} || []};
  PBuild::Verify::verify_digest($_->{'digest'}) for @blobs;
  my $imageid= $blobs[0]->{'digest'};
  $imageid=~ s/.*://;
  $imageid= substr($imageid, 0, 32);
  my $annotation = {
    'registry_refname' => ($registrydomain =~ /docker\.io/ ? 'docker.io/' : "$registrydomain/") . $refname,
    'registry_digest' => $digest,
    'binaryid' => $imageid,
  };
  $annotation->{'registry_fatdigest'} = $fatdigest if $fatdigest;
  my $sbom = fetch_sbom($repodir, $registry, $repository, $digest, $ua);
  if ($sbom) {
    $sbom = get_intoto_predicate($sbom);
    my $installed = sbom2installed($sbom);
    $annotation->{'installed'} = $installed if @{$installed || []};
  }
  return createcontainerbinary($repository, $repotag, $imageid, \@blobs, $annotation);
}

#
# get data from a registry for a set of containers
#
sub fetchrepo {
  my ($bconf, $arch, $repodir, $url, $repotags, $opts) = @_;
  my $oldmetadata = (-s "$repodir/_metadata") ? PBuild::Util::retrieve("$repodir/_metadata", 1) : undef;
  my $oldtags = ($oldmetadata || {})->{'tags'} || {};
  my $ua;
  my %tags;
  %tags = %$oldtags if $opts->{'single'};	# repotags is incomplete
  my @bins;
  for my $repotag (@{$repotags || []}) {
    my $rt = $repotag;
    $rt .= ":latest" unless $rt =~ /:[^\/:]+$/;
    my $bin;
    if ($opts->{'no-repo-refresh'} && exists $oldtags->{$rt}) {
      $bin = $oldtags->{$rt};
    } else {
      $ua ||= Build::Download::create_ua();
      $bin = queryremotecontainer($ua, $arch, $repodir, $url, $rt, $oldtags->{$rt});
    }
    push @bins, $bin if $bin;
    $tags{$rt} = $bin;
  }
  my $metadata = { 'tags' => \%tags };
  my $meta = { 'repodir' => $repodir, 'url' => $url };
  PBuild::Util::mkdir_p($repodir);
  PBuild::Util::store("$repodir/._metadata.$$", "$repodir/_metadata", $metadata);
  return (\@bins, $meta);
}

#
# download the blobs needed to reconstruct a container
#
sub fetchbinaries {
  my ($meta, $bins) = @_;
  my $repodir = $meta->{'repodir'};
  my $url = $meta->{'url'};
  my $nbins = @$bins;
  die("bad repo\n") unless $url;
  my %tofetch;
  for my $bin (@$bins) {
    my $blobs = $bin->{'blobs'};
    die unless $blobs;
    for my $blob (@$blobs) {
      my $digest = $blob->{'digest'};
      die unless $digest;
      next if -s "$repodir/blob.$digest";
      $tofetch{"$bin->{'location'}/$digest"} = 1;
    }
  }
  return unless %tofetch;
  my @tofetch = sort keys %tofetch;
  print "fetching ".PBuild::Util::plural(scalar(@tofetch), 'container blob')." from $url\n";
  my $ua = Build::Download::create_ua();
  PBuild::Util::mkdir_p($repodir);
  for my $tofetch (@tofetch) {
    next unless $tofetch =~ /^(.*)\/(.*)?$/;
    my ($repository, $digest) = ($1, $2);
    next if -s "$repodir/blob.$digest";
    Build::Download::download("$url/v2/$repository/blobs/$digest", "$repodir/.blob.$digest.$$", "$repodir/blob.$digest", 'digest' => $digest, 'ua' => $ua);
  }
}

#
# create the head/pad data for a tar file entry
#
sub maketarhead {
  my ($name, $size, $mtime) = @_;

  my $h = "\0\0\0\0\0\0\0\0" x 64;
  my $pad = '';
  return ("$h$h") unless defined $name;
  my $tartype = '0';
  die("tar entry name too big\n") if length($name) > 100;
  die("tar entry size too big\n") if $size >= 8589934592;
  my $mode = sprintf("%07o", 0x81a4);
  my $fsize = sprintf("%011o", $size);
  my $fmtime = sprintf("%011o", $mtime);
  substr($h, 0, length($name), $name);
  substr($h, 100, length($mode), $mode);
  substr($h, 108, 15, "0000000\0000000000");    # uid/gid
  substr($h, 124, length($fsize), $fsize);
  substr($h, 136, length($fmtime), $fmtime);
  substr($h, 148, 8, '        ');
  substr($h, 156, 1, $tartype);
  substr($h, 257, 8, "ustar\00000");            # magic/version
  substr($h, 329, 15, "0000000\0000000000");    # major/minor
  substr($h, 148, 7, sprintf("%06o\0", unpack("%16C*", $h)));
  $pad = "\0" x (512 - $size % 512) if $size % 512;
  return ($h, $pad);
}

#
# reconstruct a container archive from blobs
#
sub construct_containertar {
  my ($meta, $q, $dst) = @_;
  my $repodir = $meta->{'repodir'};
  die("construct_containertar: $q->{'name'}: not a container\n") unless $q->{'name'} =~ /^container:/;
  my $fd;
  open ($fd, '>', $dst) || die("$dst: $!\n");
  my $mtime = time();
  my $blobs = $q->{'blobs'};
  die unless $blobs;
  for my $blob (@$blobs) {
    my $digest = $blob->{'digest'};
    die unless $digest;
    my $bfd;
    open ($bfd, '<', "$repodir/blob.$digest") || die("$repodir/blob.$digest: $!\n");
    my @s = stat($bfd);
    die unless @s;
    my $size = $s[7];
    my ($head, $pad) = maketarhead($digest, $size, $mtime);
    print $fd $head;
    while ($size > 0) {
      my $chunk = $size > 16384 ? 16384 : $size;
      my $b = '';
      die("unexpected read error in blob\n") unless sysread($bfd, $b, $chunk);
      print $fd $b;
      $size -= length($b);
    }
    print $fd $pad;
    close($bfd);
  }
  my @digests = map {$_->{'digest'}} @$blobs;
  my $configdigest = shift @digests;
  my $manifest = {
    'Config' => $configdigest,
    'Layers' => \@digests,
    'RepoTags' => $q->{'containertags'},
    '_order' => [ 'Config', 'RepoTags', 'Layers' ],
  };
  my $manifest_json = Build::SimpleJSON::unparse([ $manifest ], 'ugly' => 1);
  my ($head, $pad) = maketarhead('manifest.json', length($manifest_json), $mtime);
  print $fd "$head$manifest_json$pad".maketarhead();
  close($fd) || die;
}

#
# write the annotation for a container binary pulled from a registry
#
sub construct_containerannotation {
  my ($meta, $q, $dst) = @_;
  my %annotation = %{$q->{'annotation'} || {}};
  $_ = ref($_) ? $_ : [ $_ ] for values %annotation;
  my $annotationxml = Build::SimpleXML::unparse( { 'annotation' => [ \%annotation ] });
  PBuild::Util::writestr($dst, undef, $annotationxml);
}

1;
