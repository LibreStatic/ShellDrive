#!/usr/bin/perl
# Generates the ShellDrive UI icons from shapes defined here (original geometric art, no image files).
#
#   perl res/icons/make-icons.pl
#
# Output, committed as binary next to this script:
#   shelldrive.ico          application icon   (resource 1, DefaultIcon index 0): a drive with a key
#   shelldrive-mounted.ico  mounted drive icon (resource 2, DefaultIcon index 1): a drive with a connected link
# Each file holds 16, 20, 24, 32, 48 and 256 pixel images at 32 bits per pixel. The images are uncompressed DIBs
# (PNG-compressed entries need Windows Vista). The AND mask marks the pixels whose alpha is below 128, which is the
# transparency Windows XP uses. Shapes are drawn with 4x4 supersampling.
use strict;
use warnings;

my ($dir) = $0 =~ m{^(.*)/[^/]*$};
$dir = '.' unless defined $dir;

my @sizes = (16, 20, 24, 32, 48, 256);
my $SUB = 4;

my $BODY  = [84, 104, 122];
my $FACE  = [150, 172, 192];
my $GOLD  = [242, 183, 5];
my $GREEN = [61, 190, 107];
my $GREY  = [200, 210, 220];

# shape: [kind, params..., colour]; kinds: rr (rounded rect x y w h r), rect (x y w h), circ (cx cy r)
my @app = (
  [ 'rr',   0.06, 0.20, 0.88, 0.60, 0.10, $BODY ],
  [ 'rect', 0.14, 0.30, 0.72, 0.06, $FACE ],
  [ 'circ', 0.78, 0.66, 0.055, $GREY ],
  [ 'circ', 0.30, 0.60, 0.12, $GOLD ],
  [ 'circ', 0.30, 0.60, 0.05, $BODY ],
  [ 'rect', 0.40, 0.585, 0.26, 0.03, $GOLD ],
  [ 'rect', 0.56, 0.615, 0.04, 0.05, $GOLD ],
  [ 'rect', 0.63, 0.615, 0.03, 0.04, $GOLD ],
);

my @mounted = (
  [ 'rr',   0.06, 0.20, 0.88, 0.60, 0.10, $BODY ],
  [ 'rect', 0.14, 0.30, 0.72, 0.06, $FACE ],
  [ 'circ', 0.78, 0.66, 0.055, $GREEN ],
  [ 'rect', 0.14, 0.56, 0.44, 0.07, $GREEN ],
);

sub inside {
  my ($s, $u, $v) = @_;
  my ($kind) = @$s;
  if ($kind eq 'rect') {
    my (undef, $x, $y, $w, $h) = @$s;
    return $u >= $x && $u <= $x + $w && $v >= $y && $v <= $y + $h;
  } elsif ($kind eq 'circ') {
    my (undef, $cx, $cy, $r) = @$s;
    return ($u - $cx) ** 2 + ($v - $cy) ** 2 <= $r * $r;
  } else {
    my (undef, $x, $y, $w, $h, $r) = @$s;
    return 0 if $u < $x || $u > $x + $w || $v < $y || $v > $y + $h;
    my $cx = $u < $x + $r ? $x + $r : ($u > $x + $w - $r ? $x + $w - $r : $u);
    my $cy = $v < $y + $r ? $y + $r : ($v > $y + $h - $r ? $y + $h - $r : $v);
    return ($u - $cx) ** 2 + ($v - $cy) ** 2 <= $r * $r;
  }
}

# Returns the BGRA rows (top-down) of one image as a list of [b,g,r,a] per pixel.
sub render {
  my ($size, $shapes) = @_;
  my @px;
  for my $y (0 .. $size - 1) {
    for my $x (0 .. $size - 1) {
      my ($hits, $sr, $sg, $sb) = (0, 0, 0, 0);
      for my $j (0 .. $SUB - 1) {
        for my $i (0 .. $SUB - 1) {
          my $u = ($x + ($i + 0.5) / $SUB) / $size;
          my $v = ($y + ($j + 0.5) / $SUB) / $size;
          my $col;
          for my $s (@$shapes) {
            $col = $s->[-1] if inside($s, $u, $v);
          }
          next unless defined $col;
          $hits++;
          $sr += $col->[0];
          $sg += $col->[1];
          $sb += $col->[2];
        }
      }
      my $n = $SUB * $SUB;
      if ($hits == 0) {
        push @px, [0, 0, 0, 0];
      } else {
        push @px, [int($sb / $hits + 0.5), int($sg / $hits + 0.5), int($sr / $hits + 0.5),
                   int(255 * $hits / $n + 0.5)];
      }
    }
  }
  return \@px;
}

sub dib {
  my ($size, $px) = @_;
  my $data = '';
  # BITMAPINFOHEADER: height is doubled (XOR bitmap plus AND mask)
  $data .= pack('V l< l< v v V V l< l< V V', 40, $size, $size * 2, 1, 32, 0, 0, 0, 0, 0, 0);
  for (my $y = $size - 1; $y >= 0; $y--) {
    for my $x (0 .. $size - 1) {
      my $p = $px->[$y * $size + $x];
      $data .= pack('C4', @$p);
    }
  }
  my $stride = int(($size + 31) / 32) * 4;
  for (my $y = $size - 1; $y >= 0; $y--) {
    my @row = (0) x $stride;
    for my $x (0 .. $size - 1) {
      if ($px->[$y * $size + $x][3] < 128) {
        $row[$x >> 3] |= (0x80 >> ($x & 7));
      }
    }
    $data .= pack('C*', @row);
  }
  return $data;
}

sub write_icon {
  my ($path, $shapes) = @_;
  my @images;
  for my $size (@sizes) {
    push @images, [$size, dib($size, render($size, $shapes))];
  }
  my $out = pack('v v v', 0, 1, scalar @images);
  my $offset = 6 + 16 * scalar @images;
  for my $img (@images) {
    my ($size, $data) = @$img;
    my $dim = $size >= 256 ? 0 : $size;
    $out .= pack('C C C C v v V V', $dim, $dim, 0, 0, 1, 32, length $data, $offset);
    $offset += length $data;
  }
  $out .= $_->[1] for @images;
  open(my $fh, '>:raw', $path) or die "cannot write $path: $!";
  print $fh $out;
  close $fh;
  print "wrote $path (", length($out), " bytes)\n";
}

write_icon("$dir/shelldrive.ico", \@app);
write_icon("$dir/shelldrive-mounted.ico", \@mounted);
